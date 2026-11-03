// Package discovery derives passive asset hypotheses from flow and asset_seen
// events.
//
// It never claims an identity that passive data cannot prove: vendor and model
// are only set when an OUI catalog match or an observed management-interface
// hint exists, and every hypothesis carries a confidence plus
// ClassificationAuto. Unclassifiable endpoints stay AssetUnknown.
package discovery

import (
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// DefaultVendorsPath is relative to the service working directory
// (src/retail -> ../../data/ot-catalog/vendors.json). A missing file is not an
// error: discovery then runs without the catalog (no vendor/lifecycle claims).
const DefaultVendorsPath = "../../data/ot-catalog/vendors.json"

// Options configures the discoverer.
type Options struct {
	Clock       ports.Clock
	VendorsPath string
	ZoneID      domain.ZoneID
}

// Discoverer turns passive events into asset hypotheses. It is safe for
// concurrent use.
type Discoverer struct {
	clock   ports.Clock
	catalog *catalog
	zoneID  domain.ZoneID

	mu     sync.Mutex
	assets map[domain.AssetID]domain.Asset
}

// New creates a discoverer. The optional OUI/device catalog is loaded once; a
// missing or malformed catalog only disables vendor/lifecycle enrichment.
func New(opts Options) *Discoverer {
	path := opts.VendorsPath
	if path == "" {
		path = DefaultVendorsPath
	}
	return &Discoverer{
		clock:   opts.Clock,
		catalog: loadCatalog(path),
		zoneID:  opts.ZoneID,
		assets:  make(map[domain.AssetID]domain.Asset),
	}
}

// Observe derives (or refines) one asset hypothesis. It reports false when the
// event carries no identity evidence at all.
func (d *Discoverer) Observe(ev domain.Event) (domain.Asset, bool) {
	evidence := extractEvidence(ev)
	if !evidence.ok() {
		return domain.Asset{}, false
	}
	asset, ok := buildAsset(evidence, d.catalog, d.zoneID, d.now())
	if !ok {
		return domain.Asset{}, false
	}
	return d.merge(asset), true
}

// Assets returns the current hypotheses, sorted by asset id for deterministic
// callers (API/state).
func (d *Discoverer) Assets() []domain.Asset {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]domain.Asset, 0, len(d.assets))
	for _, asset := range d.assets {
		out = append(out, asset)
	}
	sortAssets(out)
	return out
}

// Asset returns one hypothesis by id.
func (d *Discoverer) Asset(id domain.AssetID) (domain.Asset, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	asset, ok := d.assets[id]
	return asset, ok
}

// merge combines a new observation with an existing hypothesis: evidence is
// unioned, timestamps are kept, confidence and lifecycle never decrease.
func (d *Discoverer) merge(next domain.Asset) domain.Asset {
	d.mu.Lock()
	defer d.mu.Unlock()
	current, exists := d.assets[next.AssetID]
	if !exists {
		d.assets[next.AssetID] = next
		return next
	}
	current.LastSeenAt = laterTime(current.LastSeenAt, next.LastSeenAt)
	current.FirstSeenAt = earlierTime(current.FirstSeenAt, next.FirstSeenAt)
	if next.Confidence > current.Confidence {
		current.Confidence = next.Confidence
	}
	if current.Type == domain.AssetUnknown && next.Type != domain.AssetUnknown {
		current.Type = next.Type
	}
	if current.Vendor == "" {
		current.Vendor = next.Vendor
	}
	if current.Model == "" {
		current.Model = next.Model
	}
	if next.Lifecycle != "" && next.Lifecycle != domain.LifecycleUnknown {
		current.Lifecycle = next.Lifecycle
		current.LifecycleSource = next.LifecycleSource
	}
	current.ManagementInterface = current.ManagementInterface || next.ManagementInterface
	current.NetworkIDs = mergeNetworkIDs(current.NetworkIDs, next.NetworkIDs)
	current.Protocols = mergeProtocols(current.Protocols, next.Protocols)
	if next.Name != "" && (current.Name == "" || isIPLikeName(current.Name)) {
		current.Name = next.Name
	}
	d.assets[next.AssetID] = current
	return current
}

func (d *Discoverer) now() time.Time {
	if d.clock != nil {
		return d.clock.Now().UTC()
	}
	return time.Now().UTC()
}

func sortAssets(assets []domain.Asset) {
	for i := 1; i < len(assets); i++ {
		for j := i; j > 0 && assets[j].AssetID < assets[j-1].AssetID; j-- {
			assets[j], assets[j-1] = assets[j-1], assets[j]
		}
	}
}

func laterTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func earlierTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	if b.Before(a) {
		return b
	}
	return a
}

func isIPLikeName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= '0' && c <= '9') && c != '.' && c != ':' {
			return false
		}
	}
	return name != ""
}

func mergeProtocols(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, value := range append(append([]string{}, a...), b...) {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func mergeNetworkIDs(a, b []domain.NetworkIdentifier) []domain.NetworkIdentifier {
	type key struct {
		kind  domain.NetworkIDKind
		value string
	}
	seen := make(map[key]int, len(a))
	out := append([]domain.NetworkIdentifier{}, a...)
	for i := range out {
		seen[key{out[i].Kind, out[i].Value}] = i
	}
	for _, id := range b {
		if id.Value == "" {
			continue
		}
		k := key{id.Kind, id.Value}
		if idx, ok := seen[k]; ok {
			out[idx].LastSeen = laterTime(out[idx].LastSeen, id.LastSeen)
			if id.Confidence > out[idx].Confidence {
				out[idx].Confidence = id.Confidence
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, id)
	}
	return out
}
