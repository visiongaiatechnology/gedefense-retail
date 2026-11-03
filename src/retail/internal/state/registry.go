// Package state is the in-memory world model of one gateway: the configured
// sites, the assets and sensors observed on the plant network, a bounded sample
// ring buffer per sensor, the recent event window, the maintenance windows, the
// incident workspace and the passive peer baseline.
//
// The registry is the only mutable world state the detection engine reads. It is
// guarded by a single RWMutex; every read returns deep copies so that callers can
// never mutate stored state or race with the pipeline.
//
// Every collection is bounded: sample ring per sensor, event window, peer set and
// the per-site asset/sensor inventory. Objects beyond the inventory limit are not
// tracked, are counted (Health.AssetsDropped/SensorsDropped) and produce one
// structured warning per site; the triggering event itself is still processed.
package state

import (
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Bounded memory defaults. They protect the gateway against event storms from a
// misbehaving or hostile network segment: the registry never grows without a
// documented ceiling.
const (
	DefaultSampleLimit = 5000
	DefaultEventLimit  = 2000
	DefaultPeerLimit   = 10000
	// DefaultAssetLimit and DefaultSensorLimit bound the per-site inventory that a
	// hostile or misbehaving network segment can create through passive discovery.
	DefaultAssetLimit  = 5000
	DefaultSensorLimit = 5000

	maxSamplesPerQuery = 200000
	maxNetworkIDs      = 32
	maxProtocols       = 16
	maxIncidentNotes   = 500
	maxNoteLength      = 4096
)

// Sentinel errors used by the coordination API.
var (
	// ErrNotFound reports a missing window, incident or other object.
	ErrNotFound = errors.New("state: not found")
	// ErrConflict reports an operation that contradicts the current workflow.
	ErrConflict = errors.New("state: conflict")
	// ErrInvalidNote reports an empty or oversized note.
	ErrInvalidNote = errors.New("state: invalid note")
	// ErrCapacity reports that a per-site inventory limit was reached. The event
	// that triggered it is still processed; only the new object is not tracked.
	ErrCapacity = errors.New("state: capacity limit reached")
)

// Health is the registry counter snapshot used by the API and the self-check.
type Health struct {
	EventsIngested uint64    `json:"events_ingested"`
	EventsRejected uint64    `json:"events_rejected"`
	Sites          int       `json:"sites"`
	Assets         int       `json:"assets"`
	Sensors        int       `json:"sensors"`
	Peers          int       `json:"peers"`
	LastEventAt    time.Time `json:"last_event_at,omitempty"`
	// AssetsDropped and SensorsDropped count objects rejected by the per-site
	// inventory limits. Non-zero values are an operational signal, not a panic.
	AssetsDropped  uint64 `json:"assets_dropped"`
	SensorsDropped uint64 `json:"sensors_dropped"`
}

// Registry is the mutex-protected in-memory world model.
type Registry struct {
	mu    sync.RWMutex
	clock ports.Clock

	sites     map[domain.SiteID]domain.Site
	siteOrder []domain.SiteID

	assets  map[domain.AssetID]domain.Asset
	sensors map[domain.SensorID]domain.Sensor
	samples map[domain.SensorID][]domain.Sample
	events  []domain.Event

	peers    map[string]struct{}
	windows  map[domain.MaintenanceWindowID]domain.MaintenanceWindow
	incident map[domain.IncidentID]domain.Incident

	siteStatus map[domain.SiteID]domain.SiteStatus

	ingested    uint64
	rejected    uint64
	lastEventAt time.Time

	sampleLimit    int
	eventLimit     int
	peerLimit      int
	assetLimit     int
	sensorLimit    int
	assetCount     map[domain.SiteID]int
	sensorCount    map[domain.SiteID]int
	warnedAssets   map[domain.SiteID]bool
	warnedSensors  map[domain.SiteID]bool
	assetsDropped  uint64
	sensorsDropped uint64
}

// wallClock is the default ports.Clock implementation of the registry.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

// NewRegistry builds an empty world model for the given configured sites.
func NewRegistry(sites []domain.Site, clock ports.Clock) *Registry {
	if clock == nil {
		clock = wallClock{}
	}
	r := &Registry{
		clock:         clock,
		sites:         make(map[domain.SiteID]domain.Site, len(sites)),
		siteOrder:     make([]domain.SiteID, 0, len(sites)),
		assets:        make(map[domain.AssetID]domain.Asset),
		sensors:       make(map[domain.SensorID]domain.Sensor),
		samples:       make(map[domain.SensorID][]domain.Sample),
		events:        make([]domain.Event, 0, DefaultEventLimit),
		peers:         make(map[string]struct{}),
		windows:       make(map[domain.MaintenanceWindowID]domain.MaintenanceWindow),
		incident:      make(map[domain.IncidentID]domain.Incident),
		siteStatus:    make(map[domain.SiteID]domain.SiteStatus, len(sites)),
		sampleLimit:   DefaultSampleLimit,
		eventLimit:    DefaultEventLimit,
		peerLimit:     DefaultPeerLimit,
		assetLimit:    DefaultAssetLimit,
		sensorLimit:   DefaultSensorLimit,
		assetCount:    make(map[domain.SiteID]int),
		sensorCount:   make(map[domain.SiteID]int),
		warnedAssets:  make(map[domain.SiteID]bool),
		warnedSensors: make(map[domain.SiteID]bool),
	}
	for _, site := range sites {
		stored := copySite(site)
		if stored.Status == "" {
			stored.Status = domain.SiteUnknown
		}
		if _, exists := r.sites[stored.SiteID]; exists {
			continue
		}
		r.sites[stored.SiteID] = stored
		r.siteOrder = append(r.siteOrder, stored.SiteID)
		r.siteStatus[stored.SiteID] = stored.Status
	}
	return r
}

// Now returns the registry clock (UTC).
func (r *Registry) Now() time.Time { return r.clock.Now().UTC() }

// SetSampleLimit changes the per-sensor ring buffer size. Values outside
// [1, 100000] are clamped; the setting is documented as configurable per the
// engineering contract.
func (r *Registry) SetSampleLimit(n int) {
	if n < 1 {
		n = 1
	}
	if n > 100000 {
		n = 100000
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sampleLimit = n
}

// SetAssetLimit changes the per-site asset limit. Values outside [1, 100000] are
// clamped; the limit is never disabled.
func (r *Registry) SetAssetLimit(n int) {
	if n < 1 {
		n = 1
	}
	if n > 100000 {
		n = 100000
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.assetLimit = n
}

// SetSensorLimit changes the per-site sensor limit. Values outside [1, 100000] are
// clamped; the limit is never disabled.
func (r *Registry) SetSensorLimit(n int) {
	if n < 1 {
		n = 1
	}
	if n > 100000 {
		n = 100000
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sensorLimit = n
}

// assetLimitReached reports whether the site already holds the maximum number of
// tracked assets.
func (r *Registry) assetLimitReached(site domain.SiteID) bool {
	return r.assetCount[site] >= r.assetLimit
}

// sensorLimitReached reports whether the site already holds the maximum number of
// tracked sensors.
func (r *Registry) sensorLimitReached(site domain.SiteID) bool {
	return r.sensorCount[site] >= r.sensorLimit
}

// warnCapacityOnce emits one structured warning per site and kind. Without the
// once-guard a flood of rejected observations would flood the log itself.
func warnCapacityOnce(warned map[domain.SiteID]bool, kind string, site domain.SiteID, limit int, dropped uint64) {
	if warned[site] {
		return
	}
	warned[site] = true
	slog.Warn("in-memory inventory limit reached; further objects are not tracked",
		"kind", kind, "site_id", string(site), "limit", limit, "dropped_total", dropped)
}

// Sites returns the configured sites in configuration order.
func (r *Registry) Sites() []domain.Site {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]domain.Site, 0, len(r.siteOrder))
	for _, id := range r.siteOrder {
		if site, ok := r.sites[id]; ok {
			out = append(out, copySite(site))
		}
	}
	return out
}

// Site returns one configured site.
func (r *Registry) Site(id domain.SiteID) (domain.Site, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	site, ok := r.sites[id]
	if !ok {
		return domain.Site{}, false
	}
	return copySite(site), true
}

// SetSiteStatus updates the coarse reachability of a site.
func (r *Registry) SetSiteStatus(id domain.SiteID, status domain.SiteStatus) {
	if !validSiteStatus(status) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sites[id]; !ok {
		return
	}
	r.siteStatus[id] = status
	site := r.sites[id]
	site.Status = status
	site.UpdatedAt = r.clock.Now().UTC()
	r.sites[id] = site
}

// SiteStatus returns the current status of a site.
func (r *Registry) SiteStatus(id domain.SiteID) (domain.SiteStatus, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	status, ok := r.siteStatus[id]
	return status, ok
}

// Health returns the counter snapshot.
func (r *Registry) Health() Health {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return Health{
		EventsIngested: r.ingested,
		EventsRejected: r.rejected,
		Sites:          len(r.sites),
		Assets:         len(r.assets),
		Sensors:        len(r.sensors),
		Peers:          len(r.peers),
		LastEventAt:    r.lastEventAt,
		AssetsDropped:  r.assetsDropped,
		SensorsDropped: r.sensorsDropped,
	}
}

// AssetCountsBySite returns the number of assets per site.
func (r *Registry) AssetCountsBySite() map[domain.SiteID]int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[domain.SiteID]int, len(r.sites))
	for _, asset := range r.assets {
		out[asset.SiteID]++
	}
	return out
}

// SensorCountsBySite returns the number of sensors per site.
func (r *Registry) SensorCountsBySite() map[domain.SiteID]int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[domain.SiteID]int, len(r.sites))
	for _, sensor := range r.sensors {
		out[sensor.SiteID]++
	}
	return out
}

// sortedAssetIDs returns asset identifiers ordered by identifier.
func (r *Registry) sortedAssetIDs() []domain.AssetID {
	ids := make([]domain.AssetID, 0, len(r.assets))
	for id := range r.assets {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// sortedSensorIDs returns sensor identifiers ordered by identifier.
func (r *Registry) sortedSensorIDs() []domain.SensorID {
	ids := make([]domain.SensorID, 0, len(r.sensors))
	for id := range r.sensors {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// validSiteStatus reports whether status is a known SiteStatus value.
func validSiteStatus(status domain.SiteStatus) bool {
	switch status {
	case domain.SiteOnline, domain.SiteDegraded, domain.SiteOffline, domain.SiteUnknown:
		return true
	}
	return false
}
