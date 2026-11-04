// Asset hypothesis construction and classification.
package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/vendorcatalog"
)

// evidence is the passive evidence extracted from one event.
type evidence struct {
	siteID      domain.SiteID
	zoneID      domain.ZoneID
	ip          string
	mac         string
	hostname    string
	vendorHint  string
	modelHint   string
	protocols   []string
	servicePort int
	source      string
	observedAt  time.Time
}

func (e evidence) ok() bool { return e.ip != "" || e.mac != "" }

// servicePorts are the ports the product can interpret (hints only).
func servicePort(port int) bool {
	switch port {
	case 502, 47808, 1883, 8883, 161, 162, 80, 443, 8000, 8080, 8443:
		return true
	}
	return false
}

// managementPort reports whether the port belongs to a management UI.
func managementPort(port int) bool {
	switch port {
	case 80, 443, 8000, 8080, 8443:
		return true
	}
	return false
}

func extractEvidence(ev domain.Event) evidence {
	e := evidence{
		siteID:     ev.SiteID,
		zoneID:     ev.ZoneID,
		source:     ev.Source,
		observedAt: ev.ObservedAt,
	}
	switch ev.Kind {
	case domain.EventFlow:
		if ev.Flow == nil {
			return e
		}
		srcPort, dstPort := ev.Flow.SrcPort, ev.Flow.DstPort
		switch {
		case servicePort(dstPort):
			e.ip, e.servicePort = ev.Flow.DstIP, dstPort
		case servicePort(srcPort):
			e.ip, e.servicePort = ev.Flow.SrcIP, srcPort
		default:
			e.ip, e.servicePort = ev.Flow.DstIP, dstPort
		}
		if ev.Flow.Protocol != "" {
			e.protocols = append(e.protocols, ev.Flow.Protocol)
		}
		if label := protocolForPort(e.servicePort); label != "" {
			e.protocols = append(e.protocols, label)
		}
	case domain.EventAssetSeen:
		if ev.Device != nil {
			e.ip = ev.Device.IP
			e.mac = ev.Device.MAC
			e.hostname = ev.Device.Hostname
			e.vendorHint = ev.Device.Vendor
			e.modelHint = ev.Device.Model
		}
		if ev.Protocol != "" {
			e.protocols = append(e.protocols, ev.Protocol)
		}
		if ev.PayloadMeta != nil {
			if raw := ev.PayloadMeta["protocols"]; raw != "" {
				e.protocols = append(e.protocols, strings.Split(raw, ",")...)
			}
		}
	default:
		return evidence{}
	}
	if e.hostname != "" && len(e.hostname) > 253 {
		e.hostname = ""
	}
	return e
}

func protocolForPort(port int) string {
	switch port {
	case 502:
		return "modbus_tcp"
	case 47808:
		return "bacnet_ip"
	case 1883, 8883:
		return "mqtt"
	case 161, 162:
		return "snmp"
	case 80, 8000, 8080:
		return "http"
	case 443, 8443:
		return "https"
	default:
		return ""
	}
}

// classify derives the asset type and confidence from the observed evidence.
// The result is always a hypothesis (confidence 0.3..0.9), never an identity.
func classify(e evidence) (domain.AssetType, float64) {
	hint := strings.ToLower(e.hostname + " " + e.vendorHint + " " + e.modelHint)
	switch {
	case containsAny(hint, "storeview", "ak-sm", "ak-sc", "danfoss", "xweb", "copeland", "dixell", "carel"):
		if managementPort(e.servicePort) || containsAny(hint, "storeview", "xweb", "ak-sm", "ak-sc") {
			return domain.AssetRefrigerationController, 0.7
		}
		return domain.AssetRefrigerationController, 0.6
	case containsAny(hint, "bms", "bacnet", "hvac", "gebaeude", "gebäude"):
		return domain.AssetBMS, 0.65
	}
	for _, protocol := range e.protocols {
		switch strings.ToLower(protocol) {
		case "modbus_tcp":
			return domain.AssetPL, 0.5
		case "bacnet_ip":
			return domain.AssetBMS, 0.6
		case "mqtt":
			return domain.AssetSensorGateway, 0.6
		case "snmp":
			return domain.AssetNetworkDevice, 0.5
		case "http", "https":
			if managementPort(e.servicePort) {
				// A management UI without a proven product hint stays unknown:
				// many devices expose a web UI, that alone is not a controller.
				return domain.AssetUnknown, 0.35
			}
		}
	}
	switch e.servicePort {
	case 502:
		return domain.AssetPL, 0.5
	case 47808:
		return domain.AssetBMS, 0.6
	case 1883, 8883:
		return domain.AssetSensorGateway, 0.6
	case 161, 162:
		return domain.AssetNetworkDevice, 0.5
	case 80, 443, 8000, 8080, 8443:
		return domain.AssetUnknown, 0.35
	}
	return domain.AssetUnknown, 0.3
}

// hasManagementProtocol reports whether an observed protocol points at a
// management interface (HTTP/HTTPS).
func hasManagementProtocol(protocols []string) bool {
	for _, protocol := range protocols {
		switch strings.ToLower(protocol) {
		case "http", "https":
			return true
		}
	}
	return false
}

func containsAny(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

// buildAsset turns evidence into a validated hypothesis.
func buildAsset(e evidence, cat *vendorcatalog.Catalog, zoneID domain.ZoneID, now time.Time) (domain.Asset, bool) {
	if err := e.siteID.Validate(); err != nil {
		return domain.Asset{}, false
	}
	id := assetIDFor(e.siteID, e.ip, e.mac)
	assetType, confidence := classify(e)

	observedAt := e.observedAt
	if observedAt.IsZero() {
		observedAt = now
	}
	asset := domain.Asset{
		AssetID:             id,
		SiteID:              e.siteID,
		ZoneID:              zoneID,
		Name:                e.ip,
		Type:                assetType,
		Criticality:         domain.CriticalityMedium, // provisional; the operator confirms it
		Confidence:          clampConfidence(confidence),
		Classification:      domain.ClassificationAuto,
		Lifecycle:           domain.LifecycleUnknown,
		ManagementInterface: managementPort(e.servicePort) || hasManagementProtocol(e.protocols),
		Source:              "discovery",
		FirstSeenAt:         observedAt,
		LastSeenAt:          observedAt,
	}
	if e.zoneID != "" {
		asset.ZoneID = e.zoneID
	}
	if e.hostname != "" {
		asset.Name = e.hostname
	}
	asset.NetworkIDs = networkIDsFor(e, observedAt)
	asset.Protocols = mergeProtocols(nil, e.protocols)

	if e.mac != "" && cat != nil {
		if vendor, ok := cat.VendorForMAC(e.mac); ok {
			asset.Vendor = vendor
			asset.Confidence = clampConfidence(asset.Confidence + 0.05)
		}
	}
	if asset.Vendor == "" && e.vendorHint != "" {
		asset.Vendor = e.vendorHint
	}
	if e.modelHint != "" {
		asset.Model = e.modelHint
	}
	if cat != nil {
		if family, ok := cat.MatchFamily(asset.Vendor, asset.Model, e.hostname); ok {
			enrichFromFamily(&asset, family)
		}
	}
	asset.Confidence = clampConfidence(asset.Confidence)
	if err := asset.Validate(); err != nil {
		return domain.Asset{}, false
	}
	return asset, true
}

func networkIDsFor(e evidence, observedAt time.Time) []domain.NetworkIdentifier {
	out := make([]domain.NetworkIdentifier, 0, 3)
	if e.ip != "" {
		out = append(out, domain.NetworkIdentifier{
			Kind: domain.NetIDIP, Value: e.ip, Source: e.source,
			Confidence: 0.6, FirstSeen: observedAt, LastSeen: observedAt,
		})
	}
	if e.mac != "" {
		out = append(out, domain.NetworkIdentifier{
			Kind: domain.NetIDMAC, Value: e.mac, Source: e.source,
			Confidence: 0.7, FirstSeen: observedAt, LastSeen: observedAt,
		})
	}
	if e.hostname != "" {
		out = append(out, domain.NetworkIdentifier{
			Kind: domain.NetIDHostname, Value: e.hostname, Source: e.source,
			Confidence: 0.5, FirstSeen: observedAt, LastSeen: observedAt,
		})
	}
	for _, protocol := range e.protocols {
		if protocol == "" {
			continue
		}
		out = append(out, domain.NetworkIdentifier{
			Kind: domain.NetIDProtocol, Value: protocol, Source: e.source,
			Confidence: 0.5, FirstSeen: observedAt, LastSeen: observedAt,
		})
	}
	return out
}

// assetIDFor derives a stable identifier from the strongest available key. It
// deliberately does not encode vendor/model claims.
func assetIDFor(site domain.SiteID, ip, mac string) domain.AssetID {
	seed := string(site) + "|ip|" + ip
	if ip == "" {
		seed = string(site) + "|mac|" + mac
	}
	sum := sha256.Sum256([]byte(seed))
	return domain.AssetID("ast_" + hex.EncodeToString(sum[:8]))
}

func clampConfidence(value float64) float64 {
	if value < 0.3 {
		return 0.3
	}
	if value > 0.9 {
		return 0.9
	}
	return value
}
