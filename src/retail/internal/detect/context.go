package detect

import (
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// windowCandidates returns the maintenance windows that may cover the instant,
// including windows that ended within the operator grace period.
func windowCandidates(w World, site domain.SiteID, at time.Time, grace time.Duration) []domain.MaintenanceWindow {
	if at.IsZero() {
		return nil
	}
	probes := []time.Time{at}
	if grace > 0 {
		probes = append(probes, at.Add(-grace))
	}
	seen := make(map[domain.MaintenanceWindowID]struct{}, 4)
	out := make([]domain.MaintenanceWindow, 0, 4)
	for _, probe := range probes {
		for _, win := range w.WindowsAt(site, probe) {
			if _, dup := seen[win.WindowID]; dup {
				continue
			}
			seen[win.WindowID] = struct{}{}
			out = append(out, win)
		}
	}
	return out
}

// windowCovers reports whether a maintenance window covers the instant and the
// asset. Grace extends the window end for late-started sessions. An unknown
// target asset only matches site-wide windows (empty target list), which avoids
// crediting an unproven asset to a targeted window.
func windowCovers(win domain.MaintenanceWindow, at time.Time, asset domain.AssetID, grace time.Duration) bool {
	if at.IsZero() || win.StartsAt.IsZero() || win.EndsAt.IsZero() {
		return false
	}
	if win.Status == domain.WindowCancelled {
		return false
	}
	end := win.EndsAt
	if grace > 0 {
		end = end.Add(grace)
	}
	if at.Before(win.StartsAt) || !at.Before(end) {
		return false
	}
	return win.CoversAsset(asset)
}

// coveringWindow resolves an approved maintenance window for the instant/asset.
func coveringWindow(w World, site domain.SiteID, at time.Time, asset domain.AssetID, grace time.Duration) (domain.MaintenanceWindow, bool) {
	for _, win := range windowCandidates(w, site, at, grace) {
		if windowCovers(win, at, asset, grace) {
			return win, true
		}
	}
	return domain.MaintenanceWindow{}, false
}

// assetByIP resolves the asset that owns a network address. Passive discovery
// stores IPs as NetworkIdentifier facts; without a match the destination stays
// unknown and identity-dependent rules stay silent.
func assetByIP(w World, site domain.SiteID, ip string) (domain.Asset, bool) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return domain.Asset{}, false
	}
	for _, asset := range w.Assets(site) {
		if asset.Retired {
			continue
		}
		for _, id := range asset.NetworkIDs {
			if id.Kind == domain.NetIDIP && strings.TrimSpace(id.Value) == ip {
				return asset, true
			}
		}
	}
	return domain.Asset{}, false
}

func assetCritical(asset domain.Asset) bool {
	return asset.Criticality == domain.CriticalityHigh || asset.Criticality == domain.CriticalityCritical
}

// assetIsOTController reports whether an asset type is an OT control/supervision
// device whose management interface matters.
func assetIsOTController(asset domain.Asset) bool {
	switch asset.Type {
	case domain.AssetRefrigerationController, domain.AssetPL, domain.AssetHMI,
		domain.AssetSensorGateway, domain.AssetBMS:
		return true
	default:
		return false
	}
}

func zoneKind(w World, site domain.SiteID, zone domain.ZoneID) domain.ZoneKind {
	if zone == "" {
		return domain.ZoneUnknown
	}
	for _, s := range w.Sites() {
		if s.SiteID != site {
			continue
		}
		for _, z := range s.Zones {
			if z.ZoneID == zone {
				return z.Kind
			}
		}
	}
	return domain.ZoneUnknown
}

func sensorByID(w World, site domain.SiteID, id domain.SensorID) (domain.Sensor, bool) {
	for _, sensor := range w.Sensors(site) {
		if sensor.SensorID == id {
			return sensor, true
		}
	}
	return domain.Sensor{}, false
}
