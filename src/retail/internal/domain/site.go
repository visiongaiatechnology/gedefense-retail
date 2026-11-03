package domain

import (
	"fmt"
	"time"
)

// SiteStatus is the coarse reachability of a store gateway as last observed by
// the local detection loop. It is never inferred from a single missing poll:
// see the telemetry-gap rule for the evidence-based transition.
type SiteStatus string

const (
	SiteOnline   SiteStatus = "online"
	SiteDegraded SiteStatus = "degraded"
	SiteOffline  SiteStatus = "offline"
	SiteUnknown  SiteStatus = "unknown"
)

// ZoneKind models the five network zones from the product blueprint (§4.3).
// Zones are configuration, not detection results: passive observation may
// infer a zone hint with low confidence, but the operator owns the assignment.
type ZoneKind string

const (
	ZoneOTProcess           ZoneKind = "ot_process"
	ZoneOTMonitoring        ZoneKind = "ot_monitoring"
	ZoneRetailIT            ZoneKind = "retail_it"
	ZoneManagement          ZoneKind = "management"
	ZoneExternalMaintenance ZoneKind = "external_maintenance"
	// ZoneCoolingArea is a logical cooling area (rack, cold room, display case)
	// inside the OT process zone. It is not a network segment; it exists so
	// temperature limits and sensor grouping can be expressed per product area.
	ZoneCoolingArea ZoneKind = "cooling_area"
	ZoneUnknown     ZoneKind = "unknown"
)

func (z ZoneKind) Valid() bool {
	switch z {
	case ZoneOTProcess, ZoneOTMonitoring, ZoneRetailIT, ZoneManagement, ZoneExternalMaintenance, ZoneCoolingArea, ZoneUnknown:
		return true
	}
	return false
}

// Site is one store (Filiale). Retail is multi-site by design, but MVP runs a
// single local gateway per site; the central fleet view is optional.
type Site struct {
	SiteID     SiteID     `json:"site_id"`
	TenantID   string     `json:"tenant_id,omitempty"`
	Name       string     `json:"name"`
	Country    string     `json:"country,omitempty"`  // ISO 3166-1 alpha-2
	Timezone   string     `json:"timezone,omitempty"` // IANA, display only; storage is UTC
	Status     SiteStatus `json:"status"`
	GatewayID  AssetID    `json:"gateway_asset_id,omitempty"`
	Zones      []Zone     `json:"zones"`
	LastSeenAt time.Time  `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	Tags       []string   `json:"tags,omitempty"`
}

// Zone is a logical network / OT area inside one site.
type Zone struct {
	ZoneID     ZoneID   `json:"zone_id"`
	SiteID     SiteID   `json:"site_id"`
	Name       string   `json:"name"`
	Kind       ZoneKind `json:"kind"`
	Purpose    string   `json:"purpose,omitempty"`
	Critical   bool     `json:"critical"`
	OperatorID UserID   `json:"operator_id,omitempty"` // accountable person, optional
}

// Validate checks the invariants required before a Site may be persisted or
// returned by the API. Safe to call on partially onboarded sites: only the
// mandatory identity fields are enforced.
func (s Site) Validate() error {
	if err := s.SiteID.Validate(); err != nil {
		return fmt.Errorf("site: %w", err)
	}
	if s.Name == "" {
		return fmt.Errorf("site %q: name is required", s.SiteID)
	}
	if s.Status == "" {
		return fmt.Errorf("site %q: status is required", s.SiteID)
	}
	seen := make(map[ZoneID]struct{}, len(s.Zones))
	for i := range s.Zones {
		z := s.Zones[i]
		if err := z.ZoneID.Validate(); err != nil {
			return fmt.Errorf("site %q zone %d: %w", s.SiteID, i, err)
		}
		if _, dup := seen[z.ZoneID]; dup {
			return fmt.Errorf("site %q: duplicate zone %q", s.SiteID, z.ZoneID)
		}
		seen[z.ZoneID] = struct{}{}
		if !z.Kind.Valid() {
			return fmt.Errorf("site %q zone %q: invalid kind %q", s.SiteID, z.ZoneID, z.Kind)
		}
	}
	return nil
}
