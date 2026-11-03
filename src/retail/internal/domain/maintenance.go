package domain

import (
	"fmt"
	"time"
)

// MaintenanceWindowStatus models the lifecycle of an approved service window.
type MaintenanceWindowStatus string

const (
	WindowPlanned   MaintenanceWindowStatus = "planned"
	WindowActive    MaintenanceWindowStatus = "active"
	WindowClosed    MaintenanceWindowStatus = "closed"
	WindowCancelled MaintenanceWindowStatus = "cancelled"
)

func (s MaintenanceWindowStatus) Valid() bool {
	switch s {
	case WindowPlanned, WindowActive, WindowClosed, WindowCancelled:
		return true
	}
	return false
}

// MaintenanceWindow is the operator-approved context in which external service
// access is expected. It is the difference between "a technician is working"
// and "somebody opened a session nobody approved".
type MaintenanceWindow struct {
	WindowID           MaintenanceWindowID     `json:"maintenance_window_id"`
	SiteID             SiteID                  `json:"site_id"`
	ZoneIDs            []ZoneID                `json:"zone_ids,omitempty"`
	Vendor             string                  `json:"vendor"`
	TicketRef          string                  `json:"ticket_ref,omitempty"`
	ApprovedBy         UserID                  `json:"approved_by,omitempty"`
	ApprovedAt         time.Time               `json:"approved_at,omitempty"`
	StartsAt           time.Time               `json:"starts_at"`
	EndsAt             time.Time               `json:"ends_at"`
	TargetAssetIDs     []AssetID               `json:"target_asset_ids,omitempty"`
	AllowedSourceCIDRs []string                `json:"allowed_source_cidrs,omitempty"`
	Status             MaintenanceWindowStatus `json:"status"`
	CreatedAt          time.Time               `json:"created_at"`
	CreatedBy          UserID                  `json:"created_by"`
	Notes              string                  `json:"notes,omitempty"`
}

// Validate enforces window invariants. Overlaps are allowed (different vendors
// may work in different zones), but an empty or inverted window is a bug.
func (m MaintenanceWindow) Validate() error {
	if err := m.WindowID.Validate(); err != nil {
		return fmt.Errorf("maintenance window: %w", err)
	}
	if err := m.SiteID.Validate(); err != nil {
		return fmt.Errorf("maintenance window %q: %w", m.WindowID, err)
	}
	if !m.Status.Valid() {
		return fmt.Errorf("maintenance window %q: invalid status %q", m.WindowID, m.Status)
	}
	if m.StartsAt.IsZero() || m.EndsAt.IsZero() {
		return fmt.Errorf("maintenance window %q: start and end are required", m.WindowID)
	}
	if !m.EndsAt.After(m.StartsAt) {
		return fmt.Errorf("maintenance window %q: ends_at must be after starts_at", m.WindowID)
	}
	if m.Vendor == "" {
		return fmt.Errorf("maintenance window %q: vendor is required", m.WindowID)
	}
	for _, c := range m.AllowedSourceCIDRs {
		if err := validateCIDR(c); err != nil {
			return fmt.Errorf("maintenance window %q: %w", m.WindowID, err)
		}
	}
	return nil
}

// Contains reports whether t lies inside the window (inclusive start).
func (m MaintenanceWindow) Contains(t time.Time) bool {
	if t.IsZero() || m.StartsAt.IsZero() || m.EndsAt.IsZero() {
		return false
	}
	return !t.Before(m.StartsAt) && t.Before(m.EndsAt)
}

// CoversAsset reports whether the window targets the asset. An empty target list
// means "all assets of the listed zones"; an empty zone list means the whole
// site.
func (m MaintenanceWindow) CoversAsset(assetID AssetID) bool {
	for _, id := range m.TargetAssetIDs {
		if id == assetID {
			return true
		}
	}
	return len(m.TargetAssetIDs) == 0
}

// AccessSession describes an observed or reported external maintenance session.
type AccessSession struct {
	SessionID    string              `json:"session_id"`
	SiteID       SiteID              `json:"site_id"`
	Vendor       string              `json:"vendor,omitempty"`
	User         string              `json:"user,omitempty"`
	Method       string              `json:"method,omitempty"`
	TargetAsset  AssetID             `json:"target_asset,omitempty"`
	SourceDevice string              `json:"source_device,omitempty"`
	WindowID     MaintenanceWindowID `json:"maintenance_window_id,omitempty"`
	InWindow     bool                `json:"in_window"`
	StartedAt    time.Time           `json:"started_at"`
	EndedAt      time.Time           `json:"ended_at,omitempty"`
	Observed     bool                `json:"observed"` // true = derived from traffic, false = reported
}

// Validate checks the session identity fields.
func (s AccessSession) Validate() error {
	if err := s.SiteID.Validate(); err != nil {
		return fmt.Errorf("access session: %w", err)
	}
	if s.SessionID == "" {
		return fmt.Errorf("access session: session_id is required")
	}
	if s.StartedAt.IsZero() {
		return fmt.Errorf("access session %q: started_at is required", s.SessionID)
	}
	if !s.EndedAt.IsZero() && s.EndedAt.Before(s.StartedAt) {
		return fmt.Errorf("access session %q: ended_at before started_at", s.SessionID)
	}
	return nil
}
