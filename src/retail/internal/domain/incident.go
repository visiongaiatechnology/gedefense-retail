package domain

import (
	"fmt"
	"time"
)

// IncidentStatus models the case lifecycle. Incidents are documentation and
// coordination objects; they can never trigger plant actions.
type IncidentStatus string

const (
	IncidentOpen          IncidentStatus = "open"
	IncidentInvestigating IncidentStatus = "investigating"
	IncidentContained     IncidentStatus = "contained"
	IncidentResolved      IncidentStatus = "resolved"
	IncidentClosed        IncidentStatus = "closed"
)

func (s IncidentStatus) Valid() bool {
	switch s {
	case IncidentOpen, IncidentInvestigating, IncidentContained, IncidentResolved, IncidentClosed:
		return true
	}
	return false
}

// IncidentNote is an operator note inside an incident workspace.
type IncidentNote struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Role   string    `json:"role"`
	Note   string    `json:"note"`
	Pinned bool      `json:"pinned,omitempty"`
}

// Incident groups correlated alerts and evidence into one case.
type Incident struct {
	IncidentID  IncidentID          `json:"incident_id"`
	SiteID      SiteID              `json:"site_id"`
	Title       string              `json:"title"`
	Severity    Severity            `json:"severity"`
	Status      IncidentStatus      `json:"status"`
	Assignee    UserID              `json:"assignee,omitempty"`
	AlertIDs    []AlertID           `json:"alert_ids,omitempty"`
	ZoneIDs     []ZoneID            `json:"zone_ids,omitempty"`
	AssetIDs    []AssetID           `json:"asset_ids,omitempty"`
	FirstSeenAt time.Time           `json:"first_seen_at"`
	LastSeenAt  time.Time           `json:"last_seen_at"`
	Summary     string              `json:"summary"`
	Correlation *CorrelationSummary `json:"correlation,omitempty"`
	Notes       []IncidentNote      `json:"notes,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
	ClosedAt    time.Time           `json:"closed_at,omitempty"`
}

// Validate enforces the incident contract.
func (i Incident) Validate() error {
	if err := i.IncidentID.Validate(); err != nil {
		return fmt.Errorf("incident: %w", err)
	}
	if err := i.SiteID.Validate(); err != nil {
		return fmt.Errorf("incident %q: %w", i.IncidentID, err)
	}
	if !i.Severity.Valid() {
		return fmt.Errorf("incident %q: invalid severity %q", i.IncidentID, i.Severity)
	}
	if !i.Status.Valid() {
		return fmt.Errorf("incident %q: invalid status %q", i.IncidentID, i.Status)
	}
	if i.Title == "" || i.Summary == "" {
		return fmt.Errorf("incident %q: title and summary are required", i.IncidentID)
	}
	if i.FirstSeenAt.IsZero() || i.LastSeenAt.IsZero() {
		return fmt.Errorf("incident %q: timestamps are required", i.IncidentID)
	}
	if i.LastSeenAt.Before(i.FirstSeenAt) {
		return fmt.Errorf("incident %q: last_seen_at before first_seen_at", i.IncidentID)
	}
	for _, a := range i.AlertIDs {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("incident %q: %w", i.IncidentID, err)
		}
	}
	return nil
}

// IncidentExport is the export bundle handed to the operator (§5 Module H):
// timeline, events, asset context, audit data – no packet payloads.
type IncidentExport struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Product     string       `json:"product"`
	Version     string       `json:"version"`
	Incident    Incident     `json:"incident"`
	Alerts      []Alert      `json:"alerts"`
	Events      []Event      `json:"events"`
	Assets      []Asset      `json:"assets"`
	Audit       []AuditEntry `json:"audit"`
	Constraints []string     `json:"constraints"`
}
