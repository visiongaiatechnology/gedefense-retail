package domain

import (
	"fmt"
	"time"
)

// Severity is the operator-visible priority of an alert.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Rank returns a monotonic value for comparisons and escalation.
func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	}
	return -1
}

// Category groups alerts by detection domain. It is the primary filter in the
// dashboard and in the escalation policy.
type Category string

const (
	CategoryAccess       Category = "access"
	CategoryNetwork      Category = "network"
	CategoryThermal      Category = "thermal"
	CategoryIntegrity    Category = "integrity"
	CategoryDeviceHealth Category = "device_health"
	CategoryDataQuality  Category = "data_quality"
)

func (c Category) Valid() bool {
	switch c {
	case CategoryAccess, CategoryNetwork, CategoryThermal, CategoryIntegrity, CategoryDeviceHealth, CategoryDataQuality:
		return true
	}
	return false
}

// AlertStatus models the operator workflow. The workflow never changes the
// process state of the refrigeration plant – it is documentation only.
type AlertStatus string

const (
	AlertOpen          AlertStatus = "open"
	AlertAcknowledged  AlertStatus = "acknowledged"
	AlertInvestigating AlertStatus = "investigating"
	AlertResolved      AlertStatus = "resolved"
	AlertClosed        AlertStatus = "closed"
	AlertFalsePositive AlertStatus = "false_positive"
)

func (s AlertStatus) Valid() bool {
	switch s {
	case AlertOpen, AlertAcknowledged, AlertInvestigating, AlertResolved, AlertClosed, AlertFalsePositive:
		return true
	}
	return false
}

// Evidence is one auditable fact behind an alert. Evidence must be reproducible
// from stored events; it never contains packet payloads or personal data.
type Evidence struct {
	Kind        string    `json:"kind"` // event, measurement, baseline, policy, window
	RefID       string    `json:"ref_id,omitempty"`
	Description string    `json:"description"`
	At          time.Time `json:"at"`
	Source      string    `json:"source"`
	Value       string    `json:"value,omitempty"`
	Confidence  float64   `json:"confidence"`
}

// CorrelationSummary separates observed facts from derived hypotheses from
// recommended checks – a hard product rule (§11 of the blueprint).
type CorrelationSummary struct {
	ChainID                 string   `json:"chain_id,omitempty"`
	ObservedFacts           []string `json:"observed_facts"`
	Hypothesis              string   `json:"hypothesis"`
	AlternativeExplanations []string `json:"alternative_explanations,omitempty"`
	RecommendedChecks       []string `json:"recommended_checks,omitempty"`
	Indicators              []string `json:"indicators,omitempty"`
}

// RecommendedAction is an operator suggestion. RequiresApproval marks actions
// that must never be executed automatically by the MVP.
type RecommendedAction struct {
	Action           string `json:"action"`
	RequiresApproval bool   `json:"requires_approval"`
	SafetyNote       string `json:"safety_note,omitempty"`
}

// AlertAuditEntry is the immutable per-alert history entry.
type AlertAuditEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Role   string    `json:"role"`
	Action string    `json:"action"`
	Note   string    `json:"note,omitempty"`
}

// Alert is a detection result. The same detection may be updated over time
// (LastSeenAt, additional evidence) but never rewritten in a way that hides the
// first observation.
type Alert struct {
	AlertID            AlertID             `json:"alert_id"`
	SiteID             SiteID              `json:"site_id"`
	AssetIDs           []AssetID           `json:"asset_ids,omitempty"`
	ZoneIDs            []ZoneID            `json:"zone_ids,omitempty"`
	SensorIDs          []SensorID          `json:"sensor_ids,omitempty"`
	Category           Category            `json:"category"`
	Severity           Severity            `json:"severity"`
	Confidence         float64             `json:"confidence"`
	Title              string              `json:"title"`
	Summary            string              `json:"summary"`
	RuleID             RuleID              `json:"rule_id"`
	RuleVersion        string              `json:"rule_version"`
	FirstSeenAt        time.Time           `json:"first_seen_at"`
	LastSeenAt         time.Time           `json:"last_seen_at"`
	Status             AlertStatus         `json:"status"`
	Assignee           UserID              `json:"assignee,omitempty"`
	Evidence           []Evidence          `json:"evidence"`
	Correlation        *CorrelationSummary `json:"correlation,omitempty"`
	RecommendedActions []RecommendedAction `json:"recommended_actions,omitempty"`
	SafetyConstraints  []string            `json:"safety_constraints,omitempty"`
	DedupKey           string              `json:"dedup_key"`
	IncidentID         IncidentID          `json:"incident_id,omitempty"`
	AuditHistory       []AlertAuditEntry   `json:"audit_history"`
	CreatedAt          time.Time           `json:"created_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
}

// Validate enforces the alert contract before persistence.
func (a Alert) Validate() error {
	if err := a.AlertID.Validate(); err != nil {
		return fmt.Errorf("alert: %w", err)
	}
	if err := a.SiteID.Validate(); err != nil {
		return fmt.Errorf("alert %q: %w", a.AlertID, err)
	}
	if !a.Category.Valid() {
		return fmt.Errorf("alert %q: invalid category %q", a.AlertID, a.Category)
	}
	if !a.Severity.Valid() {
		return fmt.Errorf("alert %q: invalid severity %q", a.AlertID, a.Severity)
	}
	if !a.Status.Valid() {
		return fmt.Errorf("alert %q: invalid status %q", a.AlertID, a.Status)
	}
	if a.Confidence < 0 || a.Confidence > 1 {
		return fmt.Errorf("alert %q: confidence %v outside [0,1]", a.AlertID, a.Confidence)
	}
	if a.FirstSeenAt.IsZero() || a.LastSeenAt.IsZero() {
		return fmt.Errorf("alert %q: timestamps are required", a.AlertID)
	}
	if a.LastSeenAt.Before(a.FirstSeenAt) {
		return fmt.Errorf("alert %q: last_seen_at before first_seen_at", a.AlertID)
	}
	if a.Title == "" || a.Summary == "" {
		return fmt.Errorf("alert %q: title and summary are required", a.AlertID)
	}
	if a.RuleID == "" || a.RuleVersion == "" {
		return fmt.Errorf("alert %q: rule id and version are required", a.AlertID)
	}
	if a.Correlation != nil {
		if len(a.Correlation.ObservedFacts) == 0 || a.Correlation.Hypothesis == "" {
			return fmt.Errorf("alert %q: correlation requires facts and hypothesis", a.AlertID)
		}
	}
	return nil
}
