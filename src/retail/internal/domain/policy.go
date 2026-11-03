package domain

import (
	"fmt"
	"net"
	"time"
)

// Policy is the operator-owned, versioned rule set for one site. Every change
// creates a new immutable version plus an audit entry; the previous version is
// never overwritten (§6 Schritt 10 of the blueprint).
type Policy struct {
	PolicyID    PolicyID          `json:"policy_id"`
	SiteID      SiteID            `json:"site_id"`
	Version     int               `json:"version"`
	UpdatedAt   time.Time         `json:"updated_at"`
	UpdatedBy   UserID            `json:"updated_by"`
	Reason      string            `json:"reason"`
	Hash        string            `json:"hash,omitempty"` // canonical SHA-256 of the content
	Temperature TemperaturePolicy `json:"temperature"`
	Sensors     SensorPolicy      `json:"sensors"`
	Network     NetworkPolicy     `json:"network"`
	Maintenance MaintenancePolicy `json:"maintenance"`
	DataQuality DataQualityPolicy `json:"data_quality"`
	Retention   RetentionPolicy   `json:"retention"`
	Alerting    AlertingPolicy    `json:"alerting"`
}

// TemperatureLimit is configured per zone and metric. No universal limits are
// hardcoded: the operator declares them per product/zone.
type TemperatureLimit struct {
	ZoneID             ZoneID    `json:"zone_id"`
	Metric             string    `json:"metric"` // air_temperature, product_temperature
	MinC               *float64  `json:"min_c,omitempty"`
	MaxC               *float64  `json:"max_c,omitempty"`
	MaxRateCPerMin     *float64  `json:"max_rate_c_per_min,omitempty"`
	SetpointToleranceC *float64  `json:"setpoint_tolerance_c,omitempty"`
	ValidFrom          time.Time `json:"valid_from,omitempty"`
}

// TemperaturePolicy groups the per-zone limits.
type TemperaturePolicy struct {
	Limits []TemperatureLimit `json:"limits"`
	// AbsoluteImpossible bounds reject physically impossible values from being
	// treated as "valid but alarming"; they are data-quality boundaries.
	AbsoluteImpossibleMinC *float64 `json:"absolute_impossible_min_c,omitempty"`
	AbsoluteImpossibleMaxC *float64 `json:"absolute_impossible_max_c,omitempty"`
}

// SensorPolicy configures cross-sensor plausibility checks.
type SensorPolicy struct {
	// DivergenceC is the maximum allowed difference between two independent
	// sensors in the same zone before a data-quality alert is raised.
	DivergenceC       *float64 `json:"divergence_c,omitempty"`
	DivergenceWindowS int      `json:"divergence_window_s,omitempty"`
}

// NetworkPolicy configures the communication baseline.
type NetworkPolicy struct {
	// BaselineRequired: when true, unknown peers are alerts; when false, they
	// are recorded as observations only (observe-first onboarding).
	BaselineRequired bool `json:"baseline_required"`
	// LearnedBaselineWindowS limits how long the passive learning phase runs.
	LearnedBaselineWindowS int `json:"learned_baseline_window_s,omitempty"`
	// Allowlist of source->target communication pairs (zone-aware).
	AllowedPairs []AllowedPair `json:"allowed_pairs,omitempty"`
	// MonitoredPorts restricts which passive flows are evaluated (empty = all).
	MonitoredPorts []int `json:"monitored_ports,omitempty"`
	// UnknownPeerGraceS suppresses unknown-peer alerts during onboarding.
	UnknownPeerGraceS int `json:"unknown_peer_grace_s,omitempty"`
}

// AllowedPair is one approved communication relationship.
type AllowedPair struct {
	SourceAssetID AssetID `json:"source_asset_id,omitempty"`
	SourceZoneID  ZoneID  `json:"source_zone_id,omitempty"`
	TargetAssetID AssetID `json:"target_asset_id,omitempty"`
	TargetZoneID  ZoneID  `json:"target_zone_id,omitempty"`
	Protocol      string  `json:"protocol,omitempty"`
	Port          int     `json:"port,omitempty"`
	Note          string  `json:"note,omitempty"`
}

// MaintenancePolicy decides how strict maintenance access is evaluated.
type MaintenancePolicy struct {
	// RequireWindow: external access outside a window is at least High.
	RequireWindow bool `json:"require_window"`
	// GracePeriodS tolerates late-started sessions just after a window ends.
	GracePeriodS int `json:"grace_period_s,omitempty"`
	// TrustedVendors are vendor names that were onboarded by the operator.
	TrustedVendors []string `json:"trusted_vendors,omitempty"`
}

// DataQualityPolicy configures "is the measurement trustworthy" rules.
type DataQualityPolicy struct {
	// FrozenValueWindowS: identical values longer than this are suspicious.
	FrozenValueWindowS int `json:"frozen_value_window_s,omitempty"`
	// TelemetryGapS: missing telemetry longer than this is a gap.
	TelemetryGapS int `json:"telemetry_gap_s,omitempty"`
	// MaxClockSkewS: observed_at vs. gateway clock tolerance.
	MaxClockSkewS int `json:"max_clock_skew_s,omitempty"`
}

// RetentionPolicy bounds local storage (§11 of the blueprint).
type RetentionPolicy struct {
	EventDays  int   `json:"event_days,omitempty"`
	AlertDays  int   `json:"alert_days,omitempty"`
	AuditDays  int   `json:"audit_days,omitempty"`
	MaxEventMB int64 `json:"max_event_mb,omitempty"`
	MaxSpoolMB int64 `json:"max_spool_mb,omitempty"`
}

// AlertingPolicy decides notification thresholds and escalation.
type AlertingPolicy struct {
	MinNotifySeverity Severity         `json:"min_notify_severity"`
	Escalation        []EscalationStep `json:"escalation,omitempty"`
}

// EscalationStep is one rung of the operator-approved escalation chain.
type EscalationStep struct {
	AfterMinutes int    `json:"after_minutes"`
	Role         string `json:"role"`
	Channel      string `json:"channel,omitempty"`
	Note         string `json:"note,omitempty"`
}

// DefaultPolicy returns a fail-safe default: passive, observe-first, no
// universal temperature limits, alerting only for high/critical.
func DefaultPolicy(site SiteID, now time.Time) Policy {
	return Policy{
		PolicyID:    PolicyID("policy-" + string(site)),
		SiteID:      site,
		Version:     1,
		UpdatedAt:   now.UTC(),
		Temperature: TemperaturePolicy{Limits: []TemperatureLimit{}},
		Network:     NetworkPolicy{BaselineRequired: false, UnknownPeerGraceS: 3600},
		Maintenance: MaintenancePolicy{RequireWindow: true, GracePeriodS: 300},
		DataQuality: DataQualityPolicy{FrozenValueWindowS: 1800, TelemetryGapS: 900, MaxClockSkewS: 300},
		Retention:   RetentionPolicy{EventDays: 30, AlertDays: 180, AuditDays: 365, MaxEventMB: 2048, MaxSpoolMB: 512},
		Alerting:    AlertingPolicy{MinNotifySeverity: SeverityHigh},
	}
}

// Validate enforces the policy contract. Limits are optional but, if set, must
// be coherent (min < max, positive windows).
func (p Policy) Validate() error {
	if err := p.PolicyID.Validate(); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if err := p.SiteID.Validate(); err != nil {
		return fmt.Errorf("policy %q: %w", p.PolicyID, err)
	}
	if p.Version < 1 {
		return fmt.Errorf("policy %q: version must be >= 1", p.PolicyID)
	}
	if p.UpdatedAt.IsZero() {
		return fmt.Errorf("policy %q: updated_at is required", p.PolicyID)
	}
	for i, l := range p.Temperature.Limits {
		if err := l.ZoneID.Validate(); err != nil {
			return fmt.Errorf("policy %q limit %d: %w", p.PolicyID, i, err)
		}
		if l.Metric == "" {
			return fmt.Errorf("policy %q limit %d: metric is required", p.PolicyID, i)
		}
		if l.MinC != nil && l.MaxC != nil && *l.MinC >= *l.MaxC {
			return fmt.Errorf("policy %q limit %d: min_c must be < max_c", p.PolicyID, i)
		}
		if l.MaxRateCPerMin != nil && *l.MaxRateCPerMin <= 0 {
			return fmt.Errorf("policy %q limit %d: max_rate_c_per_min must be > 0", p.PolicyID, i)
		}
	}
	for _, pair := range p.Network.AllowedPairs {
		if pair.Port < 0 || pair.Port > 65535 {
			return fmt.Errorf("policy %q: allowed pair has invalid port %d", p.PolicyID, pair.Port)
		}
	}
	if p.Network.UnknownPeerGraceS < 0 || p.Network.LearnedBaselineWindowS < 0 {
		return fmt.Errorf("policy %q: negative network window", p.PolicyID)
	}
	if p.DataQuality.FrozenValueWindowS < 0 || p.DataQuality.TelemetryGapS < 0 || p.DataQuality.MaxClockSkewS < 0 {
		return fmt.Errorf("policy %q: negative data-quality window", p.PolicyID)
	}
	if p.Retention.EventDays < 1 || p.Retention.AlertDays < 1 || p.Retention.AuditDays < 1 {
		return fmt.Errorf("policy %q: retention days must be >= 1", p.PolicyID)
	}
	if p.Retention.MaxEventMB < 1 || p.Retention.MaxSpoolMB < 1 {
		return fmt.Errorf("policy %q: retention size limits must be >= 1 MB", p.PolicyID)
	}
	if p.Alerting.MinNotifySeverity != "" && !p.Alerting.MinNotifySeverity.Valid() {
		return fmt.Errorf("policy %q: invalid notification severity", p.PolicyID)
	}
	for _, step := range p.Alerting.Escalation {
		if step.AfterMinutes < 0 || step.Role == "" {
			return fmt.Errorf("policy %q: invalid escalation step", p.PolicyID)
		}
	}
	return nil
}

// PolicyVersion is the immutable stored record of one policy revision.
type PolicyVersion struct {
	Policy     Policy    `json:"policy"`
	StoredAt   time.Time `json:"stored_at"`
	StoredBy   UserID    `json:"stored_by,omitempty"`
	ChangeNote string    `json:"change_note,omitempty"`
	PrevHash   string    `json:"prev_hash,omitempty"`
}

func validateCIDR(c string) error {
	if _, _, err := net.ParseCIDR(c); err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", c, err)
	}
	return nil
}
