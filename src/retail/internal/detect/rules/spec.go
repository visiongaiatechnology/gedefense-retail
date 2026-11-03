// Package rules is the versioned, declarative rule pack for GeDefense Retail
// detection.
//
// It contains the operator-visible metadata of every detection rule: the stable
// identifier, the rule version, the alert category, the documented baseline, the
// confidence model, the deduplication key template, the severity matrix, the
// recommended operator actions and the safety constraints. The executable rule
// logic lives in the parent package (internal/detect); this package is data and
// string helpers only. That separation lets the API and the UI render the rule
// catalogue without importing the detection engine, and it keeps rule metadata
// reviewable by an operator who does not read Go control flow.
//
// Every rule here is passive: it observes already-normalized events and derived
// telemetry. No rule can write to an OT device, force a scan, or change a plant
// process (see internal/guard).
package rules

import (
	"sort"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// SeverityLevel is one row of a rule's severity matrix. The matrix is data, not
// prose: the executable rule selects a severity from the operator policy and the
// observed evidence, and this table documents which decision it took and why.
type SeverityLevel struct {
	Severity domain.Severity `json:"severity"`
	When     string          `json:"when"`
}

// Spec is the immutable metadata record of one detection rule.
type Spec struct {
	ID          domain.RuleID   `json:"rule_id"`
	Version     string          `json:"version"`
	Name        string          `json:"name"`
	Category    domain.Category `json:"category"`
	Description string          `json:"description"`
	// Baseline documents when the rule considers the observed state "normal".
	Baseline string `json:"baseline"`
	// Confidence documents how the numeric confidence is computed.
	Confidence string `json:"confidence_model"`
	// DedupKeyTemplate documents the dimensions of the stable dedup key.
	DedupKeyTemplate string `json:"dedup_key_template"`
	// SeverityMatrix maps observed conditions to severities.
	SeverityMatrix []SeverityLevel `json:"severity_matrix"`
	// RecommendedActions are operator suggestions; actions that would touch the
	// plant or the maintenance path require explicit approval.
	RecommendedActions []domain.RecommendedAction `json:"recommended_actions"`
	// SafetyConstraints are non-negotiable limits of what GeDefense may do.
	SafetyConstraints []string `json:"safety_constraints"`
	// FalsePositiveBoundaries documents known benign explanations and the
	// deliberate limits of the rule.
	FalsePositiveBoundaries []string `json:"false_positive_boundaries"`
	// EventKinds are the normalized event kinds the rule reacts to.
	EventKinds []domain.EventKind `json:"event_kinds,omitempty"`
	// Tick marks rules that additionally run in the periodic evaluation loop.
	Tick bool `json:"tick"`
}

// All returns the complete rule pack ordered by rule identifier. The returned
// slice is a copy: callers cannot mutate the pack.
func All() []Spec {
	out := make([]Spec, 0, len(catalog))
	for _, spec := range catalog {
		out = append(out, spec.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ByID returns the metadata of one rule.
func ByID(id domain.RuleID) (Spec, bool) {
	for _, spec := range catalog {
		if spec.ID == id {
			return spec.clone(), true
		}
	}
	return Spec{}, false
}

func (s Spec) clone() Spec {
	s.SeverityMatrix = append([]SeverityLevel(nil), s.SeverityMatrix...)
	s.RecommendedActions = append([]domain.RecommendedAction(nil), s.RecommendedActions...)
	s.SafetyConstraints = append([]string(nil), s.SafetyConstraints...)
	s.FalsePositiveBoundaries = append([]string(nil), s.FalsePositiveBoundaries...)
	s.EventKinds = append([]domain.EventKind(nil), s.EventKinds...)
	return s
}

// action is a small constructor to keep the pack readable.
func action(text string, requiresApproval bool, safetyNote string) domain.RecommendedAction {
	return domain.RecommendedAction{Action: text, RequiresApproval: requiresApproval, SafetyNote: safetyNote}
}

// level is a small constructor for severity-matrix rows.
func level(severity domain.Severity, when string) SeverityLevel {
	return SeverityLevel{Severity: severity, When: when}
}

// commonSafety is the safety text every rule shares. It is repeated verbatim in
// each spec so an API/UI consumer can render one rule without merging sources.
func commonSafety() []string {
	return []string{
		"GeDefense Retail ist passiv: keine Schreibzugriffe auf OT-Geräte, keine Sollwertänderung, keine Anlagenabschaltung.",
		"Keine aktiven Scans oder Verbindungsfluten gegen produktive Anlagen.",
		"Keine automatische Netz-Isolation; Empfehlungen mit RequiresApproval benötigen eine verantwortliche Person.",
		"Keine Aussage über Lebensmittelsicherheit oder Compliance allein aus einem technischen Signal.",
	}
}

func combine(base []string, extra ...string) []string {
	out := make([]string, 0, len(base)+len(extra))
	out = append(out, base...)
	out = append(out, extra...)
	return out
}
