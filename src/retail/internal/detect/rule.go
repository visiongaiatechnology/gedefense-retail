package detect

import (
	"context"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Rule is one versioned detection rule that evaluates a single normalized event.
// Implementations must be stateless and safe for concurrent use: all mutable
// state lives in the World, not in the rule.
type Rule interface {
	ID() domain.RuleID
	Version() string
	Name() string
	Category() domain.Category
	OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert
}

// TickRule is a rule that additionally evaluates the periodic detection loop
// (for example telemetry gaps or asset lifecycle advisories).
type TickRule interface {
	Rule
	OnTick(ctx context.Context, w World) []domain.Alert
}

// RuleInfo is the operator- and API-visible metadata of one rule. ID, Version,
// Name, Category and Description are contract fields; the remaining fields make
// the rule catalogue self-documenting for the UI without a separate document
// lookup.
type RuleInfo struct {
	ID                  domain.RuleID              `json:"rule_id"`
	Version             string                     `json:"version"`
	Name                string                     `json:"name"`
	Category            domain.Category            `json:"category"`
	Description         string                     `json:"description"`
	Baseline            string                     `json:"baseline,omitempty"`
	ConfidenceModel     string                     `json:"confidence_model,omitempty"`
	DedupKeyTemplate    string                     `json:"dedup_key_template,omitempty"`
	SeverityMatrix      []rules.SeverityLevel      `json:"severity_matrix,omitempty"`
	RecommendedActions  []domain.RecommendedAction `json:"recommended_actions,omitempty"`
	SafetyConstraints   []string                   `json:"safety_constraints,omitempty"`
	FalsePositiveLimits []string                   `json:"false_positive_boundaries,omitempty"`
	EventKinds          []domain.EventKind         `json:"event_kinds,omitempty"`
	Tick                bool                       `json:"tick"`
}

func infoFromSpec(spec rules.Spec) RuleInfo {
	return RuleInfo{
		ID:                  spec.ID,
		Version:             spec.Version,
		Name:                spec.Name,
		Category:            spec.Category,
		Description:         spec.Description,
		Baseline:            spec.Baseline,
		ConfidenceModel:     spec.Confidence,
		DedupKeyTemplate:    spec.DedupKeyTemplate,
		SeverityMatrix:      append([]rules.SeverityLevel(nil), spec.SeverityMatrix...),
		RecommendedActions:  append([]domain.RecommendedAction(nil), spec.RecommendedActions...),
		SafetyConstraints:   append([]string(nil), spec.SafetyConstraints...),
		FalsePositiveLimits: append([]string(nil), spec.FalsePositiveBoundaries...),
		EventKinds:          append([]domain.EventKind(nil), spec.EventKinds...),
		Tick:                spec.Tick,
	}
}

func cloneRuleInfo(info RuleInfo) RuleInfo {
	info.SeverityMatrix = append([]rules.SeverityLevel(nil), info.SeverityMatrix...)
	info.RecommendedActions = append([]domain.RecommendedAction(nil), info.RecommendedActions...)
	info.SafetyConstraints = append([]string(nil), info.SafetyConstraints...)
	info.FalsePositiveLimits = append([]string(nil), info.FalsePositiveLimits...)
	info.EventKinds = append([]domain.EventKind(nil), info.EventKinds...)
	return info
}

// baseRule carries the immutable rule metadata and implements the metadata part
// of the Rule interface. It is embedded by every concrete rule.
type baseRule struct {
	spec rules.Spec
}

// baseFor resolves the rule metadata. The rule pack is static and covered by
// tests, so a missing entry means a programming error; the fallback keeps the
// library panic-free and still produces a valid alert category.
func baseFor(id domain.RuleID) baseRule {
	if spec, ok := rules.ByID(id); ok {
		return baseRule{spec: spec}
	}
	return baseRule{spec: rules.Spec{
		ID:          id,
		Version:     rules.Version,
		Name:        string(id),
		Category:    domain.CategoryDeviceHealth,
		Description: "Regel-Metadaten fehlen im Regel-Pack.",
	}}
}

func (b baseRule) ID() domain.RuleID         { return b.spec.ID }
func (b baseRule) Version() string           { return b.spec.Version }
func (b baseRule) Name() string              { return b.spec.Name }
func (b baseRule) Category() domain.Category { return b.spec.Category }
