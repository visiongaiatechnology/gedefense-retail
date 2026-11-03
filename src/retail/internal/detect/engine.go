package detect

import (
	"context"
	"sort"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Engine evaluates normalized events and the periodic tick against a World and
// returns at most validated, deterministically ordered alerts.
//
// The engine is stateless apart from its rule list; all mutable detection state
// (peers, samples, windows, assets) is owned by the World. That keeps the
// detection loop restartable and makes -race testing meaningful.
type Engine struct {
	world      World
	clock      ports.Clock
	eventRules []Rule
	tickRules  []TickRule
	info       []RuleInfo
}

// worldClock is the fallback clock when the caller does not inject one. It
// delegates to the World clock so detection never silently uses wall time.
type worldClock struct {
	world World
}

func (c worldClock) Now() time.Time {
	if c.world == nil {
		return time.Time{}
	}
	return c.world.Now()
}

// NewEngine constructs the detection engine for the given read model. A nil
// clock falls back to the World clock; a nil World makes the engine inert
// (EvaluateEvent/EvaluateTick return no alerts) instead of panicking.
func NewEngine(w World, clock ports.Clock) *Engine {
	engine := &Engine{world: w}
	if clock != nil {
		engine.clock = clock
	} else {
		engine.clock = worldClock{world: w}
	}
	engine.eventRules, engine.tickRules = newRuleSet()
	engine.info = make([]RuleInfo, 0, len(engine.eventRules))
	for _, spec := range rules.All() {
		engine.info = append(engine.info, infoFromSpec(spec))
	}
	return engine
}

// Rules returns the metadata of every shipped rule, ordered by rule identifier.
// The slice is a defensive copy so callers cannot mutate the engine catalogue.
func (e *Engine) Rules() []RuleInfo {
	if e == nil {
		return nil
	}
	out := make([]RuleInfo, 0, len(e.info))
	for _, info := range e.info {
		out = append(out, cloneRuleInfo(info))
	}
	return out
}

// EvaluateEvent runs every event rule against one normalized event and returns
// the resulting alerts. Invalid events are rejected before any rule sees them;
// canceled contexts stop evaluation immediately.
func (e *Engine) EvaluateEvent(ctx context.Context, ev domain.Event) []domain.Alert {
	if e == nil || e.world == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	if err := ev.Validate(); err != nil {
		return nil
	}
	out := make([]domain.Alert, 0, 4)
	for _, rule := range e.eventRules {
		if err := ctx.Err(); err != nil {
			break
		}
		out = append(out, rule.OnEvent(ctx, ev, e.world)...)
	}
	return e.finalize(out, ev.SiteID, trustedTime(ev))
}

// EvaluateTick runs the periodic rules (telemetry gaps, asset lifecycle) and
// returns their alerts. Tick rules use the World clock, never wall time.
func (e *Engine) EvaluateTick(ctx context.Context) []domain.Alert {
	if e == nil || e.world == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	out := make([]domain.Alert, 0, 4)
	for _, rule := range e.tickRules {
		if err := ctx.Err(); err != nil {
			break
		}
		out = append(out, rule.OnTick(ctx, e.world)...)
	}
	return e.finalize(out, "", time.Time{})
}

// finalize completes rule-generated alerts with engine-owned fields, drops
// duplicates and invalid alerts, and sorts the result deterministically. Dropping
// an invalid alert protects the store/API from a rule regression; the shipped
// rules are covered by tests asserting they always produce valid alerts.
func (e *Engine) finalize(in []domain.Alert, fallbackSite domain.SiteID, observedAt time.Time) []domain.Alert {
	if len(in) == 0 {
		return nil
	}
	now := e.clock.Now().UTC()
	seen := make(map[string]struct{}, len(in))
	out := make([]domain.Alert, 0, len(in))
	for _, alert := range in {
		if alert.SiteID == "" {
			alert.SiteID = fallbackSite
		}
		if alert.RuleID == "" {
			continue
		}
		if alert.AlertID == "" {
			alert.AlertID = newAlertID()
		}
		if alert.Status == "" {
			alert.Status = domain.AlertOpen
		}
		if alert.RuleVersion == "" {
			alert.RuleVersion = rules.Version
		}
		instant := observedAt
		if instant.IsZero() || instant.After(now) {
			instant = now
		}
		if alert.FirstSeenAt.IsZero() {
			alert.FirstSeenAt = instant
		}
		if alert.LastSeenAt.IsZero() {
			alert.LastSeenAt = alert.FirstSeenAt
		}
		if alert.LastSeenAt.Before(alert.FirstSeenAt) {
			alert.LastSeenAt = alert.FirstSeenAt
		}
		if alert.CreatedAt.IsZero() {
			alert.CreatedAt = now
		}
		if alert.UpdatedAt.IsZero() {
			alert.UpdatedAt = now
		}
		if alert.DedupKey == "" {
			alert.DedupKey = rules.DedupKey(alert.RuleID, string(alert.SiteID), alert.Title)
		}
		if _, duplicate := seen[alert.DedupKey]; duplicate {
			continue
		}
		if err := alert.Validate(); err != nil {
			continue
		}
		seen[alert.DedupKey] = struct{}{}
		out = append(out, alert)
	}
	if len(out) == 0 {
		return nil
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].DedupKey != out[j].DedupKey {
			return out[i].DedupKey < out[j].DedupKey
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}
