package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	gatealert "github.com/visiongaiatechnology/gedefense/retail/internal/gate/alert"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/bypass"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// bypassContextKey carries the per-evaluation collector from the pipeline into the
// bypass emitter. The bypass engine itself is stateless, so concurrent
// ProcessBatch calls cannot mix their mapped monitoring alerts.
type bypassContextKey struct{}

// bypassCollector holds the signal of one evaluation and the mapped monitoring
// alerts produced by the emitter.
type bypassCollector struct {
	signal bypass.PassiveWriteSignal
	alerts []domain.Alert
}

// bypassEmitter implements bypass.Emitter. It maps the gate alert onto the
// monitoring domain alert and appends it to the call-scoped collector; it never
// writes to the alert store directly (the pipeline owns alerts.Observe and the
// correlation run).
type bypassEmitter struct{}

// Emit implements bypass.Emitter.
func (bypassEmitter) Emit(ctx context.Context, gateAlert gatealert.Alert) (gatealert.Alert, error) {
	collector, ok := ctx.Value(bypassContextKey{}).(*bypassCollector)
	if !ok {
		return gateAlert, errors.New("bypass: emitter called without a pipeline collector")
	}
	alert, err := bypassAlertFromGate(gateAlert, collector.signal)
	if err != nil {
		return gateAlert, err
	}
	collector.alerts = append(collector.alerts, alert)
	return gateAlert, nil
}

// newBypassEngine builds the gate-bypass detector for the retaild monitoring
// pipeline. It returns (nil, nil) when the feature is disabled. The config
// validation already enforces the fail-closed CIDR contract; bypass.New validates
// again so a programmatic configuration cannot start half-configured.
func newBypassEngine(cfg *config.BypassConfig, clock ports.Clock) (*bypass.Engine, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	if clock == nil {
		return nil, errors.New("bypass: clock is required")
	}
	return bypass.New(bypass.Options{
		Clock:     clock,
		GateCIDRs: append([]string(nil), cfg.GateSourceCIDRs...),
		Emitter:   bypassEmitter{},
	})
}

// bypassSignal maps one passive write-attempt event onto the gate bypass signal.
// Reads, disabled configurations and events without a write-attempt block never
// produce a bypass signal.
func bypassSignal(ev domain.Event) (bypass.PassiveWriteSignal, bool) {
	if ev.Kind != domain.EventWriteAttempt || ev.WriteAttempt == nil {
		return bypass.PassiveWriteSignal{}, false
	}
	attempt := ev.WriteAttempt
	at := ev.ObservedAt
	if at.IsZero() {
		at = ev.ReceivedAt
	}
	if at.IsZero() {
		return bypass.PassiveWriteSignal{}, false
	}
	return bypass.PassiveWriteSignal{
		SiteID:    ev.SiteID,
		At:        at.UTC(),
		SourceIP:  attempt.Source,
		Target:    attempt.Target,
		AssetID:   ev.AssetID,
		Protocol:  attempt.Protocol,
		Function:  attempt.Function,
		Address:   attempt.Register,
		ValueHint: attempt.ValueHint,
		Allowed:   attempt.Allowed,
		// The passive observation can prove what was seen on the wire, never who
		// initiated it or whether it was authorized.
		Detail: "Passive Beobachtung; Urheberschaft und Freigabe sind dadurch nicht belegt.",
	}, true
}

// bypassAlerts runs the bypass engine for one event and returns the mapped
// monitoring alerts. The gate sources are filtered by the bypass engine itself;
// a read or an event without a write-attempt block yields nothing.
func (p *pipeline) bypassAlerts(ctx context.Context, ev domain.Event) []domain.Alert {
	if p == nil || p.bypass == nil {
		return nil
	}
	signal, ok := bypassSignal(ev)
	if !ok {
		return nil
	}
	collector := &bypassCollector{signal: signal}
	ctx = context.WithValue(ctx, bypassContextKey{}, collector)
	if _, raised, err := p.bypass.Observe(ctx, signal); err != nil {
		if p.log != nil {
			p.log.Warn("bypass observe failed", "event_id", string(ev.EventID), "error", err.Error())
		}
		return nil
	} else if !raised {
		return nil
	}
	return collector.alerts
}

// bypassAlertFromGate converts the gate bypass alert into the monitoring alert
// contract (critical, category access, rule retail.bypass-suspected) while keeping
// the evidence, facts, hypothesis and recommended checks of the gate alert. The
// dedup key is source+target+register, so a write storm becomes one merged alert.
func bypassAlertFromGate(g gatealert.Alert, signal bypass.PassiveWriteSignal) (domain.Alert, error) {
	if g.SiteID == "" {
		return domain.Alert{}, errors.New("bypass: gate alert has no site")
	}
	at := g.At.UTC()
	if at.IsZero() {
		at = signal.At.UTC()
	}
	if at.IsZero() {
		at = time.Unix(0, 0).UTC()
	}
	last := g.LastSeenAt.UTC()
	if last.IsZero() {
		last = at
	}
	if last.Before(at) {
		last = at
	}
	facts := append([]string(nil), g.ObservedFacts...)
	if len(facts) == 0 {
		facts = append(facts, fmt.Sprintf(
			"Passiv beobachteter Schreibversuch von %s auf %s/%s (Adresse %s).",
			valueOr(signal.SourceIP, "unbekannt"), valueOr(signal.Target, "unbekannt"),
			valueOr(signal.Function, "unbekannt"), valueOr(signal.Address, "unbekannt"),
		))
	}
	hypothesis := strings.TrimSpace(g.Hypothesis)
	if hypothesis == "" {
		hypothesis = "Der Schreibweg verlief nicht über den konfigurierten Gate-Datenpfad; Urheberschaft und Freigabe sind unbelegt."
	}
	checks := append([]string(nil), g.RecommendedChecks...)
	evidence := make([]domain.Evidence, 0, len(g.Evidence))
	for _, item := range g.Evidence {
		evidence = append(evidence, domain.Evidence{
			Kind:        item.Kind,
			RefID:       item.RefID,
			Description: item.Description,
			At:          item.At.UTC(),
			Source:      item.Source,
			Value:       item.Value,
			Confidence:  clampUnit(item.Confidence),
		})
	}
	if len(evidence) == 0 {
		evidence = append(evidence, domain.Evidence{
			Kind:        "bypass",
			Description: "Passiv beobachteter Schreibversuch außerhalb der Gate-Quellen",
			At:          at,
			Source:      "retaild.passive",
			Value:       fmt.Sprintf("source=%s target=%s register=%s", valueOr(signal.SourceIP, "unbekannt"), valueOr(signal.Target, "unbekannt"), valueOr(signal.Address, "unbekannt")),
			Confidence:  clampUnit(g.Confidence),
		})
	}
	alert := domain.Alert{
		AlertID:            newBypassAlertID(),
		SiteID:             g.SiteID,
		Category:           domain.CategoryAccess,
		Severity:           domain.SeverityCritical,
		Confidence:         clampUnit(g.Confidence),
		Title:              "Bypass-Verdacht: Schreibzugriff außerhalb des Gate-Pfads",
		Summary:            composeBypassSummary(facts, hypothesis, checks),
		RuleID:             rules.IDBypassSuspected,
		RuleVersion:        rules.Version,
		FirstSeenAt:        at,
		LastSeenAt:         last,
		Status:             domain.AlertOpen,
		Evidence:           evidence,
		RecommendedActions: append([]domain.RecommendedAction(nil), g.RecommendedActions...),
		SafetyConstraints:  append([]string(nil), g.SafetyConstraints...),
		DedupKey:           rules.DedupKey(rules.IDBypassSuspected, string(g.SiteID), signal.SourceIP, signal.Target, signal.Address),
		CreatedAt:          at,
		UpdatedAt:          last,
		Correlation: &domain.CorrelationSummary{
			ObservedFacts:           facts,
			Hypothesis:              hypothesis,
			AlternativeExplanations: append([]string(nil), g.AlternativeExplanations...),
			RecommendedChecks:       checks,
		},
	}
	if signal.AssetID != "" {
		alert.AssetIDs = []domain.AssetID{signal.AssetID}
	} else if g.AssetID != "" {
		alert.AssetIDs = []domain.AssetID{g.AssetID}
	}
	if err := alert.Validate(); err != nil {
		return domain.Alert{}, fmt.Errorf("bypass: mapped monitoring alert is invalid: %w", err)
	}
	return alert, nil
}

// composeBypassSummary keeps the hard fact/hypothesis/check separation.
func composeBypassSummary(facts []string, hypothesis string, checks []string) string {
	var b strings.Builder
	b.WriteString("Beobachtung: ")
	for i, fact := range facts {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(strings.TrimSuffix(strings.TrimSpace(fact), "."))
	}
	b.WriteString(". Hypothese: ")
	b.WriteString(strings.TrimSuffix(strings.TrimSpace(hypothesis), "."))
	if len(checks) > 0 {
		b.WriteString(". Empfohlene Prüfung: ")
		limit := len(checks)
		if limit > 3 {
			limit = 3
		}
		for i := 0; i < limit; i++ {
			if i > 0 {
				b.WriteString("; ")
			}
			b.WriteString(strings.TrimSuffix(strings.TrimSpace(checks[i]), "."))
		}
	}
	b.WriteString(".")
	runes := []rune(b.String())
	if len(runes) > 1600 {
		return string(runes[:1600]) + "…"
	}
	return b.String()
}

// valueOr returns the trimmed value or the fallback.
func valueOr(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

// clampUnit bounds a confidence value to [0,1].
func clampUnit(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

var bypassAlertFallbackSeq uint64

// newBypassAlertID returns an unpredictable alert identifier ("alr_" prefix).
func newBypassAlertID() domain.AlertID {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return domain.AlertID("alr_" + hex.EncodeToString(buf[:]))
	}
	return domain.AlertID(fmt.Sprintf("alr_%032x", atomic.AddUint64(&bypassAlertFallbackSeq, 1)))
}
