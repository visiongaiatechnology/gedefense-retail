package app

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/alert"
	"github.com/visiongaiatechnology/gedefense/retail/internal/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/correlate"
	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
	"github.com/visiongaiatechnology/gedefense/retail/internal/state"
	"github.com/visiongaiatechnology/gedefense/retail/internal/store"
)

const bypassSite = domain.SiteID("filiale-001")

var bypassBaseTime = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type bypassClock struct {
	now time.Time
}

func (c *bypassClock) Now() time.Time { return c.now }

type bypassHarness struct {
	pipeline *pipeline
	alerts   *alert.Engine
	clock    *bypassClock
}

func newBypassHarness(t *testing.T, cfg *config.BypassConfig) *bypassHarness {
	t.Helper()
	dir := t.TempDir()
	clock := &bypassClock{now: bypassBaseTime}
	eventLog, err := store.OpenEventLog(store.Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	t.Cleanup(func() {
		if cerr := eventLog.Close(); cerr != nil {
			t.Errorf("EventLog.Close: %v", cerr)
		}
	})
	alertStore, err := store.OpenAlertStore(store.Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAlertStore: %v", err)
	}
	t.Cleanup(func() {
		if cerr := alertStore.Close(); cerr != nil {
			t.Errorf("AlertStore.Close: %v", cerr)
		}
	})
	registry := state.NewRegistry([]domain.Site{{
		SiteID: bypassSite, Name: "Markt Nord", Status: domain.SiteOnline,
		Zones: []domain.Zone{{ZoneID: "zone-ot", SiteID: bypassSite, Name: "OT", Kind: domain.ZoneOTProcess}},
	}}, clock)
	alertEngine := alert.NewEngine(alert.Options{Store: alertStore, Clock: clock})
	correlator := correlate.NewEngine(registry, clock)
	bypassEngine, err := newBypassEngine(cfg, clock)
	if err != nil {
		t.Fatalf("newBypassEngine: %v", err)
	}
	pipeline := newPipeline(pipelineDeps{
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:     clock,
		Events:    eventLog,
		Registry:  registry,
		Alerts:    alertEngine,
		Correlate: correlator,
		Bypass:    bypassEngine,
		SiteID:    bypassSite,
	})
	return &bypassHarness{pipeline: pipeline, alerts: alertEngine, clock: clock}
}

func (h *bypassHarness) process(t *testing.T, event domain.Event) {
	t.Helper()
	if err := h.pipeline.ProcessBatch(context.Background(), []domain.Event{event}); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
}

func (h *bypassHarness) list(t *testing.T) []domain.Alert {
	t.Helper()
	alerts, err := h.alerts.List(context.Background(), ports.AlertQuery{Limit: 100})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return alerts
}

func writeAttemptEvent(id, source, target, register string) domain.Event {
	return domain.Event{
		EventID:      domain.EventID(id),
		Kind:         domain.EventWriteAttempt,
		SiteID:       bypassSite,
		AssetID:      "ast_bypass_target",
		ObservedAt:   bypassBaseTime,
		ReceivedAt:   bypassBaseTime,
		Source:       "pcap.test",
		Collection:   "passive_tap",
		Protocol:     "modbus_tcp",
		Confidence:   0.7,
		WriteAttempt: &domain.WriteAttempt{Protocol: "modbus_tcp", Source: source, Target: target, Function: "fc6_write_single_register", Register: register, ValueHint: "redacted", Allowed: false},
	}
}

func flowEvent(id string) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(id),
		Kind:       domain.EventFlow,
		SiteID:     bypassSite,
		ObservedAt: bypassBaseTime,
		ReceivedAt: bypassBaseTime,
		Source:     "pcap.test",
		Collection: "passive_tap",
		Protocol:   "modbus_tcp",
		Confidence: 0.6,
		Flow:       &domain.FlowMeta{SrcIP: "10.99.0.7", DstIP: "10.0.0.5", SrcPort: 50000, DstPort: 502, Protocol: "modbus_tcp"},
	}
}

func enabledBypass(gateSources ...string) *config.BypassConfig {
	return &config.BypassConfig{Enabled: true, GateSourceCIDRs: gateSources}
}

func TestBypassPipelineRaisesOneAlertForForeignSource(t *testing.T) {
	h := newBypassHarness(t, enabledBypass("10.20.30.10/32"))
	h.process(t, writeAttemptEvent("evt_bypass_1", "10.99.0.7", "10.0.0.5", "40001"))
	alerts := h.list(t)
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want exactly one: %+v", len(alerts), alerts)
	}
	alert := alerts[0]
	if alert.RuleID != rules.IDBypassSuspected {
		t.Fatalf("rule = %q", alert.RuleID)
	}
	if alert.RuleVersion != rules.Version {
		t.Fatalf("rule version = %q", alert.RuleVersion)
	}
	if alert.Severity != domain.SeverityCritical {
		t.Fatalf("severity = %q, want critical", alert.Severity)
	}
	if alert.Category != domain.CategoryAccess {
		t.Fatalf("category = %q", alert.Category)
	}
	if alert.Status != domain.AlertOpen {
		t.Fatalf("status = %q", alert.Status)
	}
	if alert.SiteID != bypassSite || len(alert.AssetIDs) != 1 || alert.AssetIDs[0] != "ast_bypass_target" {
		t.Fatalf("scope = %q %v", alert.SiteID, alert.AssetIDs)
	}
	if alert.Title == "" || alert.Summary == "" {
		t.Fatal("title/summary missing")
	}
	if len(alert.Evidence) == 0 {
		t.Fatal("evidence missing")
	}
	if alert.Correlation == nil || len(alert.Correlation.ObservedFacts) == 0 || alert.Correlation.Hypothesis == "" {
		t.Fatalf("correlation = %+v", alert.Correlation)
	}
	if !contains(alert.DedupKey, "10.99.0.7") || !contains(alert.DedupKey, "10.0.0.5") || !contains(alert.DedupKey, "40001") {
		t.Fatalf("dedup key = %q", alert.DedupKey)
	}
	if alert.Confidence <= 0 || alert.Confidence > 1 {
		t.Fatalf("confidence = %v", alert.Confidence)
	}
	if alert.Evidence[0].Kind != "bypass" || alert.Evidence[0].Source != "retaild.passive" {
		t.Fatalf("evidence must come from the gate alert: %+v", alert.Evidence)
	}
	if len(alert.SafetyConstraints) == 0 || len(alert.RecommendedActions) == 0 {
		t.Fatalf("gate safety/action contract lost: %+v", alert)
	}
	if !contains(alert.Summary, "Hypothese") || !contains(alert.Summary, "Empfohlene Prüfung") {
		t.Fatalf("summary must separate fact/hypothesis/check: %q", alert.Summary)
	}
}

func TestBypassPipelineIgnoresGateSources(t *testing.T) {
	h := newBypassHarness(t, enabledBypass("10.20.30.10/32", "fd00::/64"))
	h.process(t, writeAttemptEvent("evt_gate_1", "10.20.30.10", "10.0.0.5", "40001"))
	h.process(t, writeAttemptEvent("evt_gate_2", "fd00::1", "10.0.0.5", "40002"))
	if alerts := h.list(t); len(alerts) != 0 {
		t.Fatalf("gate source produced %d alerts: %+v", len(alerts), alerts)
	}
}

func TestBypassPipelineDisabledProducesNothing(t *testing.T) {
	for _, cfg := range []*config.BypassConfig{nil, {Enabled: false, GateSourceCIDRs: []string{"10.20.30.10"}}} {
		h := newBypassHarness(t, cfg)
		h.process(t, writeAttemptEvent("evt_disabled_1", "10.99.0.7", "10.0.0.5", "40001"))
		if alerts := h.list(t); len(alerts) != 0 {
			t.Fatalf("disabled bypass produced %d alerts", len(alerts))
		}
	}
}

func TestBypassPipelineIgnoresNonWriteEvents(t *testing.T) {
	h := newBypassHarness(t, enabledBypass("10.20.30.10/32"))
	h.process(t, flowEvent("evt_flow_1"))
	if alerts := h.list(t); len(alerts) != 0 {
		t.Fatalf("read/flow event produced %d alerts", len(alerts))
	}
}

func TestBypassPipelineDeduplicatesBySourceTargetRegister(t *testing.T) {
	h := newBypassHarness(t, enabledBypass("10.20.30.10/32"))
	h.process(t, writeAttemptEvent("evt_dedup_1", "10.99.0.7", "10.0.0.5", "40001"))
	h.process(t, writeAttemptEvent("evt_dedup_2", "10.99.0.7", "10.0.0.5", "40001"))
	alerts := h.list(t)
	if len(alerts) != 1 {
		t.Fatalf("duplicate write storm produced %d alerts, want 1", len(alerts))
	}
	h.process(t, writeAttemptEvent("evt_dedup_3", "10.99.0.7", "10.0.0.5", "40002"))
	if alerts := h.list(t); len(alerts) != 2 {
		t.Fatalf("different register produced %d alerts, want 2", len(alerts))
	}
}

func TestBypassSignalMapping(t *testing.T) {
	if _, ok := bypassSignal(flowEvent("evt_flow")); ok {
		t.Fatal("flow event must not produce a bypass signal")
	}
	signal, ok := bypassSignal(writeAttemptEvent("evt_signal", "10.99.0.7", "10.0.0.5", "40001"))
	if !ok {
		t.Fatal("write attempt must produce a bypass signal")
	}
	if signal.SourceIP != "10.99.0.7" || signal.Target != "10.0.0.5" || signal.Address != "40001" {
		t.Fatalf("signal = %+v", signal)
	}
	if signal.SiteID != bypassSite || signal.AssetID != "ast_bypass_target" || signal.At.IsZero() {
		t.Fatalf("signal scope = %+v", signal)
	}
	if signal.Function != "fc6_write_single_register" || signal.Protocol != "modbus_tcp" {
		t.Fatalf("signal operation = %+v", signal)
	}
}

func contains(value, part string) bool {
	for i := 0; i+len(part) <= len(value); i++ {
		if value[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
