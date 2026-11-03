package bypass_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/alert"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/bypass"
)

var (
	baseTime = time.Date(2026, 11, 4, 2, 14, 0, 0, time.UTC)
	testSite = domain.SiteID("filiale-001")
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

type failingEmitter struct {
	err error
}

func (e failingEmitter) Emit(_ context.Context, _ alert.Alert) (alert.Alert, error) {
	return alert.Alert{}, e.err
}

func newTestBypass(t *testing.T, gateCIDRs ...string) (*bypass.Engine, *alert.Engine) {
	t.Helper()
	clock := &fakeClock{t: baseTime}
	alertEngine, err := alert.New(alert.Options{Clock: clock, SiteID: testSite})
	if err != nil {
		t.Fatalf("alert.New: %v", err)
	}
	if len(gateCIDRs) == 0 {
		gateCIDRs = []string{"10.10.40.0/24"}
	}
	engine, err := bypass.New(bypass.Options{Clock: clock, Emitter: alertEngine, GateCIDRs: gateCIDRs})
	if err != nil {
		t.Fatalf("bypass.New: %v", err)
	}
	return engine, alertEngine
}

func signal(source string) bypass.PassiveWriteSignal {
	return bypass.PassiveWriteSignal{
		SiteID:    testSite,
		At:        baseTime,
		SourceIP:  source,
		Target:    "10.10.20.10",
		TargetID:  "aksm-1",
		AssetID:   "asset-danfoss",
		Protocol:  "modbus_tcp",
		Function:  "fc6",
		Address:   "40001",
		ValueHint: "3.5",
	}
}

func TestBypassSuspectedOutsideGate(t *testing.T) {
	t.Parallel()
	engine, _ := newTestBypass(t)
	emitted, alerted, err := engine.Observe(context.Background(), signal("10.10.99.7"))
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !alerted {
		t.Fatal("expected a bypass suspicion")
	}
	if err := emitted.Validate(); err != nil {
		t.Fatalf("invalid bypass alert: %v", err)
	}
	if emitted.RuleID != alert.RuleBypass || emitted.Kind != domain.GateEventBypass {
		t.Fatalf("unexpected rule/kind: %q/%q", emitted.RuleID, emitted.Kind)
	}
	if emitted.Severity != domain.SeverityCritical {
		t.Fatalf("bypass suspicion must be critical, got %s", emitted.Severity)
	}
	if !strings.HasPrefix(emitted.DedupKey, "gate.bypass|") {
		t.Fatalf("dedup key = %q", emitted.DedupKey)
	}
	facts := strings.Join(emitted.ObservedFacts, " ")
	if !strings.Contains(facts, "außerhalb der konfigurierten Gate-Quellen") {
		t.Fatalf("facts do not document the gate-source check: %v", emitted.ObservedFacts)
	}
	checks := strings.Join(emitted.RecommendedChecks, " ")
	if !strings.Contains(checks, "Segmentierung") {
		t.Fatalf("checks do not ask for segmentation review: %v", emitted.RecommendedChecks)
	}
	if emitted.SiteID != testSite {
		t.Fatalf("site = %q", emitted.SiteID)
	}
}

func TestGateSourceIsNotReportedAsBypass(t *testing.T) {
	t.Parallel()
	engine, _ := newTestBypass(t)
	emitted, alerted, err := engine.Observe(context.Background(), signal("10.10.40.12"))
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if alerted || emitted.AlertID != "" {
		t.Fatalf("gate source must not raise a bypass: %+v", emitted)
	}
}

func TestSingleIPGateSource(t *testing.T) {
	t.Parallel()
	engine, _ := newTestBypass(t, "10.10.40.12")
	if _, alerted, err := engine.Observe(context.Background(), signal("10.10.40.12")); err != nil || alerted {
		t.Fatalf("single-IP gate source must be accepted: alerted=%t err=%v", alerted, err)
	}
	if _, alerted, err := engine.Observe(context.Background(), signal("10.10.40.13")); err != nil || !alerted {
		t.Fatalf("other source must be suspected: alerted=%t err=%v", alerted, err)
	}
}

func TestIPv6GateSource(t *testing.T) {
	t.Parallel()
	engine, _ := newTestBypass(t, "::1/128")
	if _, alerted, err := engine.Observe(context.Background(), signal("::1")); err != nil || alerted {
		t.Fatalf("IPv6 gate source must be accepted: alerted=%t err=%v", alerted, err)
	}
	if _, alerted, err := engine.Observe(context.Background(), signal("2001:db8::1")); err != nil || !alerted {
		t.Fatalf("IPv6 outside source must be suspected: alerted=%t err=%v", alerted, err)
	}
}

func TestUnparsableSourceIsStillSuspicious(t *testing.T) {
	t.Parallel()
	engine, _ := newTestBypass(t)
	emitted, alerted, err := engine.Observe(context.Background(), signal("not-an-ip"))
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !alerted {
		t.Fatal("unattributable source must raise a bypass suspicion")
	}
	if emitted.Confidence > 0.7 {
		t.Fatalf("unparsable source must lower confidence, got %v", emitted.Confidence)
	}
	if !strings.Contains(strings.Join(emitted.ObservedFacts, " "), "nicht parsebar") {
		t.Fatalf("facts must document the unparsable source: %v", emitted.ObservedFacts)
	}
}

func TestEmitterFailureIsPropagated(t *testing.T) {
	t.Parallel()
	engine, err := bypass.New(bypass.Options{
		Clock:     &fakeClock{t: baseTime},
		Emitter:   failingEmitter{err: errors.New("audit down")},
		GateCIDRs: []string{"10.10.40.0/24"},
	})
	if err != nil {
		t.Fatalf("bypass.New: %v", err)
	}
	emitted, alerted, err := engine.Observe(context.Background(), signal("10.10.99.7"))
	if err == nil {
		t.Fatal("emitter failure must be reported (fail-closed handling)")
	}
	if alerted || emitted.AlertID != "" {
		t.Fatal("no alert may be reported when the emitter failed")
	}
}

func TestBypassConfigurationValidation(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: baseTime}
	alertEngine, err := alert.New(alert.Options{Clock: clock})
	if err != nil {
		t.Fatalf("alert.New: %v", err)
	}
	cases := []struct {
		name string
		opts bypass.Options
	}{
		{"missing clock", bypass.Options{Emitter: alertEngine, GateCIDRs: []string{"10.10.40.0/24"}}},
		{"missing emitter", bypass.Options{Clock: clock, GateCIDRs: []string{"10.10.40.0/24"}}},
		{"no gate sources", bypass.Options{Clock: clock, Emitter: alertEngine}},
		{"invalid cidr", bypass.Options{Clock: clock, Emitter: alertEngine, GateCIDRs: []string{"999.999.0.0/24"}}},
		{"empty source", bypass.Options{Clock: clock, Emitter: alertEngine, GateCIDRs: []string{""}}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := bypass.New(tc.opts); err == nil {
				t.Fatalf("expected configuration error for %s", tc.name)
			}
		})
	}
}

func TestBypassSignalValidation(t *testing.T) {
	t.Parallel()
	engine, _ := newTestBypass(t)
	missingAt := signal("10.10.99.7")
	missingAt.At = time.Time{}
	if _, _, err := engine.Observe(context.Background(), missingAt); err == nil {
		t.Fatal("missing signal time must error")
	}
	missingSource := signal("")
	if _, _, err := engine.Observe(context.Background(), missingSource); err == nil {
		t.Fatal("missing source must error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := engine.Observe(ctx, signal("10.10.99.7")); err == nil {
		t.Fatal("canceled context must stop observation")
	}
	var nilEngine *bypass.Engine
	if _, _, err := nilEngine.Observe(context.Background(), signal("10.10.99.7")); err == nil {
		t.Fatal("nil engine must error")
	}
}

func TestBypassDocumentsAllowedFlagAndLimit(t *testing.T) {
	t.Parallel()
	engine, _ := newTestBypass(t)
	suspicious := signal("10.10.99.7")
	suspicious.Allowed = true
	emitted, alerted, err := engine.Observe(context.Background(), suspicious)
	if err != nil || !alerted {
		t.Fatalf("Observe: alerted=%t err=%v", alerted, err)
	}
	facts := strings.Join(emitted.ObservedFacts, " ")
	if !strings.Contains(facts, "als erlaubt") {
		t.Fatalf("allowed flag must be qualified in the facts: %v", emitted.ObservedFacts)
	}
	if !strings.Contains(emitted.Hypothesis, "beweist weder") {
		t.Fatalf("hypothesis must document the passive limit: %q", emitted.Hypothesis)
	}
	if !strings.Contains(emitted.Summary, "Abgeleitet") {
		t.Fatalf("summary must separate observed and derived statements: %q", emitted.Summary)
	}
}

func TestBypassDedupKeyIsStable(t *testing.T) {
	t.Parallel()
	engine, _ := newTestBypass(t)
	first, alerted, err := engine.Observe(context.Background(), signal("10.10.99.7"))
	if err != nil || !alerted {
		t.Fatalf("first Observe: alerted=%t err=%v", alerted, err)
	}
	second, alerted, err := engine.Observe(context.Background(), signal("10.10.99.7"))
	if err != nil || !alerted {
		t.Fatalf("second Observe: alerted=%t err=%v", alerted, err)
	}
	if first.DedupKey != second.DedupKey {
		t.Fatalf("bypass dedup key not stable: %q vs %q", first.DedupKey, second.DedupKey)
	}
	if second.AlertID == "" {
		t.Fatal("second occurrence must produce a valid alert")
	}
}

func TestBypassFutureTimestampIsClamped(t *testing.T) {
	t.Parallel()
	engine, _ := newTestBypass(t)
	future := signal("10.10.99.7")
	future.At = baseTime.Add(time.Hour)
	emitted, alerted, err := engine.Observe(context.Background(), future)
	if err != nil || !alerted {
		t.Fatalf("Observe: alerted=%t err=%v", alerted, err)
	}
	if emitted.At.After(baseTime) {
		t.Fatalf("future observation time must be clamped to the gate clock: %v", emitted.At)
	}
}
