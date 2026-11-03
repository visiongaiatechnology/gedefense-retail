package alert_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/alert"
)

func TestOnWriteUnknown(t *testing.T) {
	t.Parallel()
	deps := newTestEngine(t, nil)
	emitted, err := deps.engine.OnWriteUnknown(context.Background(), alert.UnknownWrite{
		At: baseTime, SourceIP: "10.10.40.12", TargetID: "aksm-1",
		Protocol: "modbus_tcp", Function: "fc6", Address: "40001", Outcome: "timeout",
	})
	if err != nil {
		t.Fatalf("OnWriteUnknown: %v", err)
	}
	requireValidAlert(t, emitted)
	if emitted.RuleID != alert.RuleWriteUnknown || emitted.Kind != alert.KindWriteUnknown {
		t.Fatalf("unexpected write-unknown alert: %+v", emitted)
	}
	if emitted.Severity != domain.SeverityCritical {
		t.Fatalf("write-unknown must be critical, got %s", emitted.Severity)
	}
	if !strings.HasPrefix(emitted.DedupKey, "gate.write.unknown|") {
		t.Fatalf("dedup key = %q", emitted.DedupKey)
	}
	if deps.notifier.count() != 1 {
		t.Fatal("write-unknown must notify")
	}
	if !deps.notifier.all()[0].AckRequired {
		t.Fatal("write-unknown notification must require acknowledgement")
	}
	checks := strings.Join(emitted.RecommendedChecks, " ")
	if !strings.Contains(checks, "Read-back") || !strings.Contains(checks, "KEIN automatischer Retry") {
		t.Fatalf("write-unknown must forbid retry and require read-back: %v", emitted.RecommendedChecks)
	}
	// The same unknown write dedupes, it is not a new critical every second.
	deps.clock.Advance(time.Second)
	again, err := deps.engine.OnWriteUnknown(context.Background(), alert.UnknownWrite{
		At: baseTime, SourceIP: "10.10.40.12", TargetID: "aksm-1",
		Protocol: "modbus_tcp", Function: "fc6", Address: "40001", Outcome: "timeout",
	})
	if err != nil {
		t.Fatalf("second OnWriteUnknown: %v", err)
	}
	if again.AlertID != emitted.AlertID || again.Count != 2 {
		t.Fatalf("write-unknown must dedupe: %+v", again)
	}
}

func TestOnGateEventRouting(t *testing.T) {
	t.Parallel()
	attempt := denialFixture(domain.DenyValueMismatch, domain.SeverityCritical)
	attemptPayload, err := json.Marshal(attempt)
	if err != nil {
		t.Fatalf("marshal attempt: %v", err)
	}
	unknownPayload, err := json.Marshal(alert.UnknownWrite{
		At: baseTime, SourceIP: "10.10.40.12", TargetID: "aksm-1",
		Protocol: "modbus_tcp", Function: "fc6", Address: "40001", Outcome: "disconnect",
	})
	if err != nil {
		t.Fatalf("marshal unknown: %v", err)
	}
	cases := []struct {
		name         string
		event        domain.GateEvent
		wantAlert    bool
		wantRule     string
		wantSeverity domain.Severity
		wantErr      bool
	}{
		{"write denied", domain.GateEvent{Kind: domain.GateEventWriteDenied, At: baseTime, Payload: attemptPayload}, true, alert.RuleDeniedWrite, domain.SeverityCritical, false},
		{"write unknown", domain.GateEvent{Kind: alert.KindWriteUnknown, At: baseTime, Payload: unknownPayload}, true, alert.RuleWriteUnknown, domain.SeverityCritical, false},
		{"failsafe store", domain.GateEvent{Kind: domain.GateEventFailsafe, At: baseTime, Payload: json.RawMessage(`{"reason":"failsafe_store","detail":"audit append failed"}`)}, true, alert.RuleFailsafe, domain.SeverityCritical, false},
		{"failsafe clock", domain.GateEvent{Kind: domain.GateEventFailsafe, At: baseTime, Payload: json.RawMessage(`{"reason":"failsafe_clock"}`)}, true, alert.RuleFailsafe, domain.SeverityHigh, false},
		{"bypass suspected", domain.GateEvent{Kind: domain.GateEventBypass, At: baseTime, Payload: json.RawMessage(`{"target_id":"aksm-1","source_ip":"10.10.99.7","protocol":"modbus_tcp","function":"fc6","address":"40001"}`)}, true, alert.RuleBypass, domain.SeverityCritical, false},
		{"plan rejected self approval", domain.GateEvent{Kind: domain.GateEventPlanRejected, At: baseTime, Payload: json.RawMessage(`{"plan_id":"pln_1","reason":"self_approval","actor":"vendor-acme"}`)}, true, alert.RuleApproval, domain.SeverityHigh, false},
		{"plan rejected", domain.GateEvent{Kind: domain.GateEventPlanRejected, At: baseTime, Payload: json.RawMessage(`{"plan_id":"pln_2","reason":"window_expired"}`)}, true, alert.RuleApproval, domain.SeverityMedium, false},
		{"plan expired", domain.GateEvent{Kind: domain.GateEventPlanExpired, At: baseTime, Payload: json.RawMessage(`{"plan_id":"pln_3"}`)}, true, alert.RuleApproval, domain.SeverityMedium, false},
		{"routine plan created", domain.GateEvent{Kind: domain.GateEventPlanCreated, At: baseTime}, false, "", "", false},
		{"routine session open", domain.GateEvent{Kind: domain.GateEventSessionOpen, At: baseTime}, false, "", "", false},
		{"routine write allowed", domain.GateEvent{Kind: domain.GateEventWriteAllowed, At: baseTime}, false, "", "", false},
		{"unsupported kind", domain.GateEvent{Kind: domain.GateEventKind("bogus"), At: baseTime}, false, "", "", true},
		{"denied without payload", domain.GateEvent{Kind: domain.GateEventWriteDenied, At: baseTime}, false, "", "", true},
		{"invalid payload", domain.GateEvent{Kind: domain.GateEventPlanRejected, At: baseTime, Payload: json.RawMessage(`{not-json`)}, false, "", "", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			deps := newTestEngine(t, nil)
			emitted, alerted, err := deps.engine.OnGateEvent(context.Background(), tc.event)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("OnGateEvent: %v", err)
			}
			if alerted != tc.wantAlert {
				t.Fatalf("alerted = %t, want %t", alerted, tc.wantAlert)
			}
			if !tc.wantAlert {
				if emitted.AlertID != "" {
					t.Fatalf("routine event must not emit an alert: %+v", emitted)
				}
				if deps.publisher.count() != 0 || deps.audit.count() != 0 {
					t.Fatal("routine event must not publish or audit an alert")
				}
				return
			}
			requireValidAlert(t, emitted)
			if emitted.RuleID != tc.wantRule {
				t.Fatalf("rule = %q, want %q", emitted.RuleID, tc.wantRule)
			}
			if emitted.Severity != tc.wantSeverity {
				t.Fatalf("severity = %s, want %s", emitted.Severity, tc.wantSeverity)
			}
		})
	}
}

func TestEngineValidationAndSafety(t *testing.T) {
	t.Parallel()
	if _, err := alert.New(alert.Options{}); err == nil {
		t.Fatal("clock is mandatory")
	}
	clock := &fakeClock{t: baseTime}
	cases := []alert.Options{
		{Clock: clock, MinNotify: "bogus"},
		{Clock: clock, DedupWindow: time.Millisecond},
		{Clock: clock, DedupWindow: 48 * time.Hour},
		{Clock: clock, MaxTracked: -1},
		{Clock: clock, MaxTracked: 100000},
	}
	for _, opts := range cases {
		if _, err := alert.New(opts); err == nil {
			t.Fatalf("expected options error for %+v", opts)
		}
	}
	var nilEngine *alert.Engine
	if _, err := nilEngine.Emit(context.Background(), alert.Alert{}); err == nil {
		t.Fatal("nil engine Emit must error")
	}
	deps := newTestEngine(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := deps.engine.OnDeniedWrite(ctx, denialFixture(domain.DenyNoSession, domain.SeverityCritical)); err == nil {
		t.Fatal("canceled context must stop the alert path")
	}
	if _, _, err := deps.engine.OnGateEvent(ctx, domain.GateEvent{Kind: domain.GateEventFailsafe}); err == nil {
		t.Fatal("canceled context must stop event routing")
	}
	if _, err := deps.engine.OnWriteUnknown(context.Background(), alert.UnknownWrite{At: baseTime}); err == nil {
		t.Fatal("incomplete write-unknown must error")
	}
}

func TestEngineConcurrentEmit(t *testing.T) {
	t.Parallel()
	deps := newTestEngine(t, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := make(map[string]bool)
	for worker := 0; worker < 8; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				attempt := denialFixture(domain.DenyNoSession, domain.SeverityCritical)
				attempt.TargetID = domain.TargetID(fmt.Sprintf("target-%d-%d", worker, i))
				emitted, err := deps.engine.OnDeniedWrite(context.Background(), attempt)
				if err != nil {
					t.Errorf("concurrent emit: %v", err)
					return
				}
				mu.Lock()
				ids[emitted.AlertID] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(ids) != 80 {
		t.Fatalf("expected 80 unique alert ids, got %d", len(ids))
	}
	if stats := deps.engine.Stats(); stats.Emitted != 80 || stats.Deduped != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if deps.publisher.count() != 80 || deps.audit.count() != 80 {
		t.Fatalf("expected 80 publications/audits, got %d/%d", deps.publisher.count(), deps.audit.count())
	}
}
