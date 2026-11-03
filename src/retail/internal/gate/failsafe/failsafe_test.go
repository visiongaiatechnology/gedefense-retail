package failsafe_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/failsafe"
)

var baseTime = time.Date(2026, 11, 4, 2, 14, 0, 0, time.UTC)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func newEngine(t *testing.T, mutate func(*failsafe.Options)) (*failsafe.Engine, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: baseTime}
	opts := failsafe.Options{Clock: clock}
	if mutate != nil {
		mutate(&opts)
	}
	engine, err := failsafe.NewEngine(opts)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine, clock
}

func requireColdChainSafe(t *testing.T, result failsafe.Result) {
	t.Helper()
	if result.ColdChainAffected {
		t.Fatalf("hard invariant violated: cold chain affected by %v", result.Active)
	}
}

func TestMatrixInvariants(t *testing.T) {
	t.Parallel()
	matrix := failsafe.Decisions()
	if len(matrix) != 10 {
		t.Fatalf("expected 10 fail-safe conditions, got %d", len(matrix))
	}
	denyReasons := map[string]bool{
		domain.DenyFailsafeStore: true,
		domain.DenyFailsafeClock: true,
		domain.DenyPolicyMissing: true,
	}
	seen := make(map[failsafe.Condition]bool, len(matrix))
	for _, decision := range matrix {
		if decision.Condition == "" {
			t.Fatal("matrix row without condition")
		}
		if seen[decision.Condition] {
			t.Fatalf("duplicate condition %q", decision.Condition)
		}
		seen[decision.Condition] = true
		if decision.ColdChainAffected {
			t.Fatalf("condition %q must never affect the cold chain", decision.Condition)
		}
		if !decision.Severity.Valid() {
			t.Fatalf("condition %q has invalid severity %q", decision.Condition, decision.Severity)
		}
		if decision.Note == "" {
			t.Fatalf("condition %q has no operator note", decision.Condition)
		}
		if !decision.Alert {
			t.Fatalf("condition %q must raise an alert", decision.Condition)
		}
		switch decision.Health {
		case "ok", "degraded", "blocked", "stopped":
		default:
			t.Fatalf("condition %q has invalid health %q", decision.Condition, decision.Health)
		}
		if decision.DenyReason != "" && !denyReasons[decision.DenyReason] {
			t.Fatalf("condition %q uses a non-domain deny reason %q", decision.Condition, decision.DenyReason)
		}
		if !decision.AllowWrite && decision.DenyReason == "" && decision.Condition != failsafe.CondGateCoreDown && decision.Condition != failsafe.CondNetworkSplit {
			t.Fatalf("denying condition %q has no deny reason", decision.Condition)
		}
	}
	// The matrix copy must be defensive.
	matrix[0].Note = "mutated"
	if failsafe.Decisions()[0].Note == "mutated" {
		t.Fatal("Decisions() must return a copy")
	}
	for condition := range seen {
		if _, ok := failsafe.DecisionFor(condition); !ok {
			t.Fatalf("DecisionFor(%q) not found", condition)
		}
	}
	if _, ok := failsafe.DecisionFor(failsafe.Condition("bogus")); ok {
		t.Fatal("unknown condition must not resolve")
	}
}

func TestHealthyDependenciesAllowWrites(t *testing.T) {
	t.Parallel()
	engine, _ := newEngine(t, nil)
	result := engine.Evaluate(failsafe.HealthyDependencies())
	if !result.AllowWrite || result.CloseListeners || !result.APIUp {
		t.Fatalf("healthy gate must allow writes and stay reachable: %+v", result)
	}
	if result.FailsafeActive || result.Health != "ok" || len(result.Notices) != 0 || len(result.Active) != 0 {
		t.Fatalf("unexpected healthy result: %+v", result)
	}
	requireColdChainSafe(t, result)
	if err := engine.CheckStartup(failsafe.HealthyDependencies()); err != nil {
		t.Fatalf("healthy startup: %v", err)
	}
}

func TestAuditFailureDeniesWrites(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		audit failsafe.AuditState
	}{
		{"append failing", failsafe.AuditAppendFailing},
		{"store full", failsafe.AuditFull},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			engine, _ := newEngine(t, nil)
			deps := failsafe.HealthyDependencies()
			deps.Audit = tc.audit
			result := engine.Evaluate(deps)
			if result.AllowWrite {
				t.Fatal("audit failure must deny writes (fail-closed)")
			}
			if result.DenyReason != domain.DenyFailsafeStore {
				t.Fatalf("deny reason = %q, want %q", result.DenyReason, domain.DenyFailsafeStore)
			}
			if result.Health != "degraded" || !result.APIUp || result.CloseListeners {
				t.Fatalf("unexpected fail-safe state: %+v", result)
			}
			if len(result.Notices) != 1 || result.Notices[0].Severity != domain.SeverityCritical {
				t.Fatalf("expected one critical notice: %+v", result.Notices)
			}
			requireColdChainSafe(t, result)
		})
	}
}

func TestAuthorizationOutageDenies(t *testing.T) {
	t.Parallel()
	t.Run("policy unreadable closes data plane", func(t *testing.T) {
		t.Parallel()
		engine, _ := newEngine(t, nil)
		deps := failsafe.HealthyDependencies()
		deps.PolicyReadable = false
		result := engine.Evaluate(deps)
		if result.AllowWrite || !result.CloseListeners || !result.APIUp {
			t.Fatalf("policy outage must close the data plane but keep the API up: %+v", result)
		}
		if result.DenyReason != domain.DenyPolicyMissing || result.Health != "blocked" {
			t.Fatalf("unexpected result: %+v", result)
		}
		if err := engine.CheckStartup(deps); !errors.Is(err, failsafe.ErrPolicyUnreadable) {
			t.Fatalf("startup must refuse without policy, got %v", err)
		}
		requireColdChainSafe(t, result)
	})
	t.Run("plan store corrupt", func(t *testing.T) {
		t.Parallel()
		engine, _ := newEngine(t, nil)
		deps := failsafe.HealthyDependencies()
		deps.PlanStoreReadable = false
		result := engine.Evaluate(deps)
		if result.AllowWrite || result.CloseListeners || !result.APIUp {
			t.Fatalf("plan store corruption must deny writes without closing the API: %+v", result)
		}
		if result.DenyReason != domain.DenyFailsafeStore {
			t.Fatalf("deny reason = %q", result.DenyReason)
		}
		if err := engine.CheckStartup(deps); !errors.Is(err, failsafe.ErrStoreCorrupt) {
			t.Fatalf("startup must refuse with corrupt plan store, got %v", err)
		}
	})
	t.Run("session store corrupt", func(t *testing.T) {
		t.Parallel()
		engine, _ := newEngine(t, nil)
		deps := failsafe.HealthyDependencies()
		deps.SessionStoreReadable = false
		result := engine.Evaluate(deps)
		if result.AllowWrite {
			t.Fatal("session store corruption must deny writes")
		}
		if err := engine.CheckStartup(deps); !errors.Is(err, failsafe.ErrStoreCorrupt) {
			t.Fatalf("startup must refuse with corrupt session store, got %v", err)
		}
	})
}

func TestClockJumpDeniesUntilStable(t *testing.T) {
	t.Parallel()
	engine, clock := newEngine(t, func(opts *failsafe.Options) {
		opts.MaxForwardJump = 2 * time.Minute
		opts.MaxBackwardJump = 5 * time.Second
		opts.StableObservations = 2
	})
	if result := engine.Evaluate(failsafe.HealthyDependencies()); !result.AllowWrite {
		t.Fatalf("initial healthy evaluation must allow writes: %+v", result)
	}
	clock.Advance(2 * time.Hour) // injected clock jump
	jumped := engine.Evaluate(failsafe.HealthyDependencies())
	if jumped.AllowWrite || jumped.Clock != failsafe.ClockUnstable {
		t.Fatalf("clock jump must deny writes: %+v", jumped)
	}
	if jumped.DenyReason != domain.DenyFailsafeClock || !jumped.FailsafeActive {
		t.Fatalf("unexpected deny reason/state: %+v", jumped)
	}
	if len(jumped.Notices) == 0 || jumped.Notices[0].Severity != domain.SeverityHigh {
		t.Fatalf("expected a high clock notice: %+v", jumped.Notices)
	}
	clock.Advance(10 * time.Second)
	if still := engine.Evaluate(failsafe.HealthyDependencies()); still.AllowWrite {
		t.Fatal("writes must stay denied until the clock is stable")
	}
	clock.Advance(10 * time.Second)
	if recovered := engine.Evaluate(failsafe.HealthyDependencies()); !recovered.AllowWrite || recovered.Clock != failsafe.ClockStable {
		t.Fatalf("clock must recover after stable observations: %+v", recovered)
	}
	// Backward jump is also detected.
	clock.Set(clock.Now().Add(-time.Minute))
	back := engine.Evaluate(failsafe.HealthyDependencies())
	if back.AllowWrite {
		t.Fatalf("backward clock jump must deny writes: %+v", back)
	}
	requireColdChainSafe(t, back)
}

func TestGateCoreDownClosesListeners(t *testing.T) {
	t.Parallel()
	engine, _ := newEngine(t, nil)
	deps := failsafe.HealthyDependencies()
	deps.CoreAlive = false
	result := engine.Evaluate(deps)
	if result.AllowWrite || !result.CloseListeners || result.APIUp {
		t.Fatalf("dead core must close the management path: %+v", result)
	}
	if result.Health != "stopped" {
		t.Fatalf("health = %q, want stopped", result.Health)
	}
	requireColdChainSafe(t, result)
}

func TestMonitoringDownDoesNotAffectGate(t *testing.T) {
	t.Parallel()
	engine, _ := newEngine(t, nil)
	deps := failsafe.HealthyDependencies()
	deps.MonitoringAlive = false
	result := engine.Evaluate(deps)
	if !result.AllowWrite || result.CloseListeners || !result.APIUp {
		t.Fatalf("monitoring outage must not block the gate: %+v", result)
	}
	if result.Health != "degraded" || result.DenyReason != "" {
		t.Fatalf("unexpected monitoring state: %+v", result)
	}
	if len(result.Notices) != 1 || result.Notices[0].Severity != domain.SeverityMedium {
		t.Fatalf("expected a best-effort monitoring notice: %+v", result.Notices)
	}
	requireColdChainSafe(t, result)
}

func TestUpstreamAndNetworkSplit(t *testing.T) {
	t.Parallel()
	engine, _ := newEngine(t, nil)
	upstream := failsafe.HealthyDependencies()
	upstream.UpstreamAlive = false
	result := engine.Evaluate(upstream)
	if !result.AllowWrite || result.Health != "degraded" {
		t.Fatalf("upstream outage must not change gate authorization: %+v", result)
	}
	split := failsafe.HealthyDependencies()
	split.NetworkSplit = true
	split.UpstreamAlive = false
	splitResult := engine.Evaluate(split)
	if splitResult.AllowWrite || splitResult.Health != "degraded" {
		t.Fatalf("network split must deny the management path: %+v", splitResult)
	}
	if len(splitResult.Active) != 1 || splitResult.Active[0] != failsafe.CondNetworkSplit {
		t.Fatalf("network split must be the single active condition: %v", splitResult.Active)
	}
	requireColdChainSafe(t, result)
	requireColdChainSafe(t, splitResult)
}

func TestColdChainNeverAffected(t *testing.T) {
	t.Parallel()
	engine, clock := newEngine(t, nil)
	variants := []failsafe.Dependencies{failsafe.HealthyDependencies()}
	for _, decision := range failsafe.Decisions() {
		deps := failsafe.HealthyDependencies()
		switch decision.Condition {
		case failsafe.CondAuditStoreFailure:
			deps.Audit = failsafe.AuditAppendFailing
		case failsafe.CondAuditStoreFull:
			deps.Audit = failsafe.AuditFull
		case failsafe.CondClockJump:
			clock.Advance(time.Hour)
		case failsafe.CondPolicyUnreadable:
			deps.PolicyReadable = false
		case failsafe.CondPlanStoreCorrupt:
			deps.PlanStoreReadable = false
		case failsafe.CondSessionStoreCorrupt:
			deps.SessionStoreReadable = false
		case failsafe.CondGateCoreDown:
			deps.CoreAlive = false
		case failsafe.CondMonitoringDown:
			deps.MonitoringAlive = false
		case failsafe.CondUpstreamDown:
			deps.UpstreamAlive = false
		case failsafe.CondNetworkSplit:
			deps.NetworkSplit = true
		}
		variants = append(variants, deps)
	}
	variants = append(variants, failsafe.Dependencies{}) // zero value is fail-closed
	for _, deps := range variants {
		result := engine.Evaluate(deps)
		requireColdChainSafe(t, result)
	}
}

func TestCheckStartupRules(t *testing.T) {
	t.Parallel()
	engine, _ := newEngine(t, nil)
	if err := engine.CheckStartup(failsafe.HealthyDependencies()); err != nil {
		t.Fatalf("healthy startup: %v", err)
	}
	policy := failsafe.HealthyDependencies()
	policy.PolicyReadable = false
	if err := engine.CheckStartup(policy); !errors.Is(err, failsafe.ErrPolicyUnreadable) {
		t.Fatalf("expected ErrPolicyUnreadable, got %v", err)
	}
	audit := failsafe.HealthyDependencies()
	audit.Audit = failsafe.AuditFull
	if err := engine.CheckStartup(audit); !errors.Is(err, failsafe.ErrAuditUnavailable) {
		t.Fatalf("expected ErrAuditUnavailable, got %v", err)
	}
	// Runtime-only dependencies must not block startup.
	runtime := failsafe.HealthyDependencies()
	runtime.MonitoringAlive = false
	runtime.UpstreamAlive = false
	if err := engine.CheckStartup(runtime); err != nil {
		t.Fatalf("runtime dependencies must not block startup: %v", err)
	}
}

func TestEngineValidation(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: baseTime}
	cases := []struct {
		name string
		opts failsafe.Options
	}{
		{"missing clock", failsafe.Options{}},
		{"negative forward jump", failsafe.Options{Clock: clock, MaxForwardJump: -time.Second}},
		{"too large forward jump", failsafe.Options{Clock: clock, MaxForwardJump: 2 * time.Hour}},
		{"negative backward jump", failsafe.Options{Clock: clock, MaxBackwardJump: -time.Second}},
		{"too large backward jump", failsafe.Options{Clock: clock, MaxBackwardJump: 2 * time.Minute}},
		{"too many stable observations", failsafe.Options{Clock: clock, StableObservations: 11}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := failsafe.NewEngine(tc.opts); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestNilEngineAndZeroClock(t *testing.T) {
	t.Parallel()
	var nilEngine *failsafe.Engine
	result := nilEngine.Evaluate(failsafe.HealthyDependencies())
	if result.AllowWrite || !result.CloseListeners || result.APIUp || result.Health != "stopped" {
		t.Fatalf("nil engine must report stopped/fail-closed: %+v", result)
	}
	requireColdChainSafe(t, result)
	if nilEngine.ClockState() != failsafe.ClockUnstable {
		t.Fatal("nil engine clock must be unstable")
	}
	if nilEngine.ObserveClock(baseTime) != failsafe.ClockUnstable {
		t.Fatal("nil engine observation must be unstable")
	}

	zeroClock := &fakeClock{} // zero time
	engine, err := failsafe.NewEngine(failsafe.Options{Clock: zeroClock})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	zeroResult := engine.Evaluate(failsafe.HealthyDependencies())
	if zeroResult.AllowWrite || zeroResult.Clock != failsafe.ClockUnstable {
		t.Fatalf("zero clock must deny writes: %+v", zeroResult)
	}
	requireColdChainSafe(t, zeroResult)
}

func TestEvaluateDeterministicAndConcurrent(t *testing.T) {
	t.Parallel()
	engine, _ := newEngine(t, nil)
	deps := failsafe.HealthyDependencies()
	deps.Audit = failsafe.AuditAppendFailing
	deps.MonitoringAlive = false
	first := engine.Evaluate(deps)
	second := engine.Evaluate(deps)
	if len(first.Active) != len(second.Active) || first.DenyReason != second.DenyReason || first.Health != second.Health {
		t.Fatalf("non-deterministic evaluation: %+v vs %+v", first, second)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				_ = engine.Evaluate(deps)
				_ = engine.ObserveClock(baseTime.Add(time.Duration(j) * time.Second))
				_ = engine.ClockState()
			}
		}()
	}
	wg.Wait()
}
