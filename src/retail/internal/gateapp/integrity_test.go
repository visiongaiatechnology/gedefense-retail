package gateapp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/api"
	gateconfig "github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
)

type integrityClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *integrityClock) Now() time.Time { return c.at }
func (c *integrityClock) advance(d time.Duration) {
	c.mu.Lock()
	c.at = c.at.Add(d)
	c.mu.Unlock()
}

type fakeConn struct {
	mu        sync.Mutex
	value     uint16
	readQueue []uint16
	readErr   error
	writeErr  error
	writes    int
	reads     int
}

func (c *fakeConn) ReadHoldingRegister(context.Context, uint16) (uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if c.readErr != nil {
		return 0, c.readErr
	}
	if len(c.readQueue) > 0 {
		value := c.readQueue[0]
		c.readQueue = c.readQueue[1:]
		c.value = value
		return value, nil
	}
	return c.value, nil
}

func (c *fakeConn) WriteSingleRegister(_ context.Context, _ uint16, value uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	c.writes++
	c.value = value
	return nil
}

func (c *fakeConn) Close() error { return nil }

func integrityConfig(confirm int) gateconfig.IntegrityConfig {
	return gateconfig.IntegrityConfig{
		Enabled:       true,
		PollIntervalS: 10,
		ConfirmReads:  confirm,
		StaleAfterS:   60,
		References: []gateconfig.IntegrityReference{{
			TargetID: "aksm-1", FC: 3, Register: 40001, Value: "4.0", Scale: 0.1, Recovery: true,
		}},
	}
}

func integrityDepsFor(t *testing.T, cfg gateconfig.IntegrityConfig, conn *fakeConn, clock *integrityClock) (integrityDeps, *[]string, *int, *bool) {
	t.Helper()
	var mu sync.Mutex
	audits := &[]string{}
	publishes := 0
	activeBlocked := false
	deps := integrityDeps{
		cfg:     cfg,
		targets: map[domain.TargetID]gateconfig.Target{"aksm-1": {TargetID: "aksm-1", Protocol: "modbus_tcp", UnitID: 1, ReadRegisters: &gateconfig.RegisterSpec{FC: 3, Start: 0, Count: 64}}},
		clock:   clock,
		open:    func(gateconfig.Target, uint8) (deviceConn, error) { return conn, nil },
		audit: func(_ context.Context, action, objectID, reason string) error {
			mu.Lock()
			*audits = append(*audits, action+"|"+objectID+"|"+reason)
			mu.Unlock()
			return nil
		},
		active: func(context.Context, domain.TargetID) (bool, error) { return activeBlocked, nil },
		publish: func(api.IntegrityStatus) {
			mu.Lock()
			publishes++
			mu.Unlock()
		},
		log: testLogger(t),
	}
	return deps, audits, &publishes, &activeBlocked
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func countActions(audits []string, action string) int {
	count := 0
	for _, audit := range audits {
		if len(audit) >= len(action) && audit[:len(action)] == action {
			count++
		}
	}
	return count
}

func TestIntegrityWorkerMatchNoAudit(t *testing.T) {
	clock := &integrityClock{at: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	conn := &fakeConn{value: 40}
	deps, audits, _, _ := integrityDepsFor(t, integrityConfig(2), conn, clock)
	worker := newIntegrityWorker(deps)
	worker.runOnce(context.Background())
	worker.runOnce(context.Background())
	if len(*audits) != 0 {
		t.Fatalf("unexpected audits: %v", *audits)
	}
	if status := worker.Status(); status.References[0].State != "ok" {
		t.Fatalf("state = %s", status.References[0].State)
	}
}

func TestIntegrityWorkerConfirmThenAuditWithoutRecovery(t *testing.T) {
	clock := &integrityClock{at: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	conn := &fakeConn{value: 30}
	cfg := integrityConfig(2)
	cfg.Recovery.Enabled = false
	deps, audits, _, _ := integrityDepsFor(t, cfg, conn, clock)
	worker := newIntegrityWorker(deps)
	worker.runOnce(context.Background())
	if countActions(*audits, ActionIntegrityMismatch) != 0 {
		t.Fatal("mismatch audited before confirm_reads")
	}
	worker.runOnce(context.Background())
	if countActions(*audits, ActionIntegrityMismatch) != 1 {
		t.Fatalf("mismatch audit = %v", *audits)
	}
	if conn.writes != 0 {
		t.Fatal("recovery wrote although disabled")
	}
}

func TestIntegrityWorkerRecoveryAppliedAndRateLimit(t *testing.T) {
	clock := &integrityClock{at: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	conn := &fakeConn{value: 30}
	cfg := integrityConfig(2)
	cfg.Recovery = gateconfig.RecoveryConfig{Enabled: true, MaxActionsPerHour: 1, MaxActionsPerDay: 10, CooldownS: 600}
	deps, audits, _, _ := integrityDepsFor(t, cfg, conn, clock)
	worker := newIntegrityWorker(deps)
	worker.runOnce(context.Background())
	worker.runOnce(context.Background())
	if countActions(*audits, ActionRecoveryApplied) != 1 || conn.writes != 1 {
		t.Fatalf("recovery not applied: audits=%v writes=%d", *audits, conn.writes)
	}
	if status := worker.Status(); status.References[0].State != "ok" || status.Recovery.ActionsLastHour != 1 {
		t.Fatalf("status = %+v", status)
	}
	// Drift again immediately: cooldown/rate limit must block a second write.
	conn.mu.Lock()
	conn.value = 30
	conn.mu.Unlock()
	clock.advance(20 * time.Second)
	worker.runOnce(context.Background())
	worker.runOnce(context.Background())
	if conn.writes != 1 {
		t.Fatalf("cooldown/rate limit ignored: writes=%d", conn.writes)
	}
}

func TestIntegrityWorkerRecoveryUnknownNoRetry(t *testing.T) {
	clock := &integrityClock{at: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	conn := &fakeConn{value: 30, writeErr: errors.New("device timeout")}
	cfg := integrityConfig(2)
	cfg.Recovery = gateconfig.RecoveryConfig{Enabled: true, MaxActionsPerHour: 3, MaxActionsPerDay: 10, CooldownS: 600}
	deps, audits, _, _ := integrityDepsFor(t, cfg, conn, clock)
	worker := newIntegrityWorker(deps)
	worker.runOnce(context.Background())
	worker.runOnce(context.Background())
	if countActions(*audits, ActionRecoveryUnknown) != 1 {
		t.Fatalf("unknown audit = %v", *audits)
	}
	// A second confirmed mismatch episode must not retry within the same episode.
	worker.runOnce(context.Background())
	if countActions(*audits, ActionRecoveryUnknown) != 1 {
		t.Fatalf("recovery retried: %v", *audits)
	}
}

func TestIntegrityWorkerActiveSessionBlocksRecovery(t *testing.T) {
	clock := &integrityClock{at: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	conn := &fakeConn{value: 30}
	cfg := integrityConfig(1)
	cfg.Recovery = gateconfig.RecoveryConfig{Enabled: true, MaxActionsPerHour: 3, MaxActionsPerDay: 10, CooldownS: 600}
	required := true
	cfg.Recovery.RequireNoActiveWindow = &required
	deps, audits, _, active := integrityDepsFor(t, cfg, conn, clock)
	*active = true
	worker := newIntegrityWorker(deps)
	worker.runOnce(context.Background())
	if conn.writes != 0 || countActions(*audits, ActionRecoveryApplied) != 0 {
		t.Fatalf("recovery wrote during active session: writes=%d audits=%v", conn.writes, *audits)
	}
}

func TestIntegrityWorkerUnreadableAndRestored(t *testing.T) {
	clock := &integrityClock{at: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	conn := &fakeConn{value: 30}
	cfg := integrityConfig(1)
	deps, audits, _, _ := integrityDepsFor(t, cfg, conn, clock)
	worker := newIntegrityWorker(deps)
	worker.runOnce(context.Background())
	if status := worker.Status(); status.References[0].State != "mismatch" {
		t.Fatalf("state = %s", status.References[0].State)
	}
	conn.mu.Lock()
	conn.value = 40
	conn.mu.Unlock()
	worker.runOnce(context.Background())
	if countActions(*audits, ActionIntegrityRestored) != 1 {
		t.Fatalf("restored audit = %v", *audits)
	}
}

func TestExpectedRawBounds(t *testing.T) {
	cases := []struct {
		ref  gateconfig.IntegrityReference
		want uint16
		ok   bool
	}{
		{gateconfig.IntegrityReference{Value: "4.0", Scale: 0.1}, 40, true},
		{gateconfig.IntegrityReference{Value: "3.5", Scale: 0.1}, 35, true},
		{gateconfig.IntegrityReference{Value: "65535"}, 65535, true},
		{gateconfig.IntegrityReference{Value: "70000"}, 0, false},
		{gateconfig.IntegrityReference{Value: "abc"}, 0, false},
		{gateconfig.IntegrityReference{Value: "-1"}, 0, false},
	}
	for _, tc := range cases {
		got, ok := expectedRaw(tc.ref)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("expectedRaw(%+v) = %d,%v", tc.ref, got, ok)
		}
	}
	if got := formatDisplay(40, 0.1); got != "4" {
		t.Fatalf("formatDisplay = %q", got)
	}
}

func TestIntegrityFailSafeBlocksAllDeviceIO(t *testing.T) {
	clock := &integrityClock{at: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	conn := &fakeConn{value: 40}
	deps, audits, _, _ := integrityDepsFor(t, integrityConfig(1), conn, clock)
	deps.allowWrite = func() bool { return false }
	worker := newIntegrityWorker(deps)
	worker.runOnce(context.Background())
	if conn.reads != 0 || len(*audits) != 0 {
		t.Fatalf("fail-safe violation: reads=%d audits=%v", conn.reads, *audits)
	}
	if status := worker.Status(); status.References[0].State != "stale" {
		t.Fatalf("state = %s", status.References[0].State)
	}
}

func TestIntegrityIntentAuditFailureBlocksWrite(t *testing.T) {
	clock := &integrityClock{at: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	conn := &fakeConn{value: 30}
	cfg := integrityConfig(2)
	cfg.Recovery = gateconfig.RecoveryConfig{Enabled: true, MaxActionsPerHour: 3, MaxActionsPerDay: 10, CooldownS: 600}
	deps, _, _, _ := integrityDepsFor(t, cfg, conn, clock)
	deps.audit = func(_ context.Context, action, _, _ string) error {
		if action == ActionRecoveryIntent {
			return errors.New("audit store full")
		}
		return nil
	}
	worker := newIntegrityWorker(deps)
	worker.runOnce(context.Background())
	worker.runOnce(context.Background())
	if conn.writes != 0 {
		t.Fatalf("write happened despite intent-audit failure: %d", conn.writes)
	}
	if status := worker.Status(); status.References[0].Recovery.LastResult != "blocked" {
		t.Fatalf("last_result = %q", status.References[0].Recovery.LastResult)
	}
}

func TestIntegrityAppliedAuditFailureBecomesUnknownNoRetry(t *testing.T) {
	clock := &integrityClock{at: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	conn := &fakeConn{value: 30}
	cfg := integrityConfig(1)
	cfg.Recovery = gateconfig.RecoveryConfig{Enabled: true, MaxActionsPerHour: 3, MaxActionsPerDay: 10, CooldownS: 600}
	deps, _, _, _ := integrityDepsFor(t, cfg, conn, clock)
	deps.audit = func(_ context.Context, action, _, _ string) error {
		if action == ActionRecoveryApplied {
			return errors.New("audit store full")
		}
		return nil
	}
	worker := newIntegrityWorker(deps)
	worker.runOnce(context.Background())
	if conn.writes != 1 {
		t.Fatalf("recovery did not write: %d", conn.writes)
	}
	if status := worker.Status(); status.References[0].State == "ok" || status.References[0].Recovery.LastResult != "unknown" {
		t.Fatalf("audit failure must stay unknown: %+v", status.References[0])
	}
	// No retry after the unclear/unaudited outcome.
	clock.advance(20 * time.Second)
	worker.runOnce(context.Background())
	if conn.writes != 1 {
		t.Fatalf("recovery retried after applied-audit failure: %d", conn.writes)
	}
}

func TestIntegrityRecoveryRereadRestoredSkipsWrite(t *testing.T) {
	clock := &integrityClock{at: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	// Poll reads see 30 twice, the immediate pre-write re-read already sees 40.
	conn := &fakeConn{value: 30, readQueue: []uint16{30, 30, 40}}
	cfg := integrityConfig(2)
	cfg.Recovery = gateconfig.RecoveryConfig{Enabled: true, MaxActionsPerHour: 3, MaxActionsPerDay: 10, CooldownS: 600}
	deps, audits, _, _ := integrityDepsFor(t, cfg, conn, clock)
	worker := newIntegrityWorker(deps)
	worker.runOnce(context.Background())
	worker.runOnce(context.Background())
	if conn.writes != 0 {
		t.Fatalf("re-read equal must skip the write: %d", conn.writes)
	}
	if countActions(*audits, ActionRecoveryIntent) != 1 {
		t.Fatalf("intent audit = %v", *audits)
	}
	if status := worker.Status(); status.References[0].State != "ok" || status.References[0].Recovery.LastResult != "restored" {
		t.Fatalf("status = %+v", status.References[0])
	}
}

func TestSessionBlocksRecoveryIncludingConsumed(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	consumed := domain.WriteSession{
		SessionID: "ses_1", TargetID: "cold-1", SourceIP: "127.0.0.1",
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), MaxUses: 1, Uses: 1,
	}
	if !sessionBlocksRecovery([]domain.WriteSession{consumed}, "cold-1", now) {
		t.Fatal("consumed/in-flight session must block recovery")
	}
	expired := consumed
	expired.ExpiresAt = now.Add(-time.Second)
	if sessionBlocksRecovery([]domain.WriteSession{expired}, "cold-1", now) {
		t.Fatal("expired session must not block recovery")
	}
	revoked := consumed
	revoked.Revoked = true
	if sessionBlocksRecovery([]domain.WriteSession{revoked}, "cold-1", now) {
		t.Fatal("revoked session must not block recovery")
	}
	if sessionBlocksRecovery([]domain.WriteSession{consumed}, "other-target", now) {
		t.Fatal("session of another target must not block recovery")
	}
}
