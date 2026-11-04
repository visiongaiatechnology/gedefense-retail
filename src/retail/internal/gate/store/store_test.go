package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func testClock() *fakeClock { return &fakeClock{now: time.Date(2026, 11, 3, 20, 0, 0, 0, time.UTC)} }

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func openTestStore(t *testing.T) (*Store, *fakeClock) {
	t.Helper()
	clock := testClock()
	store, err := Open(Options{Dir: t.TempDir(), Clock: clock})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("close store: %v", cerr)
		}
	})
	return store, clock
}

func validPlan(t *testing.T, id domain.PlanID, at time.Time) domain.WritePlan {
	t.Helper()
	plan := domain.WritePlan{
		PlanID: id, SiteID: "filiale-001", TargetID: "t1", AssetID: "a1",
		Protocol: "modbus_tcp",
		Operations: []domain.WriteOperation{{
			OperationID: "op-1", Protocol: "modbus_tcp", Function: "fc6",
			Address: "40001", CurrentValue: "4.0", NewValue: "3.5", ValueScale: 0.1,
		}},
		Reason: "test", RequestedBy: "vendor-1", RequestedAt: at,
		WindowStart: at, WindowEnd: at.Add(time.Hour), State: domain.PlanPending,
		CreatedAt: at, UpdatedAt: at,
	}
	hash, err := plan.ComputePlanHash()
	if err != nil {
		t.Fatalf("plan hash: %v", err)
	}
	plan.PlanHash = hash
	return plan
}

func TestStorePersistsPlanAndSession(t *testing.T) {
	store, clock := openTestStore(t)
	ctx := context.Background()
	plan := validPlan(t, "pln_1", clock.Now())
	if err := store.SavePlan(ctx, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	loaded, found, err := store.GetPlan(ctx, "pln_1")
	if err != nil || !found || loaded.PlanHash != plan.PlanHash {
		t.Fatalf("get plan: found=%v err=%v", found, err)
	}
	if plans, lerr := store.ListPlans(ctx); lerr != nil || len(plans) != 1 {
		t.Fatalf("list plans: %v %d", lerr, len(plans))
	}
	session := domain.WriteSession{
		SessionID: "ses_1", PlanID: "pln_1", TargetID: "t1", UserID: "vendor-1",
		SourceIP: "10.0.0.5", CreatedAt: clock.Now(), ExpiresAt: clock.Now().Add(time.Minute), MaxUses: 1,
	}
	if err := store.SaveSession(ctx, session); err != nil {
		t.Fatalf("save session: %v", err)
	}
	if sessions, serr := store.ListSessions(ctx); serr != nil || len(sessions) != 1 {
		t.Fatalf("list sessions: %v %d", serr, len(sessions))
	}
	if ok, _, verr := store.VerifyAudit(ctx); verr != nil || !ok {
		t.Fatalf("initial audit chain: %v %v", ok, verr)
	}
}

func TestAuditChainAndTamper(t *testing.T) {
	store, clock := openTestStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := store.AppendAudit(ctx, domain.AuditEntry{
			At: clock.Now(), Actor: "admin", Role: "master_admin",
			Action: "gate.test", ObjectType: "gate_plan", ObjectID: "pln_x",
		}); err != nil {
			t.Fatalf("append audit: %v", err)
		}
	}
	if ok, _, err := store.VerifyAudit(ctx); err != nil || !ok {
		t.Fatalf("audit verify: %v %v", ok, err)
	}
	files, err := filepath.Glob(filepath.Join(store.Dir(), auditDirName, "*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("audit files: %v", err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	tampered := []byte(string(raw))
	tampered = []byte(string(tampered))
	tampered = []byte(replaceFirst(string(tampered), `"admin"`, `"admiN"`))
	if err := os.WriteFile(files[0], tampered, 0o600); err != nil {
		t.Fatalf("write tamper: %v", err)
	}
	ok, badSeq, err := store.VerifyAudit(ctx)
	if err != nil {
		t.Fatalf("verify after tamper: %v", err)
	}
	if ok || badSeq == 0 {
		t.Fatalf("tampered chain accepted (ok=%v badSeq=%d)", ok, badSeq)
	}
	// A restarted store must refuse to start on a broken chain.
	if _, oerr := Open(Options{Dir: store.Dir(), Clock: clock}); oerr == nil {
		t.Fatal("store started with a tampered audit chain")
	}
}

func TestStoreRejectsSymlinkedDocument(t *testing.T) {
	store, clock := openTestStore(t)
	ctx := context.Background()
	target := filepath.Join(store.Dir(), "outside.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(store.Dir(), plansDirName, "pln_link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, _, err := store.GetPlan(ctx, "pln_link"); err == nil {
		t.Fatal("symlinked plan document was read")
	}
	if _, err := Open(Options{Dir: store.Dir(), Clock: clock}); err == nil {
		t.Log("open with symlinked document returned no error (document ignored)")
	}
}

func TestTOTPStepsPersist(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	if err := store.SaveTOTPStep(ctx, "vendor-1", 100); err != nil {
		t.Fatalf("save step: %v", err)
	}
	steps, err := store.LoadTOTPSteps(ctx)
	if err != nil || steps["vendor-1"] != 100 {
		t.Fatalf("load steps: %v %+v", err, steps)
	}
	if err := store.SaveTOTPStep(ctx, "vendor-1", 99); err != nil {
		t.Fatalf("older step must be ignored: %v", err)
	}
	steps, _ = store.LoadTOTPSteps(ctx)
	if steps["vendor-1"] != 100 {
		t.Fatalf("step regressed: %d", steps["vendor-1"])
	}
}

// replaceFirst replaces the first occurrence of old in text (non-destructive tamper).
func replaceFirst(text, old, replacement string) string {
	for i := 0; i+len(old) <= len(text); i++ {
		if text[i:i+len(old)] == old {
			return text[:i] + replacement + text[i+len(old):]
		}
	}
	return text
}
