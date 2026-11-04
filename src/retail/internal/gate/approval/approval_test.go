package approval

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/store"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

type fixture struct {
	service *Service
	clock   *fakeClock
	repo    *store.Store
}

func targetFor(id domain.TargetID, asset domain.AssetID, register int) config.Target {
	return config.Target{
		TargetID: id, AssetID: asset, Protocol: "modbus_tcp",
		Listen: "127.0.0.1:1502", Upstream: "127.0.0.1:502", UnitID: 1, TimeoutS: 5,
		ReadRegisters: &config.RegisterSpec{FC: 3, Start: 1, Count: 64},
	}
}

func newFixture(t *testing.T, failsafe func() (bool, string)) *fixture {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 11, 3, 20, 0, 0, 0, time.UTC)}
	repo, err := store.Open(store.Options{Dir: t.TempDir(), Clock: clock})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := repo.Close(); cerr != nil {
			t.Errorf("close store: %v", cerr)
		}
	})
	policy := config.Policy{
		PolicyID: "gate-policy-test", Version: 1, UpdatedAt: clock.Now(), UpdatedBy: "master_admin",
		DefaultDeny: true, CriticalAssets: []domain.AssetID{"a-critical"},
		ModbusWriteAllowlist: []config.ModbusWriteAllow{
			{TargetID: "t1", FC: 6, Register: 40001},
			{TargetID: "t2", FC: 6, Register: 40002},
		},
		Token:  config.TokenPolicy{MaxUses: 1, BindSourceIP: true},
		Notify: config.NotifyPolicy{DenyMinSeverity: domain.SeverityHigh},
	}
	targets := map[domain.TargetID]config.Target{
		"t1": targetFor("t1", "a1", 40001),
		"t2": targetFor("t2", "a-critical", 40002),
	}
	service, err := NewService(Options{
		SiteID: "filiale-001", Clock: clock, Repo: repo,
		Policy: func() config.Policy { return policy },
		Target: func(id domain.TargetID) (config.Target, bool) {
			target, ok := targets[id]
			return target, ok
		},
		Timeouts: config.Timeouts{SessionTTLS: 900, TokenTTLS: 300, ApprovalTTLS: 86400, PlanTTLS: 604800, WriteSessionMaxUses: 1},
		Failsafe: failsafe,
	})
	if err != nil {
		t.Fatalf("approval service: %v", err)
	}
	return &fixture{service: service, clock: clock, repo: repo}
}

func user(id string, roles ...domain.GateRole) domain.GateUser {
	return domain.GateUser{UserID: domain.GateUserID(id), Name: id, Kind: domain.GateUserAdmin,
		Roles: roles, Status: domain.GateUserActive, PasswordHash: "x"}
}

func (f *fixture) createPlan(t *testing.T, target domain.TargetID, asset domain.AssetID, register int) domain.WritePlan {
	t.Helper()
	start := f.clock.Now().Add(time.Minute)
	plan, err := f.service.CreatePlan(context.Background(), user("vendor-1", domain.GateRoleVendorWriteRequester), CreatePlanRequest{
		TargetID: target, AssetID: asset, Protocol: "modbus_tcp",
		Operations: []domain.WriteOperation{{
			OperationID: "op-1", Protocol: "modbus_tcp", Function: "fc6",
			Address: itoa(register), CurrentValue: "4.0", NewValue: "3.5", ValueScale: 0.1,
		}},
		Reason: "maintenance", WindowStart: start, WindowEnd: start.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	return plan
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	out := ""
	for value > 0 {
		out = string(rune('0'+value%10)) + out
		value /= 10
	}
	return out
}

func TestCreatePlanPolicyAndWindow(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	plan := f.createPlan(t, "t1", "a1", 40001)
	if plan.State != domain.PlanPending || plan.PlanHash == "" || plan.Critical {
		t.Fatalf("plan = %+v", plan)
	}
	vendor := user("vendor-1", domain.GateRoleVendorWriteRequester)
	_, err := f.service.CreatePlan(ctx, vendor, CreatePlanRequest{
		TargetID: "t1", AssetID: "a1", Protocol: "modbus_tcp",
		Operations: []domain.WriteOperation{{OperationID: "op", Protocol: "modbus_tcp", Function: "fc6", Address: "40009", CurrentValue: "1", NewValue: "2"}},
		Reason:     "not allowlisted", WindowStart: f.clock.Now().Add(time.Minute), WindowEnd: f.clock.Now().Add(2 * time.Minute),
	})
	if !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("allowlist error = %v", err)
	}
	if _, err := f.service.CreatePlan(ctx, user("viewer", domain.GateRoleVendorRead), CreatePlanRequest{Reason: "x"}); !errors.Is(err, ErrRoleRequired) {
		t.Fatalf("role error = %v", err)
	}
}

func TestSingleApprovalSelfApprovalAndTokenReplay(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	plan := f.createPlan(t, "t1", "a1", 40001)
	requesterMaster := user("vendor-1", domain.GateRoleMasterAdmin)
	if _, err := f.service.Approve(ctx, requesterMaster, plan.PlanID, ApproveRequest{MFAUsed: true}); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("self approval error = %v", err)
	}
	approver := user("approver-1", domain.GateRoleApprover)
	if _, err := f.service.Approve(ctx, approver, plan.PlanID, ApproveRequest{PlanHash: "deadbeef", MFAUsed: true}); !errors.Is(err, ErrPlanHashMismatch) {
		t.Fatalf("hash mismatch error = %v", err)
	}
	result, err := f.service.Approve(ctx, approver, plan.PlanID, ApproveRequest{Comment: "ok", PlanHash: plan.PlanHash, MFAUsed: true})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if result.Token == nil || result.Plan.State != domain.PlanApproved {
		t.Fatalf("approval result = %+v", result)
	}
	// Before the window opens no session may be created.
	vendor := user("vendor-1", domain.GateRoleVendorWriteRequester)
	if _, err := f.service.RedeemToken(ctx, vendor, RedeemRequest{PlanID: plan.PlanID, Token: result.Token.Token, SourceIP: "10.0.0.5"}); !errors.Is(err, ErrOutsideWindow) {
		t.Fatalf("outside window error = %v", err)
	}
	f.clock.now = f.clock.now.Add(2 * time.Minute)
	session, err := f.service.RedeemToken(ctx, vendor, RedeemRequest{PlanID: plan.PlanID, Token: result.Token.Token, SourceIP: "10.0.0.5"})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if session.SourceIP != "10.0.0.5" || session.MaxUses != 1 {
		t.Fatalf("session = %+v", session)
	}
	if _, err := f.service.RedeemToken(ctx, vendor, RedeemRequest{PlanID: plan.PlanID, Token: result.Token.Token, SourceIP: "10.0.0.5"}); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("token replay error = %v", err)
	}
	// SessionLookup seam.
	lookup, ok := f.service.Lookup("t1", "10.0.0.5", f.clock.Now())
	if !ok || lookup.SessionID != session.SessionID {
		t.Fatalf("lookup = %+v %v", lookup, ok)
	}
	if !f.service.ConsumeUse(session.SessionID, f.clock.Now()) {
		t.Fatal("first use rejected")
	}
	if f.service.ConsumeUse(session.SessionID, f.clock.Now()) {
		t.Fatal("second use accepted")
	}
	if planNow, ok := f.service.PlanFor(session.SessionID); !ok || planNow.State != domain.PlanExecuted {
		t.Fatalf("plan after use = %+v %v", planNow, ok)
	}
	if _, ok := f.service.Lookup("t1", "10.0.0.5", f.clock.Now()); ok {
		t.Fatal("executed session still usable")
	}
}

func TestFourEyesRequiresMasterAdmin(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	plan := f.createPlan(t, "t2", "a-critical", 40002)
	if !plan.Critical || !plan.NeedsFourEyes() || plan.RequiredApprovals() != 2 {
		t.Fatalf("critical plan = %+v", plan)
	}
	first, err := f.service.Approve(ctx, user("approver-1", domain.GateRoleApprover), plan.PlanID, ApproveRequest{MFAUsed: true})
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if first.Token != nil || first.Plan.State != domain.PlanPending || first.Plan.ApprovalCount() != 1 {
		t.Fatalf("partial approval = %+v", first)
	}
	second, err := f.service.Approve(ctx, user("master-1", domain.GateRoleMasterAdmin), plan.PlanID, ApproveRequest{MFAUsed: true})
	if err != nil {
		t.Fatalf("second approval: %v", err)
	}
	if second.Token == nil || second.Plan.State != domain.PlanApproved {
		t.Fatalf("final approval = %+v", second)
	}
	if _, err := f.service.Approve(ctx, user("approver-2", domain.GateRoleApprover), plan.PlanID, ApproveRequest{MFAUsed: true}); !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("approve after decision = %v", err)
	}
}

func TestDenyEvidenceAndFailsafe(t *testing.T) {
	active := false
	f := newFixture(t, func() (bool, string) { return active, domain.DenyFailsafeClock })
	ctx := context.Background()
	attempt := domain.DeniedWriteAttempt{
		SourceIP: "10.0.0.99", TargetID: "t1", Protocol: "modbus_tcp", Function: "fc6",
		Address: "40001", Reason: domain.DenyOperationNotApproved, Severity: domain.SeverityCritical,
	}
	if err := f.service.Deny(ctx, attempt); err != nil {
		t.Fatalf("deny: %v", err)
	}
	denies, err := f.service.ListDenies(ctx, 10)
	if err != nil || len(denies) != 1 || denies[0].Reason != domain.DenyOperationNotApproved {
		t.Fatalf("denies = %+v %v", denies, err)
	}
	bad := attempt
	bad.Reason = "ad-hoc-reason"
	if err := f.service.Deny(ctx, bad); !errors.Is(err, ErrInvalidDenyReason) {
		t.Fatalf("invalid reason error = %v", err)
	}
	active = true
	if deny, reason := f.service.FailsafeState(); !deny || reason != domain.DenyFailsafeClock {
		t.Fatalf("failsafe state = %v %q", deny, reason)
	}
	if _, ok := f.service.Lookup("t1", "10.0.0.5", f.clock.Now()); ok {
		t.Fatal("lookup allowed during fail-safe")
	}
}

func TestWriteUnknownRevokesSession(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	plan := f.createPlan(t, "t1", "a1", 40001)
	result, err := f.service.Approve(ctx, user("approver-1", domain.GateRoleApprover), plan.PlanID, ApproveRequest{MFAUsed: true})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	f.clock.now = f.clock.now.Add(2 * time.Minute)
	vendor := user("vendor-1", domain.GateRoleVendorWriteRequester)
	session, err := f.service.RedeemToken(ctx, vendor, RedeemRequest{PlanID: plan.PlanID, Token: result.Token.Token, SourceIP: "10.0.0.5"})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	op := domain.WriteOperation{Protocol: "modbus_tcp", Function: "fc6", Address: "40001", NewValue: "3.5", ValueScale: 0.1}
	if err := f.service.ReportWriteUnknown(ctx, session.SessionID, op, WriteUnknownTimeout); err != nil {
		t.Fatalf("report unknown: %v", err)
	}
	if _, ok := f.service.Lookup("t1", "10.0.0.5", f.clock.Now()); ok {
		t.Fatal("session usable after write-unknown")
	}
	records, err := f.service.ListWriteUnknown(ctx, plan.PlanID)
	if err != nil || len(records) != 1 || records[0].Reason != WriteUnknownTimeout {
		t.Fatalf("unknown records = %+v %v", records, err)
	}
	if _, ok := f.service.PlanFor(session.SessionID); !ok {
		t.Fatal("plan should still exist")
	}
	if planNow, _, _ := f.service.GetPlan(ctx, plan.PlanID); planNow.State == domain.PlanExecuted {
		t.Fatal("write-unknown must not mark the plan executed")
	}
}
