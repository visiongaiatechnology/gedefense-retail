package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/approval"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/identity"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/store"
)

type apiClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *apiClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *apiClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type apiFixture struct {
	handler  http.Handler
	gate     *approval.Service
	identity *identity.Service
	clock    *apiClock
	users    map[string]domain.GateUser
}

func (f *apiFixture) do(t *testing.T, method, target, body, token string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:55555"
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)
	return recorder
}

func newAPIFixture(t *testing.T, withEscalation bool) *apiFixture {
	t.Helper()
	clock := &apiClock{now: time.Date(2026, 11, 3, 20, 0, 0, 0, time.UTC)}
	repo, err := store.Open(store.Options{Dir: t.TempDir(), Clock: clock})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	mk := func(id string, kind domain.GateUserKind, roles []domain.GateRole, totp bool) domain.GateUser {
		hash, herr := identity.HashPasswordWithIterations("a-strong-password", identity.MinIterations)
		if herr != nil {
			t.Fatalf("hash: %v", herr)
		}
		user := domain.GateUser{UserID: domain.GateUserID(id), Name: id, Kind: kind, Roles: roles,
			PasswordHash: hash, Status: domain.GateUserActive}
		if totp {
			secret, serr := identity.NewTOTPSecret()
			if serr != nil {
				t.Fatalf("secret: %v", serr)
			}
			user.TOTPSecret = secret
			user.TOTPEnabled = true
		}
		return user
	}
	vendor := mk("vendor-1", domain.GateUserVendor, []domain.GateRole{domain.GateRoleVendorWriteRequester}, false)
	approver := mk("approver-1", domain.GateUserOperator, []domain.GateRole{domain.GateRoleApprover}, true)
	viewer := mk("viewer-1", domain.GateUserVendor, []domain.GateRole{domain.GateRoleVendorRead}, false)
	identityService, err := identity.New(identity.Options{Users: []domain.GateUser{vendor, approver, viewer}, Clock: clock})
	users := map[string]domain.GateUser{"vendor-1": vendor, "approver-1": approver, "viewer-1": viewer}
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	policy := config.Policy{
		PolicyID: "gate-policy-test", Version: 1, UpdatedAt: clock.Now(), UpdatedBy: "master_admin",
		DefaultDeny:          true,
		ModbusWriteAllowlist: []config.ModbusWriteAllow{{TargetID: "t1", FC: 6, Register: 40001}},
		Token:                config.TokenPolicy{MaxUses: 1, BindSourceIP: true},
		Notify:               config.NotifyPolicy{DenyMinSeverity: domain.SeverityHigh},
	}
	target := config.Target{
		TargetID: "t1", AssetID: "a1", Protocol: "modbus_tcp", Listen: "127.0.0.1:1502",
		Upstream: "127.0.0.1:502", UnitID: 1, TimeoutS: 5,
		ReadRegisters: &config.RegisterSpec{FC: 3, Start: 1, Count: 64},
	}
	gate, err := approval.NewService(approval.Options{
		SiteID: "filiale-001", Clock: clock, Repo: repo,
		Policy: func() config.Policy { return policy },
		Target: func(id domain.TargetID) (config.Target, bool) {
			if id == "t1" {
				return target, true
			}
			return config.Target{}, false
		},
		Timeouts: config.Timeouts{SessionTTLS: 900, TokenTTLS: 300, ApprovalTTLS: 86400, PlanTTLS: 604800, WriteSessionMaxUses: 1},
	})
	if err != nil {
		t.Fatalf("approval: %v", err)
	}
	deps := Deps{
		Info:   Info{Product: "GeDefense Retail Access Gate", Version: "0.2.0-alpha"},
		Config: config.Config{PolicyFile: "gate-policy.json"}, Identity: identityService, Gate: gate,
		Targets: func() []config.TargetStatus {
			return []config.TargetStatus{{TargetID: "t1", Protocol: "modbus_tcp", State: "listening"}}
		},
		Failsafe:       func() (bool, string) { return false, "" },
		LoadPolicy:     func() (config.Policy, error) { return policy, nil },
		ActivatePolicy: func(config.Policy) error { return nil },
		Policy:         func() config.Policy { return policy },
	}
	if withEscalation {
		acked := false
		deps.Escalations = &EscalationHooks{
			List: func() []EscalationView {
				return []EscalationView{{NotificationID: "ntf_1", AlertID: "alr_1", Severity: domain.SeverityCritical, Level: 1, Delivered: true, Acked: acked}}
			},
			Ack: func(_ context.Context, id, _ string, _ string) (EscalationView, error) {
				if id != "ntf_1" {
					return EscalationView{}, approval.ErrNotFound
				}
				acked = true
				return EscalationView{NotificationID: id, Acked: true, AckedBy: "approver-1"}, nil
			},
		}
	}
	server, err := New(deps)
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	return &apiFixture{handler: server.Handler(), gate: gate, identity: identityService, clock: clock, users: users}
}

func (f *apiFixture) login(t *testing.T, userID string, totpSecret string) string {
	t.Helper()
	body := `{"user_id":"` + userID + `","password":"a-strong-password"}`
	if totpSecret != "" {
		code, err := identity.TOTPCodeAt(totpSecret, f.clock.Now())
		if err != nil {
			panic("totp: " + err.Error())
		}
		body = `{"user_id":"` + userID + `","password":"a-strong-password","totp":"` + code + `"}`
	}
	recorder := f.do(t, http.MethodPost, "/api/v1/gate/auth/login", body, "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("login %s = %d %s", userID, recorder.Code, recorder.Body.String())
	}
	var response struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response.SessionToken == "" {
		t.Fatalf("login body: %v", err)
	}
	return response.SessionToken
}

func (f *apiFixture) totpNow(userID string) string {
	user := f.users[userID]
	code, err := identity.TOTPCodeAt(user.TOTPSecret, f.clock.Now())
	if err != nil {
		panic("totp: " + err.Error())
	}
	return code
}

func TestAPIAuthAndRBAC(t *testing.T) {
	f := newAPIFixture(t, false)
	if recorder := f.do(t, http.MethodGet, "/api/v1/gate/plans", "", "", nil); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated plans = %d", recorder.Code)
	}
	if recorder := f.do(t, http.MethodGet, "/api/v1/gate/health", "", "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("public health = %d", recorder.Code)
	}
	viewerToken := f.login(t, "viewer-1", "")
	if recorder := f.do(t, http.MethodGet, "/api/v1/gate/status", "", viewerToken, nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("viewer status = %d, want 403", recorder.Code)
	}
	approverToken := f.login(t, "approver-1", f.users["approver-1"].TOTPSecret)
	if recorder := f.do(t, http.MethodGet, "/api/v1/gate/status", "", approverToken, nil); recorder.Code != http.StatusOK {
		t.Fatalf("approver status = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestAPIPlanApprovalSessionFlow(t *testing.T) {
	f := newAPIFixture(t, false)
	vendorToken := f.login(t, "vendor-1", "")
	f.clock.advance(time.Minute)
	windowStart := f.clock.Now().Add(time.Minute).Format(time.RFC3339)
	windowEnd := f.clock.Now().Add(2 * time.Hour).Format(time.RFC3339)
	body := `{"target_id":"t1","asset_id":"a1","protocol":"modbus_tcp","operations":[{"operation_id":"op-1","protocol":"modbus_tcp","function":"fc6","address":"40001","current_value":"4.0","new_value":"3.5","value_scale":0.1}],"reason":"maintenance","window_start":"` + windowStart + `","window_end":"` + windowEnd + `"}`
	headers := map[string]string{"Idempotency-Key": "idem-plan-0001"}
	created := f.do(t, http.MethodPost, "/api/v1/gate/plans", body, vendorToken, headers)
	if created.Code != http.StatusCreated {
		t.Fatalf("create plan = %d %s", created.Code, created.Body.String())
	}
	var planResponse struct {
		Plan domain.WritePlan `json:"plan"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &planResponse); err != nil {
		t.Fatalf("plan body: %v", err)
	}
	replay := f.do(t, http.MethodPost, "/api/v1/gate/plans", body, vendorToken, headers)
	if replay.Code != http.StatusCreated || !bytes.Equal(replay.Body.Bytes(), created.Body.Bytes()) {
		t.Fatalf("idempotent replay = %d %s", replay.Code, replay.Body.String())
	}
	conflict := f.do(t, http.MethodPost, "/api/v1/gate/plans", strings.Replace(body, `"maintenance"`, `"other"`, 1), vendorToken, headers)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("idempotency conflict = %d", conflict.Code)
	}
	approverToken := f.login(t, "approver-1", f.users["approver-1"].TOTPSecret)
	if recorder := f.do(t, http.MethodPost, "/api/v1/gate/plans/"+string(planResponse.Plan.PlanID)+"/approve", `{"comment":"x"}`, approverToken, nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("approve without MFA = %d, want 403 mfa_required", recorder.Code)
	}
	f.clock.advance(30 * time.Second)
	approved := f.do(t, http.MethodPost, "/api/v1/gate/plans/"+string(planResponse.Plan.PlanID)+"/approve", `{"comment":"ok"}`, approverToken,
		map[string]string{"X-Gate-MFA": f.totpNow("approver-1")})
	if approved.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", approved.Code, approved.Body.String())
	}
	var approveResponse struct {
		Token *struct {
			Token string `json:"token"`
		} `json:"token"`
	}
	if err := json.Unmarshal(approved.Body.Bytes(), &approveResponse); err != nil || approveResponse.Token == nil {
		t.Fatalf("approve body: %v", err)
	}
	f.clock.advance(2 * time.Minute)
	sessionBody := `{"plan_id":"` + string(planResponse.Plan.PlanID) + `","token":"` + approveResponse.Token.Token + `"}`
	session := f.do(t, http.MethodPost, "/api/v1/gate/sessions", sessionBody, vendorToken, map[string]string{"Idempotency-Key": "idem-sess-0001"})
	if session.Code != http.StatusCreated {
		t.Fatalf("session = %d %s", session.Code, session.Body.String())
	}
	reuse := f.do(t, http.MethodPost, "/api/v1/gate/sessions", sessionBody, vendorToken, nil)
	if reuse.Code != http.StatusConflict {
		t.Fatalf("token replay = %d, want 409 token_used", reuse.Code)
	}
	if recorder := f.do(t, http.MethodPost, "/api/v1/gate/auth/login", `{"user_id":"vendor-1","password":"wrong"}`, "", nil); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("bad login = %d", recorder.Code)
	}
	if recorder := f.do(t, http.MethodPost, "/api/v1/gate/plans", `{"unknown":true}`, vendorToken, nil); recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", recorder.Code)
	}
}

func TestAPILoginRateLimit(t *testing.T) {
	f := newAPIFixture(t, false)
	limited := 0
	for i := 0; i < loginBurst+2; i++ {
		recorder := f.do(t, http.MethodPost, "/api/v1/gate/auth/login", `{"user_id":"vendor-1","password":"wrong"}`, "", nil)
		if recorder.Code == http.StatusTooManyRequests {
			limited++
			if recorder.Header().Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
		}
	}
	if limited == 0 {
		t.Fatal("login rate limit did not trigger")
	}
}

func TestAPIEscalations(t *testing.T) {
	f := newAPIFixture(t, true)
	approverToken := f.login(t, "approver-1", f.users["approver-1"].TOTPSecret)
	list := f.do(t, http.MethodGet, "/api/v1/gate/escalations", "", approverToken, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("escalations = %d %s", list.Code, list.Body.String())
	}
	ack := f.do(t, http.MethodPost, "/api/v1/gate/escalations/ntf_1/ack", `{"note":"on call informed"}`, approverToken, nil)
	if ack.Code != http.StatusOK || !strings.Contains(ack.Body.String(), `"acked":true`) {
		t.Fatalf("escalation ack = %d %s", ack.Code, ack.Body.String())
	}
	missing := f.do(t, http.MethodPost, "/api/v1/gate/escalations/ntf_404/ack", `{}`, approverToken, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown escalation = %d", missing.Code)
	}
	entries, err := f.gate.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	found := false
	for _, entry := range entries {
		if entry.Action == approval.ActionEscalationAck {
			found = true
		}
	}
	if !found {
		t.Fatal("escalation ack not audited")
	}
	if recorder := f.do(t, http.MethodGet, "/api/v1/gate/does-not-exist", "", approverToken, nil); recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d", recorder.Code)
	}
}

var _ io.Reader
