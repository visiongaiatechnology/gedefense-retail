package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
	"github.com/visiongaiatechnology/gedefense/retail/internal/store"
)

// setupTestHarness builds an API harness in first-run setup mode.
func setupTestHarness(t *testing.T) *apiHarness {
	t.Helper()
	return newAPIHarness(t, apiTestOptions{
		setup:    true,
		security: &WhitelistConfig{SetupMode: true},
	})
}

// postSetup sends a setup step with the current session token.
func (h *apiHarness) postSetup(t *testing.T, token, path, body string) int {
	t.Helper()
	recorder := h.doFromHeaders(t, "POST", path, body, "", "127.0.0.1:5555",
		map[string]string{"X-Setup-Session": token})
	return recorder.Code
}

// stepSetup runs the language/site/whitelist steps needed before admin.
func (h *apiHarness) stepSetup(t *testing.T, token string) {
	t.Helper()
	for _, step := range []struct{ path, body string }{
		{"/api/v1/setup/language", `{"language":"de"}`},
		{"/api/v1/setup/site", `{"site_id":"filiale-001","name":"Markt Nord","zones":[]}`},
		{"/api/v1/setup/whitelist", `{"cidrs":["10.20.30.0/24"]}`},
	} {
		if code := h.postSetup(t, token, step.path, step.body); code != 200 {
			t.Fatalf("%s = %d", step.path, code)
		}
	}
}

// TestW01_HostAllowlist: DNS rebinding via a foreign Host must be rejected.
func TestW01_HostAllowlist(t *testing.T) {
	h := setupTestHarness(t)
	request := newSetupRequest(t, "GET", "/api/v1/setup/state", "127.0.0.1:5555")
	request.Host = "evil.example:8080"
	recorder := h.serve(request)
	if recorder.Code != 403 || !strings.Contains(recorder.Body.String(), "forbidden") {
		t.Fatalf("foreign host = %d %s", recorder.Code, recorder.Body.String())
	}
	// Allowed loopback Host reaches the wizard.
	if code := h.doFrom(t, "GET", "/api/v1/setup/state", "", "", "127.0.0.1:5555").Code; code != 200 {
		t.Fatalf("loopback host = %d", code)
	}
}

// TestW02_OriginAndFetchSite: cross-origin and DNS-rebinding combinations are
// rejected; same-origin loopback passes.
func TestW02_OriginAndFetchSite(t *testing.T) {
	h := setupTestHarness(t)
	cases := []struct {
		name   string
		host   string
		origin string
		fetch  string
		want   int
	}{
		{"evil origin", "127.0.0.1:8080", "http://evil.example", "", 403},
		{"rebinding", "127.0.0.1:8080", "http://evil.example", "same-origin", 403},
		{"cross-site fetch", "127.0.0.1:8080", "", "cross-site", 403},
		{"same origin", "127.0.0.1:8080", "http://127.0.0.1:8080", "same-origin", 200},
		{"localhost origin", "localhost:8080", "http://localhost:8080", "none", 200},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			request := newSetupRequest(t, "GET", "/api/v1/setup/state", "127.0.0.1:5555")
			request.Host = tc.host
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			if tc.fetch != "" {
				request.Header.Set("Sec-Fetch-Site", tc.fetch)
			}
			recorder := h.serve(request)
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", recorder.Code, tc.want, recorder.Body.String())
			}
		})
	}
}

// TestW03_SessionRequired: every setup POST needs the session header.
func TestW03_SessionRequired(t *testing.T) {
	h := setupTestHarness(t)
	for _, path := range []string{
		"/api/v1/setup/language", "/api/v1/setup/site", "/api/v1/setup/whitelist",
		"/api/v1/setup/admin", "/api/v1/setup/collectors", "/api/v1/setup/complete",
	} {
		recorder := h.doFrom(t, "POST", path, "{}", "", "127.0.0.1:5555")
		if recorder.Code != 403 || !strings.Contains(recorder.Body.String(), "setup_session_invalid") {
			t.Fatalf("%s without session = %d %s", path, recorder.Code, recorder.Body.String())
		}
	}
}

// TestW04_SessionTTL ensures the configured session TTL is enforced.
func TestW04_SessionTTL(t *testing.T) {
	h := setupTestHarness(t)
	token := h.setupSession(t)
	h.clock.now = h.clock.now.Add(h.server.setup.SessionTTL() + time.Minute)
	if code := h.postSetup(t, token, "/api/v1/setup/language", `{"language":"de"}`); code != 403 {
		t.Fatalf("expired session = %d, want 403", code)
	}
	// A new state call issues a fresh session after expiry.
	fresh := h.setupSession(t)
	if code := h.postSetup(t, fresh, "/api/v1/setup/language", `{"language":"de"}`); code != 200 {
		t.Fatalf("renewed session = %d", code)
	}
}

// TestW05_SessionRotation: a new state call invalidates the previous token.
func TestW05_SessionRotation(t *testing.T) {
	h := setupTestHarness(t)
	first := h.setupSession(t)
	second := h.setupSession(t)
	if first == second {
		t.Fatal("session token did not rotate")
	}
	if code := h.postSetup(t, first, "/api/v1/setup/language", `{"language":"de"}`); code != 403 {
		t.Fatalf("old session accepted = %d", code)
	}
	if code := h.postSetup(t, second, "/api/v1/setup/language", `{"language":"de"}`); code != 200 {
		t.Fatalf("new session rejected = %d", code)
	}
}

// TestW06_AdminTokenIdempotent: repeated admin creation keeps the first token.
func TestW06_AdminTokenIdempotent(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "retail.json")
	if err := os.WriteFile(configPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	h := newAPIHarness(t, apiTestOptions{setup: true, security: &WhitelistConfig{SetupMode: true}, configPath: configPath})
	token := h.setupSession(t)
	h.stepSetup(t, token)
	first := h.doFromHeaders(t, "POST", "/api/v1/setup/admin", `{"user_id":"admin","name":"Admin"}`, "",
		"127.0.0.1:5555", map[string]string{"X-Setup-Session": token})
	if first.Code != 200 || !strings.Contains(first.Body.String(), `"token"`) {
		t.Fatalf("first admin = %d %s", first.Code, first.Body.String())
	}
	second := h.doFromHeaders(t, "POST", "/api/v1/setup/admin", `{"user_id":"admin","name":"Admin"}`, "",
		"127.0.0.1:5555", map[string]string{"X-Setup-Session": token})
	if second.Code != 409 || !strings.Contains(second.Body.String(), "admin_exists") {
		t.Fatalf("second admin = %d %s", second.Code, second.Body.String())
	}
	var firstBody struct {
		TokenSHA256 string `json:"token_sha256"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstBody); err != nil || firstBody.TokenSHA256 == "" {
		t.Fatalf("first admin hash missing: %v", err)
	}
	complete := h.doFromHeaders(t, "POST", "/api/v1/setup/complete", "{}", "", "127.0.0.1:5555",
		map[string]string{"X-Setup-Session": token})
	if complete.Code != 200 {
		t.Fatalf("complete = %d %s", complete.Code, complete.Body.String())
	}
	written := readFile(t, configPath)
	if !strings.Contains(written, firstBody.TokenSHA256) {
		t.Fatal("persisted hash changed after duplicate admin call")
	}
}

// TestW07_UntrustedXFFIgnored: XFF from a non-trusted peer cannot bypass.
func TestW07_UntrustedXFFIgnored(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{security: &WhitelistConfig{
		RequireWhitelist: true, CIDRs: []string{"10.0.0.0/24"},
		TrustProxyHeaders: true, TrustedProxyCIDRs: []string{"192.0.2.0/24"},
	}})
	request := newSetupRequest(t, "GET", "/api/v1/health", "10.0.1.5:1234")
	request.Header.Set("X-Forwarded-For", "10.0.0.7") // allowed hop must be ignored
	if recorder := h.serve(request); recorder.Code != 403 {
		t.Fatalf("untrusted XFF bypassed the whitelist: %d", recorder.Code)
	}
}

// TestW08_DenyResponseHygiene checks headers, request_id and JSON of a deny.
func TestW08_DenyResponseHygiene(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{security: &WhitelistConfig{
		RequireWhitelist: true, CIDRs: []string{"10.0.0.0/24"},
	}})
	recorder := h.doFrom(t, "GET", "/api/v1/health", "", "", "10.0.9.9:1234")
	if recorder.Code != 403 {
		t.Fatalf("status = %d", recorder.Code)
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Error("missing no-store")
	}
	if !strings.HasPrefix(recorder.Header().Get("Content-Type"), "application/json") {
		t.Errorf("content type = %q", recorder.Header().Get("Content-Type"))
	}
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("deny body is not JSON: %v", err)
	}
	if envelope.Error.Code != "ip_not_allowed" || envelope.Error.RequestID == "" {
		t.Fatalf("deny envelope = %+v", envelope.Error)
	}
}

// TestW09_DenyMapsBounded: 10k distinct sources must not grow the maps past the
// hard limit (F-SW-05).
func TestW09_DenyMapsBounded(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{security: &WhitelistConfig{
		RequireWhitelist: true, CIDRs: []string{"10.0.0.0/24"},
	}})
	for i := 0; i < 10000; i++ {
		remote := "192.0." + strconv.Itoa(i/256%256) + "." + strconv.Itoa(i%256) + ":1234"
		recorder := h.doFrom(t, "GET", "/api/v1/health", "", "", remote)
		if recorder.Code != 403 {
			t.Fatalf("deny %d = %d", i, recorder.Code)
		}
	}
	h.server.filter.mu.Lock()
	warnLen := len(h.server.filter.lastWarn)
	denyLen := len(h.server.filter.basicDeny)
	h.server.filter.mu.Unlock()
	if warnLen > maxFilterEntries || denyLen > maxFilterEntries {
		t.Fatalf("filter maps unbounded: lastWarn=%d basicDeny=%d", warnLen, denyLen)
	}
}

// TestW10_SetupRateLimit: the setup API has its own 30/min/IP bucket.
func TestW10_SetupRateLimit(t *testing.T) {
	h := setupTestHarness(t)
	last := 0
	for i := 0; i < 40; i++ {
		last = h.doFrom(t, "GET", "/api/v1/setup/state", "", "", "127.0.0.1:5555").Code
		if last == 429 {
			break
		}
	}
	if last != 429 {
		t.Fatalf("setup rate limit not enforced (last status %d)", last)
	}
}

// failingAudit simulates an audit store failure for the setup object type.
type failingAudit struct {
	inner ports.AuditStore
}

func (f failingAudit) Append(ctx context.Context, entry domain.AuditEntry) (domain.AuditEntry, error) {
	if entry.Action == "setup.complete" {
		return domain.AuditEntry{}, errors.New("audit store down")
	}
	return f.inner.Append(ctx, entry)
}

func (f failingAudit) List(ctx context.Context, limit int) ([]domain.AuditEntry, error) {
	return f.inner.List(ctx, limit)
}
func (f failingAudit) Verify(ctx context.Context) (bool, uint64, error) { return f.inner.Verify(ctx) }
func (f failingAudit) Close() error                                     { return nil }

// TestW11_AuditBeforeConfigWrite: a failing audit blocks the completion and
// leaves the config untouched (audit before effect, F-SW-07).
func TestW11_AuditBeforeConfigWrite(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "retail.json")
	if err := os.WriteFile(configPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	h := newAPIHarness(t, apiTestOptions{
		setup: true, security: &WhitelistConfig{SetupMode: true}, configPath: configPath,
		auditWrapper: func(log *store.AuditLog) ports.AuditStore { return failingAudit{inner: log} },
	})
	token := h.setupSession(t)
	h.stepSetup(t, token)
	admin := h.doFromHeaders(t, "POST", "/api/v1/setup/admin", `{"user_id":"admin","name":"Admin"}`, "",
		"127.0.0.1:5555", map[string]string{"X-Setup-Session": token})
	if admin.Code != 200 {
		t.Fatalf("admin step = %d %s", admin.Code, admin.Body.String())
	}
	complete := h.doFromHeaders(t, "POST", "/api/v1/setup/complete", "{}", "", "127.0.0.1:5555",
		map[string]string{"X-Setup-Session": token})
	if complete.Code != 500 {
		t.Fatalf("audit failure complete = %d, want 500", complete.Code)
	}
	written := readFile(t, configPath)
	if strings.Contains(written, `"completed": true`) {
		t.Fatal("config was written although the audit failed")
	}
}

// TestW12_BindHint: completion reports the actual loopback setup URL.
func TestW12_BindHint(t *testing.T) {
	h := setupTestHarness(t)
	token := h.setupSession(t)
	h.stepSetup(t, token)
	admin := h.doFromHeaders(t, "POST", "/api/v1/setup/admin", `{"user_id":"admin","name":"Admin"}`, "",
		"127.0.0.1:5555", map[string]string{"X-Setup-Session": token})
	if admin.Code != 200 {
		t.Fatalf("admin = %d", admin.Code)
	}
	complete := h.doFromHeaders(t, "POST", "/api/v1/setup/complete", "{}", "", "127.0.0.1:5555",
		map[string]string{"X-Setup-Session": token})
	if complete.Code != 200 || !strings.Contains(complete.Body.String(), "http://127.0.0.1:8080/setup") {
		t.Fatalf("bind_hint = %d %s", complete.Code, complete.Body.String())
	}
}

// newSetupRequest builds a setup request with loopback peer and Host.
func newSetupRequest(t *testing.T, method, target, remote string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, target, nil)
	request.RemoteAddr = remote
	request.Host = "127.0.0.1:8080"
	return request
}

// readFile reads a test file or fails.
func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}
