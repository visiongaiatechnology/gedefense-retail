package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// doFrom executes a request with a forged peer address and the loopback Host
// expected by the setup API (F-SW-01).
func (h *apiHarness) doFrom(t *testing.T, method, target, body, token, remote string) *httptest.ResponseRecorder {
	t.Helper()
	return h.doFromHeaders(t, method, target, body, token, remote, nil)
}

func (h *apiHarness) doFromHeaders(t *testing.T, method, target, body, token, remote string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.RemoteAddr = remote
	request.Host = "127.0.0.1:8080"
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}

// setupSession fetches a fresh setup session token from GET /setup/state.
func (h *apiHarness) setupSession(t *testing.T) string {
	t.Helper()
	recorder := h.doFrom(t, http.MethodGet, "/api/v1/setup/state", "", "", "127.0.0.1:5555")
	if recorder.Code != http.StatusOK {
		t.Fatalf("setup state = %d %s", recorder.Code, recorder.Body.String())
	}
	var state struct {
		SetupSession string `json:"setup_session"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode setup state: %v", err)
	}
	if state.SetupSession == "" {
		t.Fatal("setup state carries no setup_session")
	}
	return state.SetupSession
}

func TestWhitelistAllowDeny(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{security: &WhitelistConfig{
		RequireWhitelist: true,
		CIDRs:            []string{"10.0.0.0/24", "2001:db8::/32"},
	}})
	if recorder := h.doFrom(t, http.MethodGet, "/api/v1/health", "", "", "10.0.0.5:1234"); recorder.Code != http.StatusOK {
		t.Fatalf("allowed IPv4 = %d", recorder.Code)
	}
	denied := h.doFrom(t, http.MethodGet, "/api/v1/health", "", "", "10.0.1.5:1234")
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "ip_not_allowed") {
		t.Fatalf("denied IPv4 = %d %s", denied.Code, denied.Body.String())
	}
	if denied.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("deny without no-store: %q", denied.Header().Get("Cache-Control"))
	}
	if strings.Contains(strings.ToLower(denied.Body.String()), "setup") {
		t.Error("deny response leaks setup state")
	}
	if recorder := h.doFrom(t, http.MethodGet, "/api/v1/health", "", "", "[2001:db8::1]:1234"); recorder.Code != http.StatusOK {
		t.Fatalf("allowed IPv6 = %d", recorder.Code)
	}
	if recorder := h.doFrom(t, http.MethodGet, "/api/v1/health", "", "", "[2001:db9::1]:1234"); recorder.Code != http.StatusForbidden {
		t.Fatalf("denied IPv6 = %d", recorder.Code)
	}
	if recorder := h.doFrom(t, http.MethodGet, "/api/v1/health", "", "", "garbage"); recorder.Code != http.StatusForbidden {
		t.Fatalf("unparseable source = %d, want 403", recorder.Code)
	}
}

func TestWhitelistProxyHeaders(t *testing.T) {
	trustedCIDR := []string{"192.0.2.0/24"}
	h := newAPIHarness(t, apiTestOptions{security: &WhitelistConfig{
		RequireWhitelist: true, CIDRs: []string{"10.0.0.0/24"},
	}})
	// trust_proxy_headers=false: XFF is ignored.
	request := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	request.RemoteAddr = "10.0.0.5:1234"
	request.Header.Set("X-Forwarded-For", "1.2.3.4")
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("untrusted XFF influenced the check: %d", recorder.Code)
	}

	trusted := newAPIHarness(t, apiTestOptions{security: &WhitelistConfig{
		RequireWhitelist: true, CIDRs: []string{"10.0.0.0/24"},
		TrustProxyHeaders: true, TrustedProxyCIDRs: trustedCIDR,
	}})
	// F-SW-02: only a trusted proxy may set XFF; from an untrusted peer it is
	// ignored and the direct (allowed) peer address decides.
	untrusted := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	untrusted.RemoteAddr = "10.0.0.5:1234"
	untrusted.Header.Set("X-Forwarded-For", "1.2.3.4")
	recorder = httptest.NewRecorder()
	trusted.handler.ServeHTTP(recorder, untrusted)
	if recorder.Code != http.StatusOK {
		t.Fatalf("untrusted peer XFF changed the decision: %d", recorder.Code)
	}

	lastHopAllowed := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	lastHopAllowed.RemoteAddr = "192.0.2.9:1234"
	lastHopAllowed.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.7")
	recorder = httptest.NewRecorder()
	trusted.handler.ServeHTTP(recorder, lastHopAllowed)
	if recorder.Code != http.StatusOK {
		t.Fatalf("trusted last hop = %d", recorder.Code)
	}
	lastHopDenied := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	lastHopDenied.RemoteAddr = "192.0.2.9:1234"
	lastHopDenied.Header.Set("X-Forwarded-For", "10.0.0.7, 1.2.3.4")
	recorder = httptest.NewRecorder()
	trusted.handler.ServeHTTP(recorder, lastHopDenied)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("spoofed last hop = %d, want 403", recorder.Code)
	}
	duplicate := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	duplicate.RemoteAddr = "192.0.2.9:1234"
	duplicate.Header.Add("X-Forwarded-For", "10.0.0.5")
	duplicate.Header.Add("X-Forwarded-For", "10.0.0.6")
	recorder = httptest.NewRecorder()
	trusted.handler.ServeHTTP(recorder, duplicate)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("ambiguous XFF = %d, want 403", recorder.Code)
	}
	// Trust is disabled internally when no proxy allowlist is configured.
	emptyTrust := newAPIHarness(t, apiTestOptions{security: &WhitelistConfig{
		RequireWhitelist: true, CIDRs: []string{"10.0.0.0/24"}, TrustProxyHeaders: true,
	}})
	spoof := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	spoof.RemoteAddr = "10.0.0.5:1234"
	spoof.Header.Set("X-Forwarded-For", "1.2.3.4")
	recorder = httptest.NewRecorder()
	emptyTrust.handler.ServeHTTP(recorder, spoof)
	if recorder.Code != http.StatusOK {
		t.Fatalf("empty trusted list must ignore XFF: %d", recorder.Code)
	}
}

func TestSetupWizardFlow(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "retail.json")
	if err := os.WriteFile(configPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	h := newAPIHarness(t, apiTestOptions{setup: true, configPath: configPath, security: &WhitelistConfig{SetupMode: true}})

	// W-06: non-loopback is denied in setup mode, loopback gets the wizard state.
	if recorder := h.doFrom(t, http.MethodGet, "/api/v1/setup/state", "", "", "10.1.1.1:1234"); recorder.Code != http.StatusForbidden {
		t.Fatalf("remote setup state = %d, want 403", recorder.Code)
	}
	token := h.setupSession(t)
	// W-08: complete before admin/whitelist is rejected and writes no config.
	if recorder := h.doFromHeaders(t, http.MethodPost, "/api/v1/setup/complete", "{}", "", "127.0.0.1:5555",
		map[string]string{"X-Setup-Session": token}); recorder.Code != http.StatusConflict {
		t.Fatalf("premature complete = %d, want 409", recorder.Code)
	}
	if raw, _ := os.ReadFile(configPath); strings.Contains(string(raw), `"completed": true`) {
		t.Fatal("premature complete wrote the configuration")
	}
	session := map[string]string{"X-Setup-Session": token}
	for _, step := range []struct{ path, body string }{
		{"/api/v1/setup/language", `{"language":"de"}`},
		{"/api/v1/setup/site", `{"site_id":"filiale-001","name":"Markt Nord","zones":[]}`},
		{"/api/v1/setup/whitelist", `{"cidrs":["10.20.30.0/24"]}`},
		{"/api/v1/setup/collectors", `{"adapters":[]}`},
	} {
		recorder := h.doFromHeaders(t, http.MethodPost, step.path, step.body, "", "127.0.0.1:5555", session)
		if recorder.Code != http.StatusOK {
			t.Fatalf("step %s = %d %s", step.path, recorder.Code, recorder.Body.String())
		}
	}
	admin := h.doFromHeaders(t, http.MethodPost, "/api/v1/setup/admin", `{"user_id":"admin","name":"Admin"}`, "", "127.0.0.1:5555", session)
	if admin.Code != http.StatusOK {
		t.Fatalf("admin step = %d %s", admin.Code, admin.Body.String())
	}
	var adminBody struct {
		Token       string `json:"token"`
		TokenSHA256 string `json:"token_sha256"`
	}
	if err := json.Unmarshal(admin.Body.Bytes(), &adminBody); err != nil || adminBody.Token == "" {
		t.Fatalf("admin response: %v %s", err, admin.Body.String())
	}
	// F-SW-03: a repeated admin call must not rotate the token.
	again := h.doFromHeaders(t, http.MethodPost, "/api/v1/setup/admin", `{"user_id":"admin","name":"Admin"}`, "", "127.0.0.1:5555", session)
	if again.Code != http.StatusConflict || !strings.Contains(again.Body.String(), "admin_exists") {
		t.Fatalf("second admin = %d %s", again.Code, again.Body.String())
	}
	if strings.Contains(again.Body.String(), "token") && strings.Contains(again.Body.String(), adminBody.Token) {
		t.Fatal("second admin response leaked a token")
	}
	// W-09: only the hash is persisted.
	sum := sha256.Sum256([]byte(adminBody.Token))
	if hex.EncodeToString(sum[:]) != adminBody.TokenSHA256 {
		t.Fatal("token hash mismatch")
	}
	complete := h.doFromHeaders(t, http.MethodPost, "/api/v1/setup/complete", "{}", "", "127.0.0.1:5555", session)
	if complete.Code != http.StatusOK || !strings.Contains(complete.Body.String(), "restart_required") {
		t.Fatalf("complete = %d %s", complete.Code, complete.Body.String())
	}
	// F-SW-08: bind_hint must name the actual loopback listener.
	if !strings.Contains(complete.Body.String(), `"bind_hint":"http://127.0.0.1:8080/setup"`) {
		t.Fatalf("bind_hint wrong: %s", complete.Body.String())
	}
	written, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	text := string(written)
	for _, want := range []string{`"completed": true`, "10.20.30.0/24", "127.0.0.1/32", adminBody.TokenSHA256} {
		if !strings.Contains(text, want) {
			t.Errorf("written config misses %q", want)
		}
	}
	if strings.Contains(text, adminBody.Token) {
		t.Fatal("plaintext admin token was persisted")
	}
	if info, serr := os.Stat(configPath); serr != nil {
		t.Fatalf("config stat: %v", serr)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %v", info.Mode().Perm())
	}
	// W-10: setup API and /setup are disabled after completion.
	if recorder := h.doFrom(t, http.MethodGet, "/api/v1/setup/state", "", "", "127.0.0.1:5555"); recorder.Code != http.StatusNotFound {
		t.Fatalf("setup state after complete = %d, want 404", recorder.Code)
	}
	if recorder := h.doFrom(t, http.MethodGet, "/setup", "", "", "127.0.0.1:5555"); recorder.Code != http.StatusFound {
		t.Fatalf("/setup after complete = %d, want 302", recorder.Code)
	}
	// W-11/W-12: audit contains setup steps but never the token.
	entries, err := h.audit.List(context.Background(), 200)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	setupEntries := 0
	for _, entry := range entries {
		if entry.ObjectType == "setup" {
			setupEntries++
		}
		if strings.Contains(entry.Reason, adminBody.Token) {
			t.Fatal("audit contains the plaintext setup token")
		}
	}
	if setupEntries < 5 {
		t.Errorf("setup audit entries = %d, want >= 5", setupEntries)
	}
}
