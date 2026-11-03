package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestHealthIsPublic(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	recorder := h.do(t, http.MethodGet, "/api/v1/health", nil, "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	body := decode[healthResponse](t, recorder)
	if body.Status != "ok" || body.Product != "GeDefense Retail" {
		t.Errorf("health = %+v", body)
	}
	if !body.ReadOnly {
		t.Error("read_only must be true")
	}
	if len(body.Collectors) != 2 || body.Collectors[0].AdapterID != "modbus.pool1" {
		t.Errorf("collectors = %+v", body.Collectors)
	}
	if body.Storage.Events != 0 || body.Storage.Alerts != 0 || !body.Storage.AuditChainOK {
		t.Errorf("storage = %+v", body.Storage)
	}
	if body.Now.IsZero() || body.UptimeS < 0 {
		t.Errorf("timing = %+v", body)
	}
	assertSecurityHeaders(t, recorder)
	if got := recorder.Header().Get("X-Request-Id"); len(got) < minRequestIDLen {
		t.Errorf("X-Request-Id = %q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestProtectedEndpointsRequireToken(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	paths := []string{
		"/api/v1/meta", "/api/v1/overview", "/api/v1/sites", "/api/v1/assets",
		"/api/v1/alerts", "/api/v1/coldchain", "/api/v1/access", "/api/v1/timeline",
		"/api/v1/integrity", "/api/v1/incidents", "/api/v1/policies", "/api/v1/audit",
		"/api/v1/collectors", "/api/v1/stream",
	}
	for _, path := range paths {
		recorder := h.do(t, http.MethodGet, path, nil, "", nil)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", path, recorder.Code)
			continue
		}
		body := decode[apiErrorEnvelope](t, recorder)
		if body.Error.Code != "unauthorized" || body.Error.RequestID == "" {
			t.Errorf("%s: error = %+v", path, body.Error)
		}
		if got := recorder.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
			t.Errorf("%s: WWW-Authenticate = %q", path, got)
		}
	}
}

func TestInvalidTokens(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	headers := []string{
		"Bearer " + viewerToken + "x",
		"Bearer wrong-token",
		"Bearer ",
		"Token " + viewerToken,
		viewerToken,
		"Bearer " + viewerToken + " extra",
	}
	for _, header := range headers {
		recorder := h.do(t, http.MethodGet, "/api/v1/sites", nil, "", map[string]string{"Authorization": header})
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: status = %d, want 401", header, recorder.Code)
		}
	}
}

func TestRoleBasedAccessControl(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})

	// A viewer may read.
	if recorder := h.do(t, http.MethodGet, "/api/v1/sites", nil, viewerToken, nil); recorder.Code != http.StatusOK {
		t.Fatalf("viewer GET = %d", recorder.Code)
	}
	// A viewer may not close an alert.
	alert := h.seedAlert(t, "alr-1", "dedup-1", "high", "Temperature above limit")
	recorder := h.do(t, http.MethodPost, "/api/v1/alerts/"+string(alert.AlertID)+"/close", map[string]string{"status": "resolved"}, viewerToken, nil)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("viewer close = %d, want 403", recorder.Code)
	}
	// An operator may acknowledge.
	recorder = h.do(t, http.MethodPost, "/api/v1/alerts/"+string(alert.AlertID)+"/ack", map[string]string{"note": "seen"}, operatorToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("operator ack = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	// An operator may not reload policies or create windows.
	if recorder = h.do(t, http.MethodPost, "/api/v1/policies/reload", nil, operatorToken, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("operator reload = %d, want 403", recorder.Code)
	}
	body := map[string]any{
		"vendor": "ServiceCo", "starts_at": "2026-11-03T13:00:00Z", "ends_at": "2026-11-03T15:00:00Z",
	}
	if recorder = h.do(t, http.MethodPost, "/api/v1/windows", body, operatorToken, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("operator window create = %d, want 403", recorder.Code)
	}
	// An admin may create a window.
	if recorder = h.do(t, http.MethodPost, "/api/v1/windows", body, adminToken, nil); recorder.Code != http.StatusOK {
		t.Errorf("admin window create = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestRateLimit(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	limited := 0
	for i := 0; i < rateBurst+2; i++ {
		recorder := h.do(t, http.MethodGet, "/api/v1/sites", nil, adminToken, nil)
		if recorder.Code == http.StatusTooManyRequests {
			limited++
			if i < rateBurst {
				t.Fatalf("request %d was limited before the burst was exhausted", i+1)
			}
			if recorder.Header().Get("Retry-After") == "" {
				t.Error("429 without Retry-After header")
			}
			body := decode[apiErrorEnvelope](t, recorder)
			if body.Error.Code != "rate_limited" {
				t.Errorf("error code = %q", body.Error.Code)
			}
			continue
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d", i+1, recorder.Code)
		}
	}
	if limited != 2 {
		t.Errorf("limited requests = %d, want 2", limited)
	}
	// A different token has its own bucket.
	if recorder := h.do(t, http.MethodGet, "/api/v1/sites", nil, viewerToken, nil); recorder.Code != http.StatusOK {
		t.Errorf("other token after rate limit = %d, want 200", recorder.Code)
	}
}

func TestStrictJSONBody(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	alert := h.seedAlert(t, "alr-1", "dedup-1", "high", "Temperature above limit")
	path := "/api/v1/alerts/" + string(alert.AlertID) + "/ack"

	cases := []struct {
		name string
		body string
	}{
		{"unknown field", `{"note":"x","unexpected":true}`},
		{"trailing content", `{"note":"x"} {"note":"y"}`},
		{"malformed", `{"note":`},
		{"wrong type", `{"note":42}`},
		{"not an object", `["note"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newJSONRequest(t, http.MethodPost, path, tc.body, adminToken)
			recorder := h.serve(req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", recorder.Code, recorder.Body.String())
			}
			body := decode[apiErrorEnvelope](t, recorder)
			if body.Error.Code != "invalid_request" {
				t.Errorf("code = %q", body.Error.Code)
			}
		})
	}
}

func TestBodyLimit(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	alert := h.seedAlert(t, "alr-1", "dedup-1", "high", "Temperature above limit")
	path := "/api/v1/alerts/" + string(alert.AlertID) + "/ack"
	padding := strings.Repeat("a", maxBodyBytes+1)
	req := newJSONRequest(t, http.MethodPost, path, `{"note":"`+padding+`"}`, adminToken)
	recorder := h.serve(req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	body := decode[apiErrorEnvelope](t, recorder)
	if !strings.Contains(body.Error.Message, "256 KiB") {
		t.Errorf("message = %q", body.Error.Message)
	}
}

func TestRequestIDHandling(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	valid := "client-request_1234"
	recorder := h.do(t, http.MethodGet, "/api/v1/health", nil, "", map[string]string{"X-Request-Id": valid})
	if got := recorder.Header().Get("X-Request-Id"); got != valid {
		t.Errorf("valid request id = %q, want %q", got, valid)
	}
	recorder = h.do(t, http.MethodGet, "/api/v1/health", nil, "", map[string]string{"X-Request-Id": "bad id with spaces"})
	if got := recorder.Header().Get("X-Request-Id"); got == "bad id with spaces" || len(got) < minRequestIDLen {
		t.Errorf("invalid request id not replaced: %q", got)
	}
	body := decode[apiErrorEnvelope](t, h.do(t, http.MethodGet, "/api/v1/sites", nil, "", nil))
	if body.Error.RequestID == "" {
		t.Error("error response without request id")
	}
}

func TestQueryValidation(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	cases := []string{
		"/api/v1/sites?unexpected=1",
		"/api/v1/assets?limit=0",
		"/api/v1/assets?limit=500",
		"/api/v1/assets?offset=-1",
		"/api/v1/alerts?status=bogus",
		"/api/v1/alerts?severity=apocalyptic",
		"/api/v1/alerts?category=nonsense",
		"/api/v1/assets?type=toaster",
		"/api/v1/coldchain?since=yesterday",
		"/api/v1/assets?site_id=bad%20id",
	}
	for _, target := range cases {
		recorder := h.do(t, http.MethodGet, target, nil, viewerToken, nil)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", target, recorder.Code)
		}
	}
}

func TestMethodNotAllowedAndUnknownPath(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	recorder := h.do(t, http.MethodDelete, "/api/v1/sites", nil, adminToken, nil)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", recorder.Code)
	}
	if allow := recorder.Header().Get("Allow"); !strings.Contains(allow, http.MethodGet) {
		t.Errorf("Allow = %q", allow)
	}
	recorder = h.do(t, http.MethodGet, "/api/v1/does-not-exist", nil, adminToken, nil)
	if recorder.Code != http.StatusNotFound {
		t.Errorf("unknown path status = %d, want 404", recorder.Code)
	}
	body := decode[apiErrorEnvelope](t, recorder)
	if body.Error.Code != "not_found" {
		t.Errorf("code = %q", body.Error.Code)
	}
}

func assertSecurityHeaders(t *testing.T, recorder interface{ Header() http.Header }) {
	t.Helper()
	header := recorder.Header()
	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for key, want := range expected {
		if got := header.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if got := header.Get("Permissions-Policy"); !strings.Contains(got, "camera=()") {
		t.Errorf("Permissions-Policy = %q", got)
	}
	csp := header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy = %q", csp)
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP allows unsafe sources: %q", csp)
	}
}
