package httpproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/fakedev"
)

func TestLoginFlowAndReadProxy(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	client := f.login(t)
	response, err := client.Get(f.server.URL + "/")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "Fake Supervisor") {
		t.Fatalf("read status=%d body=%q", response.StatusCode, body)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control = %q", response.Header.Get("Cache-Control"))
	}
	if response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("nosniff missing")
	}
	state := f.supervisor.State()
	if state.Requests == 0 {
		t.Fatal("upstream saw no request")
	}
	if state.LastHeaders.Get("Cookie") != "" {
		t.Fatalf("gate cookie was forwarded to the device: %q", state.LastHeaders.Get("Cookie"))
	}
}

func TestUnauthenticatedReadIsRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	response, err := http.Get(f.server.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if f.supervisor.State().Requests != 0 {
		t.Fatal("unauthenticated request reached the device")
	}
}

func TestLoginFailuresAndRateLimit(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(f.server.URL + gateLoginPath)
	if err != nil {
		t.Fatalf("form: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	token := extractCSRF(string(body))
	form := url.Values{"user_id": {"vendor"}, "password": {"wrong"}, "csrf": {token}}
	last := 0
	for i := 0; i < 11; i++ {
		post, err := client.PostForm(f.server.URL+gateLoginPath, form)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		last = post.StatusCode
		_ = post.Body.Close()
	}
	if last != http.StatusUnauthorized && last != http.StatusTooManyRequests {
		t.Fatalf("last login status = %d", last)
	}
	// CSRF is required (fresh fixture so the rate limit does not interfere).
	csrfFixture := newFixture(t, nil)
	post, err := http.PostForm(csrfFixture.server.URL+gateLoginPath, url.Values{"user_id": {"vendor"}, "password": {"correct"}})
	if err != nil {
		t.Fatalf("csrf post: %v", err)
	}
	_ = post.Body.Close()
	if post.StatusCode != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d", post.StatusCode)
	}
}

func TestPOSTWithoutPlanDenied(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	client := f.login(t)
	response, err := client.PostForm(f.server.URL+"/cgi-bin/config", url.Values{"setpoint": {"3.5"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if f.supervisor.State().Writes != 0 {
		t.Fatal("denied write reached the device")
	}
	if f.gate.denyCount() != 1 {
		t.Fatalf("deny evidence = %d", f.gate.denyCount())
	}
	if f.gate.lastDeny(t).Reason != ReasonNoSession {
		t.Fatalf("reason = %q", f.gate.lastDeny(t).Reason)
	}
}

func TestPOSTWithExactPlanForwarded(t *testing.T) {
	t.Parallel()
	body := "setpoint=3.5"
	f := newFixture(t, nil)
	f.gate.mu.Lock()
	f.gate.hasSession = true
	f.gate.hasPlan = true
	f.gate.session = sessionFor("127.0.0.1", testNow.Add(time.Hour))
	f.gate.plan = httpPlan(httpOp("http_post", "/cgi-bin/config", sha256Hex(body)))
	f.gate.mu.Unlock()
	client := f.login(t)
	response, err := client.PostForm(f.server.URL+"/cgi-bin/config", url.Values{"setpoint": {"3.5"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d body=%q", response.StatusCode, body)
	}
	if f.supervisor.State().Writes != 1 {
		t.Fatalf("upstream writes = %d", f.supervisor.State().Writes)
	}
	if f.gate.allowedCount() != 1 {
		t.Fatalf("allowed audit = %d", f.gate.allowedCount())
	}
}

func TestPOSTWrongBodyDenied(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.gate.mu.Lock()
	f.gate.hasSession = true
	f.gate.hasPlan = true
	f.gate.session = sessionFor("127.0.0.1", testNow.Add(time.Hour))
	f.gate.plan = httpPlan(httpOp("http_post", "/cgi-bin/config", sha256Hex("setpoint=3.5")))
	f.gate.mu.Unlock()
	client := f.login(t)
	response, err := client.PostForm(f.server.URL+"/cgi-bin/config", url.Values{"setpoint": {"9.9"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if f.gate.lastDeny(t).Reason != ReasonValueMismatch {
		t.Fatalf("reason = %q", f.gate.lastDeny(t).Reason)
	}
	if f.supervisor.State().Writes != 0 {
		t.Fatal("value mismatch reached the device")
	}
}

func TestURLNotAllowlistedDenied(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.gate.mu.Lock()
	f.gate.hasSession = true
	f.gate.hasPlan = true
	f.gate.session = sessionFor("127.0.0.1", testNow.Add(time.Hour))
	f.gate.plan = httpPlan(httpOp("http_post", "/other", sha256Hex("a=1")))
	f.gate.mu.Unlock()
	client := f.login(t)
	response, err := client.PostForm(f.server.URL+"/other", url.Values{"a": {"1"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if f.supervisor.State().Requests != 0 {
		t.Fatal("not-allowlisted write reached the device")
	}
}

func TestFirmwareUploadHardDenied(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.gate.mu.Lock()
	f.gate.hasSession = true
	f.gate.hasPlan = true
	f.gate.session = sessionFor("127.0.0.1", testNow.Add(time.Hour))
	f.gate.plan = httpPlan(httpOp("http_post", "/firmware/x.spk", sha256Hex("")))
	f.gate.mu.Unlock()
	client := f.login(t)
	response, err := client.Post(f.server.URL+"/firmware/x.spk", "application/octet-stream", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if f.gate.denyCount() != 1 {
		t.Fatalf("deny evidence = %d", f.gate.denyCount())
	}
	if f.supervisor.State().Requests != 0 {
		t.Fatal("firmware upload reached the device")
	}
}

func TestDeviceCookiesRewritten(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	client := f.login(t)
	response, err := client.Get(f.server.URL + "/cgi-bin/setcookie")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = response.Body.Close()
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v", cookies)
	}
	cookie := cookies[0]
	if !strings.HasPrefix(cookie.Name, deviceCookiePrefix) {
		t.Fatalf("cookie name not prefixed: %q", cookie.Name)
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Domain != "" {
		t.Fatalf("cookie flags = %+v", cookie)
	}
	if cookie.Path != "/" {
		t.Fatalf("cookie path = %q", cookie.Path)
	}
}

func TestLocationRewrittenToGatePath(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	client := f.login(t)
	response, err := client.Get(f.server.URL + "/cgi-bin/redirect")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", response.StatusCode)
	}
	location := response.Header.Get("Location")
	if strings.HasPrefix(location, "http") {
		t.Fatalf("absolute device redirect leaked: %q", location)
	}
	if location != "/cgi-bin/config" {
		t.Fatalf("location = %q", location)
	}
}

func TestXForwardedForAndAuthNotForwarded(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	client := f.login(t)
	request, _ := http.NewRequest(http.MethodGet, f.server.URL+"/", nil)
	request.Header.Set("X-Forwarded-For", "10.0.0.1")
	request.Header.Set("Authorization", "Basic c2VjcmV0")
	request.Header.Set("Connection", "keep-alive")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = response.Body.Close()
	headers := f.supervisor.State().LastHeaders
	for _, forbidden := range []string{"X-Forwarded-For", "Authorization", "Connection"} {
		if headers.Get(forbidden) != "" {
			t.Fatalf("header %s was forwarded to the device: %q", forbidden, headers.Get(forbidden))
		}
	}
}

func TestUpgradeRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	client := f.login(t)
	request, _ := http.NewRequest(http.MethodGet, f.server.URL+"/", nil)
	request.Header.Set("Upgrade", "websocket")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestChunkedPOSTForwarded(t *testing.T) {
	t.Parallel()
	body := "setpoint=2.5"
	f := newFixture(t, nil)
	f.gate.mu.Lock()
	f.gate.hasSession = true
	f.gate.hasPlan = true
	f.gate.session = sessionFor("127.0.0.1", testNow.Add(time.Hour))
	f.gate.plan = httpPlan(httpOp("http_post", "/cgi-bin/config", sha256Hex(body)))
	f.gate.mu.Unlock()
	client := f.login(t)
	request, _ := http.NewRequest(http.MethodPost, f.server.URL+"/cgi-bin/config", io.NopCloser(strings.NewReader(body)))
	request.ContentLength = -1 // forces chunked transfer encoding
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("chunked post: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d body=%q", response.StatusCode, body)
	}
	if f.supervisor.State().Writes != 1 {
		t.Fatalf("upstream writes = %d", f.supervisor.State().Writes)
	}
}

func TestParameterAllowlistEnforced(t *testing.T) {
	t.Parallel()
	body := "evil=1"
	f := newFixture(t, nil)
	f.gate.mu.Lock()
	f.gate.hasSession = true
	f.gate.hasPlan = true
	f.gate.session = sessionFor("127.0.0.1", testNow.Add(time.Hour))
	f.gate.plan = httpPlan(httpOp("http_post", "/cgi-bin/config", sha256Hex(body)))
	f.gate.mu.Unlock()
	client := f.login(t)
	response, err := client.PostForm(f.server.URL+"/cgi-bin/config", url.Values{"evil": {"1"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if f.supervisor.State().Writes != 0 {
		t.Fatal("non-allowlisted parameter reached the device")
	}
}

func TestCertificatePinRequiredAndEnforced(t *testing.T) {
	t.Parallel()
	supervisor, err := fakedev.NewSupervisor(fakedev.HTTPConfig{})
	if err != nil {
		t.Fatalf("supervisor: %v", err)
	}
	defer func() { _ = supervisor.Close() }()
	tlsServer := httptest.NewTLSServer(supervisor.Handler())
	defer tlsServer.Close()
	pin := sha256.Sum256(tlsServer.Certificate().Raw)
	goodPin := hex.EncodeToString(pin[:])
	wrongPin := strings.Repeat("00", 32)

	cfg := Config{
		TargetID: "xweb-1", Listen: "127.0.0.1:0", Upstream: tlsServer.URL,
		URLAllowlist: []string{"/"}, CertPins: []string{goodPin}, RequireCertPin: true,
		SourceCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Clock: fixedClock{at: testNow},
	}
	gate := &fakeGate{consumeOK: true}
	proxy, err := New(cfg, gate, gate)
	if err != nil {
		t.Fatalf("new proxy with pin: %v", err)
	}
	server := httptest.NewServer(proxy.Handler())
	defer server.Close()
	f := &fixture{gate: gate, supervisor: supervisor, proxy: proxy, server: server}
	client := f.login(t)
	response, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("pinned get: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("pinned status = %d", response.StatusCode)
	}
	cfg.CertPins = []string{wrongPin}
	badProxy, err := New(cfg, gate, gate)
	if err != nil {
		t.Fatalf("new proxy with wrong pin: %v", err)
	}
	badServer := httptest.NewServer(badProxy.Handler())
	defer badServer.Close()
	badFixture := &fixture{gate: gate, supervisor: supervisor, proxy: badProxy, server: badServer}
	badClient := badFixture.login(t)
	badResponse, err := badClient.Get(badServer.URL + "/")
	if err != nil {
		t.Fatalf("bad pin get: %v", err)
	}
	_ = badResponse.Body.Close()
	if badResponse.StatusCode != http.StatusBadGateway {
		t.Fatalf("pin mismatch status = %d", badResponse.StatusCode)
	}
	// Missing pin with require_cert_pin is a configuration error (fail closed).
	cfg.CertPins = nil
	if _, err := New(cfg, gate, gate); err == nil {
		t.Fatal("require_cert_pin without a pin must fail")
	}
}
