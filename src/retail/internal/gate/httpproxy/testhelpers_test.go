package httpproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/fakedev"
)

var testNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// fakeGate implements both the SessionLookup and the Authenticator seam.
type fakeGate struct {
	mu         sync.Mutex
	session    domain.WriteSession
	plan       domain.WritePlan
	hasSession bool
	hasPlan    bool
	consumeOK  bool
	allowedErr error
	denies     []domain.DeniedWriteAttempt
	allowedOps []domain.WriteOperation
}

func (f *fakeGate) Lookup(domain.TargetID, string, time.Time) (domain.WriteSession, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.session, f.hasSession
}

func (f *fakeGate) ConsumeUse(domain.SessionID, time.Time) bool { return f.consumeOK }

func (f *fakeGate) PlanFor(domain.SessionID) (domain.WritePlan, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.plan, f.hasPlan
}

func (f *fakeGate) Deny(_ context.Context, attempt domain.DeniedWriteAttempt) error {
	f.mu.Lock()
	f.denies = append(f.denies, attempt)
	f.mu.Unlock()
	return nil
}

func (f *fakeGate) Allowed(_ context.Context, _ domain.SessionID, op domain.WriteOperation) error {
	f.mu.Lock()
	f.allowedOps = append(f.allowedOps, op)
	f.mu.Unlock()
	return f.allowedErr
}

func (f *fakeGate) Login(_ context.Context, userID, password, _ string) (domain.GateUserID, string, error) {
	if userID == "vendor" && password == "correct" {
		return "vendor-acme", "tok_test", nil
	}
	return "", "", errors.New("invalid credentials")
}

func (f *fakeGate) Authenticate(_ context.Context, token string) (domain.GateUserID, bool) {
	return "vendor-acme", token == "tok_test"
}

func (f *fakeGate) Logout(context.Context, string) error { return nil }

func (f *fakeGate) denyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.denies)
}

func (f *fakeGate) lastDeny(t *testing.T) domain.DeniedWriteAttempt {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.denies) == 0 {
		t.Fatal("no deny recorded")
	}
	return f.denies[len(f.denies)-1]
}

func (f *fakeGate) allowedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.allowedOps)
}

func sessionFor(sourceIP string, expires time.Time) domain.WriteSession {
	return domain.WriteSession{
		SessionID: "ses_http", PlanID: "pln_http", TargetID: "xweb-1", UserID: "vendor-acme",
		SourceIP: sourceIP, CreatedAt: testNow.Add(-time.Minute), ExpiresAt: expires, MaxUses: 1,
	}
}

func httpOp(function, address, value string) domain.WriteOperation {
	return domain.WriteOperation{Protocol: Protocol, Function: function, Address: address, CurrentValue: "old", NewValue: value}
}

func httpPlan(ops ...domain.WriteOperation) domain.WritePlan {
	return domain.WritePlan{
		PlanID: "pln_http", SiteID: "filiale-001", TargetID: "xweb-1",
		AssetID: "asset-dixell-xweb", Protocol: Protocol, Operations: ops,
		Reason: "test", RequestedBy: "vendor-acme",
		RequestedAt: testNow.Add(-time.Hour),
		WindowStart: testNow.Add(-time.Hour), WindowEnd: testNow.Add(time.Hour),
		State: domain.PlanApproved,
	}
}

type fixture struct {
	gate       *fakeGate
	supervisor *fakedev.Supervisor
	proxy      *Proxy
	server     *httptest.Server
	upstream   string
}

func newFixture(t *testing.T, mutate func(*Config)) *fixture {
	t.Helper()
	supervisor, err := fakedev.NewSupervisor(fakedev.HTTPConfig{})
	if err != nil {
		t.Fatalf("fake supervisor: %v", err)
	}
	if err := supervisor.Start(); err != nil {
		t.Fatalf("start supervisor: %v", err)
	}
	t.Cleanup(func() { _ = supervisor.Close() })
	gate := &fakeGate{consumeOK: true}
	cfg := Config{
		TargetID:           "xweb-1",
		Listen:             "127.0.0.1:0",
		Upstream:           "http://" + supervisor.Addr(),
		URLAllowlist:       []string{"/", "/cgi-bin/*"},
		ParameterAllowlist: []string{"setpoint", "defrost_mode"},
		SourceCIDRs:        []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Clock:              fixedClock{at: testNow},
		BodyLimit:          64 << 10,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	proxy, err := New(cfg, gate, gate)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	server := httptest.NewServer(proxy.Handler())
	t.Cleanup(server.Close)
	return &fixture{gate: gate, supervisor: supervisor, proxy: proxy, server: server, upstream: cfg.Upstream}
}

// login performs the full gate login (CSRF + credentials) and returns a cookie
// jar client that does not follow redirects.
func (f *fixture) login(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err := client.Get(f.server.URL + gateLoginPath)
	if err != nil {
		t.Fatalf("login form: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	token := extractCSRF(string(body))
	if token == "" {
		t.Fatalf("no csrf token in login form: %s", body)
	}
	form := url.Values{"user_id": {"vendor"}, "password": {"correct"}, "csrf": {token}}
	post, err := client.PostForm(f.server.URL+gateLoginPath, form)
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	defer func() { _ = post.Body.Close() }()
	if post.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d", post.StatusCode)
	}
	return client
}

func extractCSRF(body string) string {
	const marker = `name="csrf" value="`
	index := strings.Index(body, marker)
	if index < 0 {
		return ""
	}
	rest := body[index+len(marker):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func sha256Hex(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}
