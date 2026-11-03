package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/notify"
)

var (
	testSecret = []byte("0123456789abcdef0123456789abcdef")
	baseTime   = time.Date(2026, 11, 4, 2, 14, 0, 0, time.UTC)
)

func testNotification() notify.Notification {
	return notify.Notification{
		ID:                "gal_test_1",
		Kind:              "write_denied",
		At:                baseTime,
		Severity:          domain.SeverityCritical,
		Title:             "Schreibversuch ohne Freigabe abgelehnt",
		Summary:           "Beobachtet: Schreibversuch. Abgeleitet: keine Freigabe. Empfohlene Prüfung: Freigabe prüfen.",
		DedupKey:          "gate.deny|aksm-1|10.10.40.99|fc6|40001",
		SiteID:            "filiale-001",
		TargetID:          "aksm-1",
		SourceIP:          "10.10.40.99",
		Reason:            "no_session",
		ObservedFacts:     []string{"Schreibversuch ohne Session"},
		Hypothesis:        "Unklare Autorisierung",
		RecommendedChecks: []string{"Freigabe prüfen"},
	}
}

func zeroJitter(_ int, _ time.Duration) time.Duration { return 0 }

func newTestWebhook(t *testing.T, url string, cfg func(*notify.WebhookConfig)) *notify.Webhook {
	t.Helper()
	webhookCfg := notify.WebhookConfig{
		URL:        url,
		HMACSecret: testSecret,
		// Generous per-attempt timeout: the httptest handlers are local and fast,
		// but "-race" plus parallel packages can delay scheduling well beyond a
		// second. A short timeout here makes healthy tests flaky; a hung handler is
		// still bounded by the server's request context and the test deadline.
		Timeout:     5 * time.Second,
		MaxAttempts: 1,
		BaseBackoff: time.Millisecond,
		MaxBackoff:  5 * time.Millisecond,
		Jitter:      zeroJitter,
	}
	if cfg != nil {
		cfg(&webhookCfg)
	}
	hook, err := notify.NewWebhook(webhookCfg)
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	return hook
}

func TestWebhookSignatureHeadersAndBody(t *testing.T) {
	t.Parallel()
	var (
		gotBody      []byte
		gotSignature string
		gotEvent     string
		gotDelivery  string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		gotBody = body
		gotSignature = r.Header.Get(notify.SignatureHeader)
		gotEvent = r.Header.Get(notify.EventHeader)
		gotDelivery = r.Header.Get(notify.DeliveryHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	hook := newTestWebhook(t, server.URL, nil)
	notification := testNotification()
	if err := hook.Notify(context.Background(), notification); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if gotSignature != notify.Signature(testSecret, gotBody) {
		t.Fatalf("signature mismatch: got %q want %q", gotSignature, notify.Signature(testSecret, gotBody))
	}
	if gotEvent != notification.Kind || gotDelivery != notification.ID {
		t.Fatalf("headers mismatch: event=%q delivery=%q", gotEvent, gotDelivery)
	}
	var decoded notify.Notification
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if decoded.ID != notification.ID || decoded.Severity != notification.Severity || decoded.DedupKey != notification.DedupKey {
		t.Fatalf("payload roundtrip mismatch: %+v", decoded)
	}
	if len(decoded.ObservedFacts) != 1 || decoded.Hypothesis == "" {
		t.Fatalf("payload does not separate facts and hypothesis: %+v", decoded)
	}
}

func TestWebhookRetriesServerErrorsThenSucceeds(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := requests.Add(1)
		if attempt <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	hook := newTestWebhook(t, server.URL, func(cfg *notify.WebhookConfig) {
		cfg.MaxAttempts = 5
	})
	if err := hook.Notify(context.Background(), testNotification()); err != nil {
		t.Fatalf("Notify after retries: %v", err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

func TestWebhookRetriesTooManyRequests(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	hook := newTestWebhook(t, server.URL, func(cfg *notify.WebhookConfig) { cfg.MaxAttempts = 3 })
	if err := hook.Notify(context.Background(), testNotification()); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
}

func TestWebhookDoesNotRetryClientErrors(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	hook := newTestWebhook(t, server.URL, func(cfg *notify.WebhookConfig) { cfg.MaxAttempts = 5 })
	err := hook.Notify(context.Background(), testNotification())
	if err == nil {
		t.Fatal("expected delivery error")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("4xx must not be retried, got %d attempts", got)
	}
}

// roundTripFunc adapts a function to http.RoundTripper for deterministic
// transport tests (no network, no timing races).
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestWebhookTimeoutIsRetried(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	// Deterministic timeout simulation: the transport fails every attempt with a
	// deadline error, so the retry logic is exercised without any real sleep or
	// HTTP timing that could race under full-suite load.
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		return nil, context.DeadlineExceeded
	})}
	hook := newTestWebhook(t, "http://gate.invalid/notify", func(cfg *notify.WebhookConfig) {
		cfg.MaxAttempts = 2
		cfg.Client = client
	})
	if err := hook.Notify(context.Background(), testNotification()); err == nil {
		t.Fatal("expected timeout error")
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected 2 timeout attempts, got %d", got)
	}
}

func TestWebhookContextCancellationStopsRetries(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	hook := newTestWebhook(t, server.URL, func(cfg *notify.WebhookConfig) {
		cfg.Timeout = 50 * time.Millisecond
		cfg.MaxAttempts = 5
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := hook.Notify(ctx, testNotification()); err == nil {
		t.Fatal("expected cancellation error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancellation took too long: %s", elapsed)
	}
}

func TestWebhookSendTest(t *testing.T) {
	t.Parallel()
	var kind string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload notify.Notification
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode test payload: %v", err)
		}
		kind = payload.Kind
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	hook := newTestWebhook(t, server.URL, nil)
	if err := hook.SendTest(context.Background(), baseTime, "filiale-001"); err != nil {
		t.Fatalf("SendTest: %v", err)
	}
	if kind != "gate.notify.test" {
		t.Fatalf("unexpected test kind %q", kind)
	}
}

func TestWebhookRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  notify.WebhookConfig
	}{
		{name: "missing url", cfg: notify.WebhookConfig{HMACSecret: testSecret}},
		{name: "unsupported scheme", cfg: notify.WebhookConfig{URL: "ftp://example.invalid", HMACSecret: testSecret}},
		{name: "credentials in url", cfg: notify.WebhookConfig{URL: "http://user:pass@127.0.0.1:1", HMACSecret: testSecret}},
		{name: "short secret", cfg: notify.WebhookConfig{URL: "http://127.0.0.1:1", HMACSecret: []byte("short")}},
		{name: "too many attempts", cfg: notify.WebhookConfig{URL: "http://127.0.0.1:1", HMACSecret: testSecret, MaxAttempts: 6}},
		{name: "negative timeout", cfg: notify.WebhookConfig{URL: "http://127.0.0.1:1", HMACSecret: testSecret, Timeout: -time.Second}},
		{name: "timeout too large", cfg: notify.WebhookConfig{URL: "http://127.0.0.1:1", HMACSecret: testSecret, Timeout: time.Minute}},
		{name: "base above max backoff", cfg: notify.WebhookConfig{URL: "http://127.0.0.1:1", HMACSecret: testSecret, BaseBackoff: 10 * time.Second, MaxBackoff: time.Second}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := notify.NewWebhook(tc.cfg); err == nil {
				t.Fatalf("expected configuration error for %s", tc.name)
			}
		})
	}
}

func TestWebhookRejectsInvalidNotification(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	hook := newTestWebhook(t, server.URL, nil)
	invalid := notify.Notification{ID: "gal_invalid", Kind: "write_denied", At: baseTime}
	if err := hook.Notify(context.Background(), invalid); err == nil {
		t.Fatal("expected validation error")
	}
	if requests.Load() != 0 {
		t.Fatal("invalid notification must not be sent")
	}
}

func TestWebhookSignatureIsStableAndSecretBound(t *testing.T) {
	t.Parallel()
	body := []byte(`{"id":"gal_1"}`)
	first := notify.Signature(testSecret, body)
	if first != notify.Signature(testSecret, body) {
		t.Fatal("signature is not deterministic")
	}
	other := notify.Signature([]byte("another-secret-0123456789"), body)
	if first == other {
		t.Fatal("signature does not depend on the secret")
	}
	if len(first) <= len("sha256=") || first[:7] != "sha256=" {
		t.Fatalf("unexpected signature format: %q", first)
	}
}
