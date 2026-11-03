package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Webhook header names. They are exported so operators, tests and provider
// integrations use exactly the same contract.
const (
	SignatureHeader = "X-GeDefense-Signature" // sha256=<hex hmac of the body>
	EventHeader     = "X-GeDefense-Event"     // notification kind
	DeliveryHeader  = "X-GeDefense-Delivery"  // notification id
	TimestampHeader = "X-GeDefense-Timestamp" // unix seconds of the notification instant
)

// Delivery bounds. They match the engineering contract (max. 5 attempts,
// timeout 5 s by default) and are validated instead of silently corrected.
const (
	defaultTimeout     = 5 * time.Second
	maxTimeout         = 30 * time.Second
	defaultMaxAttempts = 5
	maxMaxAttempts     = 5
	defaultBaseBackoff = 200 * time.Millisecond
	defaultMaxBackoff  = 5 * time.Second
)

// WebhookConfig configures the HMAC-signed webhook transport.
type WebhookConfig struct {
	// URL is the operator-approved receiver endpoint (http or https only).
	URL string
	// HMACSecret signs the request body. It must be at least 16 bytes; it is
	// never logged and never included in a payload.
	HMACSecret []byte
	// Timeout is the per-attempt HTTP timeout (default 5 s, max 30 s).
	Timeout time.Duration
	// MaxAttempts bounds the delivery attempts including the first one
	// (default 5, max 5).
	MaxAttempts int
	// BaseBackoff/MaxBackoff configure exponential backoff between attempts.
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	// Jitter decorates the computed backoff (default: 50-100% of the backoff).
	Jitter func(attempt int, backoff time.Duration) time.Duration
	// Client optionally injects the HTTP client (tests, custom transports). When
	// nil, a client with the configured Timeout is used. An injected client owns
	// its own timeout configuration.
	Client *http.Client
}

func (cfg WebhookConfig) normalize() (WebhookConfig, error) {
	if cfg.URL == "" {
		return WebhookConfig{}, fmt.Errorf("notify: webhook url is required")
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return WebhookConfig{}, fmt.Errorf("notify: invalid webhook url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return WebhookConfig{}, fmt.Errorf("notify: webhook url scheme must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return WebhookConfig{}, fmt.Errorf("notify: webhook url has no host")
	}
	if parsed.User != nil {
		return WebhookConfig{}, fmt.Errorf("notify: webhook url must not contain credentials")
	}
	if len(cfg.HMACSecret) < 16 {
		return WebhookConfig{}, fmt.Errorf("notify: hmac secret must be at least 16 bytes")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Timeout < 0 || cfg.Timeout > maxTimeout {
		return WebhookConfig{}, fmt.Errorf("notify: timeout must be in (0, %s]", maxTimeout)
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.MaxAttempts < 1 || cfg.MaxAttempts > maxMaxAttempts {
		return WebhookConfig{}, fmt.Errorf("notify: max attempts must be in [1, %d]", maxMaxAttempts)
	}
	if cfg.BaseBackoff == 0 {
		cfg.BaseBackoff = defaultBaseBackoff
	}
	if cfg.BaseBackoff < 0 {
		return WebhookConfig{}, fmt.Errorf("notify: negative base backoff")
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}
	if cfg.MaxBackoff < cfg.BaseBackoff {
		return WebhookConfig{}, fmt.Errorf("notify: max backoff smaller than base backoff")
	}
	if cfg.Jitter == nil {
		cfg.Jitter = defaultJitter
	}
	return cfg, nil
}

// Webhook is the HMAC-signed HTTP transport. It retries bounded network/5xx/429
// failures with exponential backoff and never retries a definite 4xx rejection.
type Webhook struct {
	endpoint    string
	secret      []byte
	client      *http.Client
	maxAttempts int
	baseBackoff time.Duration
	maxBackoff  time.Duration
	jitter      func(attempt int, backoff time.Duration) time.Duration
}

// NewWebhook validates the configuration and builds the transport.
func NewWebhook(cfg WebhookConfig) (*Webhook, error) {
	normalized, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	client := normalized.Client
	if client == nil {
		client = &http.Client{Timeout: normalized.Timeout}
	}
	return &Webhook{
		endpoint:    normalized.URL,
		secret:      append([]byte(nil), normalized.HMACSecret...),
		client:      client,
		maxAttempts: normalized.MaxAttempts,
		baseBackoff: normalized.BaseBackoff,
		maxBackoff:  normalized.MaxBackoff,
		jitter:      normalized.Jitter,
	}, nil
}

// Notify delivers the notification with retries. The returned error wraps the
// last delivery error; context cancellation stops the retry loop immediately.
func (w *Webhook) Notify(ctx context.Context, n Notification) error {
	if w == nil {
		return fmt.Errorf("notify: nil webhook")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := n.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("notify: encode payload: %w", err)
	}
	var lastErr error
	for attempt := 1; attempt <= w.maxAttempts; attempt++ {
		lastErr = w.deliver(ctx, body, n)
		if lastErr == nil {
			return nil
		}
		if !retryable(lastErr) {
			return fmt.Errorf("notify: delivery rejected: %w", lastErr)
		}
		if attempt == w.maxAttempts {
			break
		}
		if err := sleepContext(ctx, w.backoff(attempt)); err != nil {
			return fmt.Errorf("notify: retry wait: %w", err)
		}
	}
	return fmt.Errorf("notify: delivery failed after %d attempts: %w", w.maxAttempts, lastErr)
}

// SendTest sends the operator-triggered "notify test" payload.
func (w *Webhook) SendTest(ctx context.Context, at time.Time, site domain.SiteID) error {
	return w.Notify(ctx, TestNotification(at, site))
}

func (w *Webhook) deliver(ctx context.Context, body []byte, n Notification) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, w.endpoint, bytes.NewReader(body))
	if err != nil {
		return &deliveryError{retryable: false, err: err}
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("User-Agent", "GeDefense-Retail-Access-Gate/0.2")
	request.Header.Set(SignatureHeader, Signature(w.secret, body))
	request.Header.Set(EventHeader, n.Kind)
	request.Header.Set(DeliveryHeader, n.ID)
	request.Header.Set(TimestampHeader, fmt.Sprintf("%d", n.At.Unix()))
	response, err := w.client.Do(request)
	if err != nil {
		status := 0
		var statusErr interface{ StatusCode() int }
		if errors.As(err, &statusErr) {
			status = statusErr.StatusCode()
		}
		return &deliveryError{status: status, retryable: ctx.Err() == nil, err: err}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	return &deliveryError{status: response.StatusCode, retryable: retryableStatus(response.StatusCode)}
}

// Signature returns the header value for a body: "sha256=<hex>".
func Signature(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

type deliveryError struct {
	status    int
	retryable bool
	err       error
}

func (e *deliveryError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("status=%d: %v", e.status, e.err)
	}
	return fmt.Sprintf("status=%d", e.status)
}

func (e *deliveryError) Unwrap() error { return e.err }

func retryable(err error) bool {
	var delivery *deliveryError
	if errors.As(err, &delivery) {
		return delivery.retryable
	}
	return false
}

func (w *Webhook) backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := w.baseBackoff
	for i := 1; i < attempt && delay < w.maxBackoff; i++ {
		if delay > w.maxBackoff/2 {
			delay = w.maxBackoff
			break
		}
		delay *= 2
	}
	if delay > w.maxBackoff {
		delay = w.maxBackoff
	}
	jittered := w.jitter(attempt, delay)
	if jittered < 0 {
		return 0
	}
	return jittered
}

func defaultJitter(_ int, backoff time.Duration) time.Duration {
	half := backoff / 2
	if half <= 0 {
		return backoff
	}
	// math/rand's global source is safe for concurrent use and is only used for
	// retry dispersion, never for secrets or identifiers.
	return half + time.Duration(rand.Int63n(int64(half)))
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
