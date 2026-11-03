// Proxy lifecycle and configuration.
package httpproxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Protocol is the protocol label used in plans and deny evidence.
const Protocol = "http"

// Defaults; the body/response limits keep a broken device from exhausting the
// gate.
const (
	defaultTimeout       = 5 * time.Second
	defaultBodyLimit     = 128 << 10
	defaultResponseLimit = 8 << 20
	defaultSessionTTL    = 15 * time.Minute
	defaultMaxIdleConns  = 32
	maxBodyLimit         = 4 << 20
	maxResponseLimit     = 64 << 20
	maxCAFileBytes       = 1 << 20
)

// SessionLookup is the consumer-defined seam to the gate core (contract §2).
type SessionLookup interface {
	Lookup(targetID domain.TargetID, sourceIP string, now time.Time) (domain.WriteSession, bool)
	ConsumeUse(sessionID domain.SessionID, now time.Time) bool
	PlanFor(sessionID domain.SessionID) (domain.WritePlan, bool)
	Deny(ctx context.Context, attempt domain.DeniedWriteAttempt) error
	Allowed(ctx context.Context, sessionID domain.SessionID, op domain.WriteOperation) error
}

// Authenticator is the consumer-defined login seam. The identity implementation
// (PBKDF2/TOTP/lockout) lives in the gate core; the proxy owns the HTTP login
// mechanics and the session cookie.
type Authenticator interface {
	// Login verifies the credentials and returns the user plus a new opaque
	// session token (only the proxy stores it in the browser cookie).
	Login(ctx context.Context, userID, password, totp string) (domain.GateUserID, string, error)
	// Authenticate resolves a session token to an active gate user.
	Authenticate(ctx context.Context, token string) (domain.GateUserID, bool)
	// Logout revokes the token (best effort).
	Logout(ctx context.Context, token string) error
}

// Config is the per-target proxy configuration.
type Config struct {
	TargetID domain.TargetID
	Listen   string
	Upstream string
	CAFile   string
	// CertPins are SHA-256 hex fingerprints of the device leaf certificate
	// (certificate pinning). A missing pin is a deny when RequireCertPin is set.
	CertPins        []string
	RequireCertPin  bool
	URLAllowlist    []string
	HeaderAllowlist []string
	// ParameterAllowlist restricts the form/JSON parameter names of writes
	// (Alpha CGI mitigation; empty documents the Alpha limitation).
	ParameterAllowlist []string
	// AllowCGIWrites must be enabled explicitly; CGI write paths are denied by
	// default (StoreView xml.cgi is the documented high-risk endpoint).
	AllowCGIWrites   bool
	Timeout          time.Duration
	BodyLimit        int64
	MaxResponseBytes int64
	SessionTTL       time.Duration
	SecureCookies    bool
	SourceCIDRs      []netip.Prefix
	Clock            ports.Clock
}

// Validate checks the mandatory fields.
func (c Config) Validate() error {
	if err := c.TargetID.Validate(); err != nil {
		return fmt.Errorf("httpproxy: %w", err)
	}
	if c.Listen == "" || c.Upstream == "" {
		return errors.New("httpproxy: listen and upstream are required")
	}
	if len(c.SourceCIDRs) == 0 {
		return errors.New("httpproxy: source_cidrs is required (fail-closed)")
	}
	if _, err := parseUpstream(c.Upstream); err != nil {
		return err
	}
	return nil
}

// parseUpstream validates the upstream base URL.
func parseUpstream(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("httpproxy: invalid upstream: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("httpproxy: upstream scheme %q must be http or https", parsed.Scheme)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("httpproxy: upstream must be scheme://host[:port][/basepath] without credentials/query")
	}
	return parsed, nil
}

// Stats is the health snapshot of one HTTP proxy.
type Stats struct {
	Requests          uint64
	ReadRequests      uint64
	WritesAllowed     uint64
	WritesDenied      uint64
	LoginOK           uint64
	LoginFailures     uint64
	AuthFailures      uint64
	SourceDenied      uint64
	UpstreamErrors    uint64
	LastError         string
	ListenAddress     string
	State             string
	ActiveConnections int
}

// Proxy is one HTTP(S) reverse proxy listener.
type Proxy struct {
	cfg         Config
	sessions    SessionLookup
	auth        Authenticator
	clock       ports.Clock
	target      *url.URL
	allowed     *allowlist
	transport   *http.Transport
	server      *http.Server
	headerAllow map[string]struct{}

	mu      sync.Mutex
	ln      net.Listener
	state   string
	limiter *loginLimiter

	requests       atomic.Uint64
	reads          atomic.Uint64
	writesAllowed  atomic.Uint64
	writesDenied   atomic.Uint64
	loginOK        atomic.Uint64
	loginFailures  atomic.Uint64
	authFailures   atomic.Uint64
	sourceDenied   atomic.Uint64
	upstreamErrors atomic.Uint64

	errMu   sync.Mutex
	lastErr string
}

// New validates the configuration, loads the CA and builds the transport.
func New(cfg Config, sessions SessionLookup, auth Authenticator) (*Proxy, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if sessions == nil {
		return nil, errors.New("httpproxy: session lookup is required (fail-closed)")
	}
	if auth == nil {
		return nil, errors.New("httpproxy: authenticator is required")
	}
	cfg.Timeout = clampTimeout(cfg.Timeout, defaultTimeout)
	if cfg.BodyLimit <= 0 {
		cfg.BodyLimit = defaultBodyLimit
	}
	if cfg.BodyLimit > maxBodyLimit {
		cfg.BodyLimit = maxBodyLimit
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = defaultResponseLimit
	}
	if cfg.MaxResponseBytes > maxResponseLimit {
		cfg.MaxResponseBytes = maxResponseLimit
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	if cfg.SessionTTL > 24*time.Hour {
		cfg.SessionTTL = 24 * time.Hour
	}
	target, err := parseUpstream(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	patternList, err := newAllowlist(cfg.URLAllowlist)
	if err != nil {
		return nil, err
	}
	headerAllow, err := buildHeaderAllowlist(cfg.HeaderAllowlist)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    cfg.Timeout,
		ResponseHeaderTimeout:  cfg.Timeout,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           defaultMaxIdleConns,
		MaxIdleConnsPerHost:    4,
		MaxResponseHeaderBytes: 64 << 10,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
	}
	p := &Proxy{
		cfg:         cfg,
		sessions:    sessions,
		auth:        auth,
		clock:       cfg.Clock,
		target:      target,
		allowed:     patternList,
		transport:   transport,
		headerAllow: headerAllow,
		limiter:     newLoginLimiter(),
		state:       "stopped",
	}
	handler := p.Handler()
	p.server = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.Timeout + 10*time.Second,
		WriteTimeout:      cfg.Timeout + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	return p, nil
}

// buildTLSConfig builds the upstream TLS configuration with certificate pinning.
//
// Policy (review §2.2): InsecureSkipVerify is never used as a blanket switch.
// The chain is only skipped when the operator pinned the exact device
// certificate; the pin is then verified constant-time. Without a pin the
// standard chain verification (CA file or system roots) applies and a
// self-signed device simply fails closed.
func buildTLSConfig(cfg Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	pins, err := parseCertPins(cfg.CertPins)
	if err != nil {
		return nil, err
	}
	if cfg.RequireCertPin && len(pins) == 0 {
		return nil, errors.New("httpproxy: require_cert_pin is set but no cert_pin is configured (device onboarding required)")
	}
	var pool *x509.CertPool
	if cfg.CAFile != "" {
		raw, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("httpproxy: read ca_file: %w", err)
		}
		if len(raw) == 0 || len(raw) > maxCAFileBytes {
			return nil, errors.New("httpproxy: ca_file size out of range")
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("httpproxy: ca_file contains no valid PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	if len(pins) == 0 {
		return tlsConfig, nil
	}
	// Pin configured: skip the default chain check and enforce the pin (plus the
	// CA chain when a CA file is present).
	tlsConfig.InsecureSkipVerify = true
	upstreamHost := ""
	if parsed, err := parseUpstream(cfg.Upstream); err == nil {
		upstreamHost = parsed.Hostname()
	}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("httpproxy: device presented no certificate")
		}
		leaf := state.PeerCertificates[0]
		if pool != nil {
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, DNSName: upstreamHost}); err != nil {
				return fmt.Errorf("httpproxy: device certificate chain invalid: %w", err)
			}
		}
		sum := sha256.Sum256(leaf.Raw)
		for _, pin := range pins {
			if subtle.ConstantTimeCompare(sum[:], pin) == 1 {
				return nil
			}
		}
		return errors.New("httpproxy: device certificate pin mismatch")
	}
	return tlsConfig, nil
}

// parseCertPins validates the configured SHA-256 certificate pins.
func parseCertPins(raw []string) ([][]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > 8 {
		return nil, errors.New("httpproxy: at most 8 certificate pins are supported")
	}
	out := make([][]byte, 0, len(raw))
	for _, entry := range raw {
		clean := strings.ToLower(strings.TrimSpace(entry))
		if len(clean) != 64 {
			return nil, fmt.Errorf("httpproxy: cert_pin %q must be a SHA-256 hex fingerprint", entry)
		}
		pin, err := hex.DecodeString(clean)
		if err != nil || len(pin) != sha256.Size {
			return nil, fmt.Errorf("httpproxy: cert_pin %q is not valid hex", entry)
		}
		out = append(out, pin)
	}
	return out, nil
}

// Handler exposes the proxy handler (tests use httptest).
func (p *Proxy) Handler() http.Handler { return http.HandlerFunc(p.serve) }

// Start binds the listener and serves.
func (p *Proxy) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("httpproxy: nil context")
	}
	p.mu.Lock()
	if p.ln != nil {
		p.mu.Unlock()
		return errors.New("httpproxy: already started")
	}
	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		p.mu.Unlock()
		return fmt.Errorf("httpproxy %q: listen %q: %w", p.cfg.TargetID, p.cfg.Listen, err)
	}
	p.ln = ln
	p.state = "running"
	p.mu.Unlock()
	go func() {
		_ = p.server.Serve(ln)
	}()
	go func() {
		<-ctx.Done()
		_ = p.Close()
	}()
	return nil
}

// Addr returns the bound address ("" before Start).
func (p *Proxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln == nil {
		return ""
	}
	return p.ln.Addr().String()
}

// Close stops the server idempotently.
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.state != "running" {
		p.mu.Unlock()
		return nil
	}
	p.state = "stopped"
	p.mu.Unlock()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := p.server.Shutdown(shutdownCtx); err != nil {
		_ = p.server.Close()
	}
	p.transport.CloseIdleConnections()
	return nil
}

// Stats returns a consistent health snapshot.
func (p *Proxy) Stats() Stats {
	p.mu.Lock()
	listen := ""
	if p.ln != nil {
		listen = p.ln.Addr().String()
	}
	state := p.state
	p.mu.Unlock()
	p.errMu.Lock()
	lastErr := p.lastErr
	p.errMu.Unlock()
	return Stats{
		Requests:       p.requests.Load(),
		ReadRequests:   p.reads.Load(),
		WritesAllowed:  p.writesAllowed.Load(),
		WritesDenied:   p.writesDenied.Load(),
		LoginOK:        p.loginOK.Load(),
		LoginFailures:  p.loginFailures.Load(),
		AuthFailures:   p.authFailures.Load(),
		SourceDenied:   p.sourceDenied.Load(),
		UpstreamErrors: p.upstreamErrors.Load(),
		LastError:      lastErr,
		ListenAddress:  listen,
		State:          state,
	}
}

func (p *Proxy) recordError(message string) {
	if len(message) > 240 {
		message = message[:240]
	}
	p.errMu.Lock()
	p.lastErr = message
	p.errMu.Unlock()
}

// now returns the injected clock time in UTC.
func (p *Proxy) now() time.Time {
	if p.clock != nil {
		return p.clock.Now().UTC()
	}
	return time.Now().UTC()
}

// clampTimeout bounds a configured timeout.
func clampTimeout(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	if value > 60*time.Second {
		return 60 * time.Second
	}
	return value
}

// buildHeaderAllowlist validates the outbound header allowlist. Credentials and
// forwarding headers can never be allowlisted.
func buildHeaderAllowlist(configured []string) (map[string]struct{}, error) {
	defaults := []string{
		"User-Agent", "Accept", "Accept-Language", "Content-Type",
		"Range", "If-None-Match", "If-Modified-Since",
	}
	list := configured
	if len(list) == 0 {
		list = defaults
	}
	out := make(map[string]struct{}, len(list))
	sensitive := map[string]struct{}{
		"authorization": {}, "proxy-authorization": {}, "cookie": {}, "set-cookie": {},
		"x-forwarded-for": {}, "x-forwarded-host": {}, "x-forwarded-proto": {},
		"forwarded": {}, "x-real-ip": {}, "connection": {}, "transfer-encoding": {},
		"upgrade": {}, "proxy-connection": {}, "keep-alive": {}, "te": {}, "trailer": {},
	}
	for _, raw := range list {
		name := strings.TrimSpace(raw)
		if name == "" || len(name) > 64 || strings.ContainsAny(name, " \t\r\n:") {
			return nil, fmt.Errorf("httpproxy: invalid header allowlist entry %q", raw)
		}
		lower := strings.ToLower(name)
		if _, forbidden := sensitive[lower]; forbidden {
			return nil, fmt.Errorf("httpproxy: header %q must never be forwarded", name)
		}
		out[lower] = struct{}{}
	}
	return out, nil
}
