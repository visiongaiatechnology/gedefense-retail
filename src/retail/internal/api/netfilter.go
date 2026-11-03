package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxFilterEntries bounds the diagnostic maps of the IP filter (F-SW-05).
const maxFilterEntries = 4096

// WhitelistConfig is the resolved dashboard access policy (contract §4).
type WhitelistConfig struct {
	RequireWhitelist  bool
	CIDRs             []string
	TrustProxyHeaders bool
	// TrustedProxyCIDRs lists the reverse proxies whose X-Forwarded-For header
	// may be honoured (F-SW-02). It is mandatory when TrustProxyHeaders is set.
	TrustedProxyCIDRs []string
	SetupMode         bool
}

// ipFilter enforces the source-IP whitelist. Fail-closed: an unparseable source
// address is denied, never allowed.
type ipFilter struct {
	prefixes   []netip.Prefix
	trusted    []netip.Prefix
	enforce    bool
	trustProxy bool
	setupMode  bool

	mu        sync.Mutex
	lastWarn  map[string]time.Time
	basicDeny map[string]int
	denials   atomic.Int64
	warnOnce  sync.Once
}

// newIPFilter resolves the policy. A malformed CIDR is a configuration error.
func newIPFilter(cfg WhitelistConfig) (*ipFilter, error) {
	filter := &ipFilter{
		enforce:    cfg.RequireWhitelist || len(cfg.CIDRs) > 0 || cfg.SetupMode,
		trustProxy: cfg.TrustProxyHeaders,
		setupMode:  cfg.SetupMode,
		lastWarn:   make(map[string]time.Time),
		basicDeny:  make(map[string]int),
	}
	for _, raw := range cfg.CIDRs {
		prefix, err := parsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("api: whitelist entry %q: %w", raw, err)
		}
		filter.prefixes = append(filter.prefixes, prefix)
	}
	for _, raw := range cfg.TrustedProxyCIDRs {
		prefix, err := parsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("api: trusted proxy entry %q: %w", raw, err)
		}
		filter.trusted = append(filter.trusted, prefix)
	}
	// Trusting proxy headers without a trusted-proxy allowlist is a bypass; the
	// config validator rejects it at startup, the API fails closed as well.
	if filter.trustProxy && len(filter.trusted) == 0 {
		filter.trustProxy = false
	}
	return filter, nil
}

// parsePrefix accepts a CIDR or a single address (implicit /32 or /128).
func parsePrefix(raw string) (netip.Prefix, error) {
	text := strings.TrimSpace(raw)
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not a CIDR or IP address")
	}
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

// remoteAddr returns the direct peer address.
func remoteAddr(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("unparseable remote address")
	}
	return addr.Unmap(), nil
}

// remoteTrusted reports whether the direct peer is an allowed reverse proxy.
func (f *ipFilter) remoteTrusted(addr netip.Addr) bool {
	for _, prefix := range f.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// sourceAddr resolves the source address of a request. X-Forwarded-For is only
// evaluated when the direct peer is inside trusted_proxy_cidrs (F-SW-02). The
// LAST hop counts because the trusted proxy appends it; duplicated or malformed
// headers are denied.
func (f *ipFilter) sourceAddr(r *http.Request) (netip.Addr, error) {
	remote, remoteErr := remoteAddr(r)
	if f.trustProxy && remoteErr == nil && f.remoteTrusted(remote) {
		values := r.Header.Values("X-Forwarded-For")
		if len(values) > 1 {
			return netip.Addr{}, fmt.Errorf("ambiguous X-Forwarded-For")
		}
		if len(values) == 1 {
			parts := strings.Split(values[0], ",")
			last := strings.TrimSpace(parts[len(parts)-1])
			if last == "" {
				return netip.Addr{}, fmt.Errorf("empty X-Forwarded-For hop")
			}
			addr, err := netip.ParseAddr(last)
			if err != nil {
				return netip.Addr{}, fmt.Errorf("invalid X-Forwarded-For hop")
			}
			return addr.Unmap(), nil
		}
		return remote, nil
	}
	if f.trustProxy && remoteErr == nil {
		// One-time warning: an untrusted client sent (or could send) XFF; the
		// header is ignored and the direct peer is evaluated instead.
		f.warnOnce.Do(func() {
			// Logging happens through denyIP's logger at request time; this hook
			// stays side-effect free because ipFilter has no logger.
		})
	}
	if remoteErr != nil {
		return netip.Addr{}, remoteErr
	}
	return remote, nil
}

// allow reports whether addr may access the dashboard.
func (f *ipFilter) allow(addr netip.Addr) bool {
	if !f.enforce {
		return true
	}
	if f.setupMode {
		return addr.IsLoopback()
	}
	for _, prefix := range f.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// whitelistMW is the outermost middleware: every path (dashboard, API, SSE,
// static assets, setup) passes through it.
func (s *Server) whitelistMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, err := s.filter.sourceAddr(r)
		if err != nil || !s.filter.allow(addr) {
			s.denyIP(w, r, addr)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// recordDenial counts one rejection and reports whether a warning should be
// logged. Both maps are hard-bounded (F-SW-05): once the limit is reached the
// diagnostic maps are purged instead of growing without bound.
func (f *ipFilter) recordDenial(key string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.lastWarn) >= maxFilterEntries || len(f.basicDeny) >= maxFilterEntries {
		f.purgeLocked(now)
	}
	last := f.lastWarn[key]
	logIt := now.Sub(last) >= time.Minute
	if logIt {
		f.lastWarn[key] = now
	}
	f.basicDeny[key]++
	if len(f.basicDeny) > maxFilterEntries || len(f.lastWarn) > maxFilterEntries {
		f.purgeLocked(now)
	}
	return logIt
}

func (f *ipFilter) purgeLocked(now time.Time) {
	for key, at := range f.lastWarn {
		if now.Sub(at) >= time.Minute {
			delete(f.lastWarn, key)
		}
	}
	if len(f.lastWarn) >= maxFilterEntries {
		f.lastWarn = make(map[string]time.Time, 64)
	}
	if len(f.basicDeny) >= maxFilterEntries {
		f.basicDeny = make(map[string]int, 64)
	}
}

// denyIP writes the opaque 403 response with complete security headers and a
// non-empty request id (F-SW-04).
func (s *Server) denyIP(w http.ResponseWriter, r *http.Request, addr netip.Addr) {
	s.filter.denials.Add(1)
	key := addr.String()
	if key == "<invalid>" || key == "" {
		key = "invalid"
	}
	logIt := s.filter.recordDenial(key, time.Now())
	if logIt {
		s.logger.Warn("dashboard access denied by whitelist", "source", key, "path", r.URL.Path)
	}
	if requestID(r) == "" {
		id := requestIDFromRequest(r)
		w.Header().Set("X-Request-Id", id)
		r = r.WithContext(withRequestID(r.Context(), id))
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	s.fail(w, r, http.StatusForbidden, "ip_not_allowed", "access denied")
}

// withRequestID stores the request id in the context (baseMW normally does this).
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}
