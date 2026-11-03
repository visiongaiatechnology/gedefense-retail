package api

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// setupAllowedHost reports whether the request Host is one of the loopback
// names bound to the listener port (F-SW-01: DNS-rebinding defence).
func (s *Server) setupAllowedHost(host string) bool {
	port := s.setup.ListenPort()
	allowed := []string{"127.0.0.1:" + port, "localhost:" + port, "[::1]:" + port}
	for _, candidate := range allowed {
		if strings.EqualFold(host, candidate) {
			return true
		}
	}
	return false
}

// setupHostOK validates the Host header.
func (s *Server) setupHostOK(r *http.Request) bool {
	return s.setupAllowedHost(strings.TrimSpace(r.Host))
}

// setupOriginOK validates an optional Origin header: it must be the exact
// same-origin loopback URL (F-SW-01). Absent Origin is accepted (simple GET).
func (s *Server) setupOriginOK(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" {
		return false
	}
	return s.setupAllowedHost(parsed.Host)
}

// setupFetchSiteOK rejects cross-site browser fetches (F-SW-01).
func (s *Server) setupFetchSiteOK(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "", "same-origin", "none":
		return true
	default:
		return false
	}
}

// setupLoopback reports whether the (whitelisted) source is loopback.
func (s *Server) setupLoopback(r *http.Request) (netip.Addr, bool) {
	addr, err := s.filter.sourceAddr(r)
	if err != nil || !addr.IsLoopback() {
		return addr, false
	}
	return addr, true
}

// requireSetupSession enforces the setup session header on every POST (F-SW-01).
func (s *Server) requireSetupSession(w http.ResponseWriter, r *http.Request) bool {
	token := strings.TrimSpace(r.Header.Get("X-Setup-Session"))
	if token == "" || s.setup == nil || !s.setup.VerifySession(token, s.setup.Now()) {
		s.fail(w, r, http.StatusForbidden, "setup_session_invalid", "invalid or expired setup session")
		return false
	}
	return true
}

// isLoopbackHostname is used by tests to document the accepted Host shapes.
func isLoopbackHostname(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// hostPort splits a Host header without requiring a valid port.
func hostPort(host string) (string, string) {
	split, port, err := net.SplitHostPort(host)
	if err != nil {
		return host, ""
	}
	return split, port
}
