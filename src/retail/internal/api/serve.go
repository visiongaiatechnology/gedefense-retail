package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// serve dispatches one request: static UI or authenticated API endpoint.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	recorder, ok := w.(*statusRecorder)
	if !ok {
		recorder = &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	}
	if !strings.HasPrefix(r.URL.Path, apiPrefix) {
		s.serveStatic(recorder, r)
		return
	}

	matched, routeParams, allowed := matchRoute(s.routes(), r.Method, r.URL.Path)
	if matched == nil {
		if len(allowed) > 0 {
			recorder.Header().Set("Allow", strings.Join(allowed, ", "))
			s.fail(recorder, r, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		s.fail(recorder, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}

	if matched.setup {
		s.serveSetup(recorder, r, matched, routeParams)
		return
	}

	ident, authenticated := s.authenticate(r)
	key := "ip:" + clientIP(r)
	if authenticated {
		key = "token:" + ident.tokenHash
	}
	if allowedNow, retryAfter := s.limiter.allow(key); !allowedNow {
		recorder.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		s.fail(recorder, r, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}

	if !matched.public && !authenticated {
		recorder.Header().Set("WWW-Authenticate", `Bearer realm="gedefense-retail"`)
		s.fail(recorder, r, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	if matched.minRole != "" {
		if !authenticated || !ident.Role.Allows(matched.minRole) {
			s.fail(recorder, r, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
	}
	if authenticated {
		r = r.WithContext(withIdentity(r.Context(), ident))
	}
	matched.handler(recorder, r, routeParams, ident)
}

// collectorHealth returns the collector snapshot, tolerating a nil provider.
func (s *Server) collectorHealth() []ports.CollectorHealth {
	if s.deps.Collectors == nil {
		return []ports.CollectorHealth{}
	}
	health := s.deps.Collectors()
	if health == nil {
		return []ports.CollectorHealth{}
	}
	return health
}

// pathParam returns a path wildcard value.
func pathParam(p params, name string) string { return p[name] }

// defaultSiteID returns the configured site of a single-site gateway.
func (s *Server) defaultSiteID() domain.SiteID {
	sites := s.deps.Sites.Sites()
	if len(sites) == 1 {
		return sites[0].SiteID
	}
	return ""
}
