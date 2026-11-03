package api

import (
	"net/http"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/config"
)

// params are the path wildcards of a matched route.
type params map[string]string

// handlerFunc is the signature of every API handler.
type handlerFunc func(w http.ResponseWriter, r *http.Request, p params, ident identity)

// segment is one path element of a route: either a literal or a wildcard.
type segment struct {
	literal string
	name    string
}

// route is one method + path pattern of the HTTP contract.
type route struct {
	method  string
	segs    []segment
	minRole config.Role
	public  bool
	setup   bool
	handler handlerFunc
}

// seg builds a path segment; a leading ':' marks a wildcard.
func seg(pattern string) segment {
	if strings.HasPrefix(pattern, ":") {
		return segment{name: strings.TrimPrefix(pattern, ":")}
	}
	return segment{literal: pattern}
}

// path builds the segment list of a route pattern.
func routeSegs(pattern string) []segment {
	trimmed := strings.Trim(pattern, "/")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "/")
	segs := make([]segment, len(parts))
	for i, part := range parts {
		segs[i] = seg(part)
	}
	return segs
}

// routes is the complete v1 route table. Every endpoint of the contract is
// registered exactly once.
func (s *Server) routes() []route {
	return []route{
		// 2. Health, meta, overview.
		{method: http.MethodGet, segs: routeSegs("/api/v1/health"), public: true, handler: s.handleHealth},
		{method: http.MethodGet, segs: routeSegs("/api/v1/meta"), minRole: config.RoleViewer, handler: s.handleMeta},
		{method: http.MethodGet, segs: routeSegs("/api/v1/overview"), minRole: config.RoleViewer, handler: s.handleOverview},

		// 3. Sites and assets.
		{method: http.MethodGet, segs: routeSegs("/api/v1/sites"), minRole: config.RoleViewer, handler: s.handleSites},
		{method: http.MethodGet, segs: routeSegs("/api/v1/sites/:site_id"), minRole: config.RoleViewer, handler: s.handleSite},
		{method: http.MethodGet, segs: routeSegs("/api/v1/assets"), minRole: config.RoleViewer, handler: s.handleAssets},
		{method: http.MethodGet, segs: routeSegs("/api/v1/assets/:asset_id"), minRole: config.RoleViewer, handler: s.handleAsset},

		// 4. Alert workflow.
		{method: http.MethodGet, segs: routeSegs("/api/v1/alerts"), minRole: config.RoleViewer, handler: s.handleAlerts},
		{method: http.MethodGet, segs: routeSegs("/api/v1/alerts/:alert_id"), minRole: config.RoleViewer, handler: s.handleAlert},
		{method: http.MethodPost, segs: routeSegs("/api/v1/alerts/:alert_id/ack"), minRole: config.RoleOperator, handler: s.handleAlertAck},
		{method: http.MethodPost, segs: routeSegs("/api/v1/alerts/:alert_id/assign"), minRole: config.RoleOperator, handler: s.handleAlertAssign},
		{method: http.MethodPost, segs: routeSegs("/api/v1/alerts/:alert_id/close"), minRole: config.RoleOperator, handler: s.handleAlertClose},

		// 5. Cold chain and data quality.
		{method: http.MethodGet, segs: routeSegs("/api/v1/coldchain"), minRole: config.RoleViewer, handler: s.handleColdChain},
		{method: http.MethodGet, segs: routeSegs("/api/v1/data-quality"), minRole: config.RoleViewer, handler: s.handleDataQuality},

		// 6. Access and maintenance windows.
		{method: http.MethodGet, segs: routeSegs("/api/v1/access"), minRole: config.RoleViewer, handler: s.handleAccess},
		{method: http.MethodPost, segs: routeSegs("/api/v1/windows"), minRole: config.RoleAdmin, handler: s.handleWindowCreate},
		{method: http.MethodPost, segs: routeSegs("/api/v1/windows/:window_id/close"), minRole: config.RoleAdmin, handler: s.handleWindowClose},

		// 7. Timeline, integrity, incidents.
		{method: http.MethodGet, segs: routeSegs("/api/v1/timeline"), minRole: config.RoleViewer, handler: s.handleTimeline},
		{method: http.MethodGet, segs: routeSegs("/api/v1/integrity"), minRole: config.RoleViewer, handler: s.handleIntegrity},
		{method: http.MethodGet, segs: routeSegs("/api/v1/incidents"), minRole: config.RoleViewer, handler: s.handleIncidents},
		{method: http.MethodGet, segs: routeSegs("/api/v1/incidents/:incident_id"), minRole: config.RoleViewer, handler: s.handleIncident},
		{method: http.MethodPost, segs: routeSegs("/api/v1/incidents/:incident_id/note"), minRole: config.RoleOperator, handler: s.handleIncidentNote},
		{method: http.MethodGet, segs: routeSegs("/api/v1/incidents/:incident_id/export"), minRole: config.RoleViewer, handler: s.handleIncidentExport},

		// 8. Policy, audit, collectors.
		{method: http.MethodGet, segs: routeSegs("/api/v1/policies"), minRole: config.RoleViewer, handler: s.handlePolicies},
		{method: http.MethodGet, segs: routeSegs("/api/v1/policies/:site_id/versions/:version"), minRole: config.RoleViewer, handler: s.handlePolicyVersion},
		{method: http.MethodPost, segs: routeSegs("/api/v1/policies/reload"), minRole: config.RoleAdmin, handler: s.handlePolicyReload},
		{method: http.MethodGet, segs: routeSegs("/api/v1/audit"), minRole: config.RoleViewer, handler: s.handleAudit},
		{method: http.MethodGet, segs: routeSegs("/api/v1/collectors"), minRole: config.RoleViewer, handler: s.handleCollectors},

		// 9. Live stream.
		{method: http.MethodGet, segs: routeSegs("/api/v1/stream"), minRole: config.RoleViewer, handler: s.handleStream},

		// Setup wizard (loopback only, disabled once completed).
		{method: http.MethodGet, segs: routeSegs("/api/v1/setup/state"), setup: true, handler: s.handleSetupState},
		{method: http.MethodPost, segs: routeSegs("/api/v1/setup/language"), setup: true, handler: s.handleSetupLanguage},
		{method: http.MethodPost, segs: routeSegs("/api/v1/setup/site"), setup: true, handler: s.handleSetupSite},
		{method: http.MethodPost, segs: routeSegs("/api/v1/setup/whitelist"), setup: true, handler: s.handleSetupWhitelist},
		{method: http.MethodPost, segs: routeSegs("/api/v1/setup/admin"), setup: true, handler: s.handleSetupAdmin},
		{method: http.MethodPost, segs: routeSegs("/api/v1/setup/collectors"), setup: true, handler: s.handleSetupCollectors},
		{method: http.MethodPost, segs: routeSegs("/api/v1/setup/complete"), setup: true, handler: s.handleSetupComplete},

		// 10. Simulator ingest. The handler performs the full guard chain itself
		// (simulation flag, loopback peer, sim header, admin token) and answers 404
		// when any guard fails, so the route cannot be used as an oracle.
		{method: http.MethodPost, segs: routeSegs("/api/v1/dev/events"), public: true, handler: s.handleDevEvents},
	}
}

// matchRoute finds the route for method + path. It returns the allowed methods
// when the path exists under a different method.
func matchRoute(routes []route, method, rawPath string) (*route, params, []string) {
	requestParts := splitPath(rawPath)
	var allowed []string
	for i := range routes {
		values, ok := matchSegments(routes[i].segs, requestParts)
		if !ok {
			continue
		}
		if routes[i].method == method {
			return &routes[i], values, nil
		}
		allowed = append(allowed, routes[i].method)
	}
	return nil, nil, allowed
}

// matchSegments matches one route pattern against the request path parts.
func matchSegments(pattern, request []segment) (params, bool) {
	if len(pattern) != len(request) {
		return nil, false
	}
	values := make(params, 2)
	for i := range pattern {
		switch {
		case pattern[i].name != "":
			values[pattern[i].name] = request[i].literal
		case pattern[i].literal != request[i].literal:
			return nil, false
		}
	}
	return values, true
}

// splitPath splits a URL path into its non-empty parts.
func splitPath(rawPath string) []segment {
	trimmed := strings.Trim(rawPath, "/")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "/")
	out := make([]segment, len(parts))
	for i, part := range parts {
		out[i] = segment{literal: part}
	}
	return out
}
