package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// params are the path wildcards of a matched route.
type params map[string]string

// apiSession is one authenticated management session.
type apiSession struct {
	TokenHash string
	User      domain.GateUser
	MFAOK     bool
	ExpiresAt time.Time
}

// handlerFunc is the signature of a gate API handler.
type handlerFunc func(w http.ResponseWriter, r *http.Request, p params, session apiSession)

// segment is one path element: literal or wildcard.
type segment struct {
	literal string
	name    string
}

// route is one method + path pattern with its role requirement.
type route struct {
	method     string
	segs       []segment
	roles      []domain.GateRole
	public     bool
	login      bool
	idempotent bool
	handler    handlerFunc
}

// seg builds a path segment; a leading ':' marks a wildcard.
func seg(pattern string) segment {
	if strings.HasPrefix(pattern, ":") {
		return segment{name: strings.TrimPrefix(pattern, ":")}
	}
	return segment{literal: pattern}
}

// routeSegs builds the segment list of a route pattern.
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

// routes is the complete gate API route table.
func (s *Server) routes() []route {
	readRoles := []domain.GateRole{domain.GateRoleApprover, domain.GateRoleMasterAdmin, domain.GateRoleAuditor}
	vendorRoles := []domain.GateRole{domain.GateRoleVendorRead, domain.GateRoleVendorWriteRequester}
	allRead := append(append([]domain.GateRole{}, readRoles...), vendorRoles...)
	requester := []domain.GateRole{domain.GateRoleVendorWriteRequester}
	approvers := []domain.GateRole{domain.GateRoleApprover, domain.GateRoleMasterAdmin}
	master := []domain.GateRole{domain.GateRoleMasterAdmin}

	return []route{
		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/health"), public: true, handler: s.handleHealth},
		{method: http.MethodPost, segs: routeSegs("/api/v1/gate/auth/login"), public: true, login: true, handler: s.handleLogin},
		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/auth/me"), handler: s.handleMe},
		{method: http.MethodPost, segs: routeSegs("/api/v1/gate/auth/logout"), handler: s.handleLogout},

		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/status"), roles: readRoles, handler: s.handleStatus},
		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/integrity"), roles: readRoles, handler: s.handleIntegrity},
		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/plans"), roles: allRead, handler: s.handlePlans},
		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/plans/:plan_id"), roles: allRead, handler: s.handlePlan},
		{method: http.MethodPost, segs: routeSegs("/api/v1/gate/plans"), roles: requester, idempotent: true, handler: s.handleCreatePlan},
		{method: http.MethodPost, segs: routeSegs("/api/v1/gate/plans/:plan_id/approve"), roles: approvers, handler: s.handleApprove},
		{method: http.MethodPost, segs: routeSegs("/api/v1/gate/plans/:plan_id/reject"), roles: approvers, handler: s.handleReject},
		{method: http.MethodPost, segs: routeSegs("/api/v1/gate/plans/:plan_id/cancel"), roles: requester, handler: s.handleCancel},

		{method: http.MethodPost, segs: routeSegs("/api/v1/gate/sessions"), roles: requester, idempotent: true, handler: s.handleCreateSession},
		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/sessions"), roles: readRoles, handler: s.handleSessions},
		{method: http.MethodDelete, segs: routeSegs("/api/v1/gate/sessions/:session_id"), roles: approvers, handler: s.handleRevokeSession},

		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/denies"), roles: readRoles, handler: s.handleDenies},
		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/audit"), roles: readRoles, handler: s.handleAudit},
		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/policy"), roles: readRoles, handler: s.handlePolicy},
		{method: http.MethodPost, segs: routeSegs("/api/v1/gate/policy/reload"), roles: master, handler: s.handlePolicyReload},
		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/escalations"), roles: approvers, handler: s.handleEscalations},
		{method: http.MethodPost, segs: routeSegs("/api/v1/gate/escalations/:notification_id/ack"), roles: approvers, handler: s.handleEscalationAck},
		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/users"), roles: master, handler: s.handleUsers},
		{method: http.MethodPost, segs: routeSegs("/api/v1/gate/notify/test"), roles: master, handler: s.handleNotifyTest},
		{method: http.MethodGet, segs: routeSegs("/api/v1/gate/stream"), handler: s.handleStream},
	}
}

// matchRoute finds the route for method + path.
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

// matchSegments matches a pattern against the request path parts.
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

// pathParam returns a path wildcard value.
func pathParam(p params, name string) string { return p[name] }
