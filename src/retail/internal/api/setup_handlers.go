package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Setup request bodies.
type setupLanguageBody struct {
	Language string `json:"language"`
}
type setupSiteBody struct {
	SiteID   domain.SiteID `json:"site_id"`
	Name     string        `json:"name"`
	Country  string        `json:"country,omitempty"`
	Timezone string        `json:"timezone,omitempty"`
	Zones    []domain.Zone `json:"zones"`
}
type setupWhitelistBody struct {
	CIDRs []string `json:"cidrs"`
}
type setupAdminBody struct {
	UserID domain.UserID `json:"user_id"`
	Name   string        `json:"name"`
}
type setupCollectorsBody struct {
	Adapters []string `json:"adapters"`
}

// maxSetupBody bounds the wizard request bodies (contract §5: 64 KiB).
const maxSetupBody = 64 << 10

// decodeSetupBody strictly decodes the setup payload within the 64 KiB budget.
func (s *Server) decodeSetupBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.ContentLength > maxSetupBody {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "request body exceeds 64 KiB")
		return false
	}
	return s.decodeJSON(w, r, dst)
}

// handleSetupState serves GET /api/v1/setup/state. Every call issues a fresh
// setup session (F-SW-01/F-SW-06) that the POST steps must present.
func (s *Server) handleSetupState(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	if s.setup == nil {
		s.fail(w, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if s.setup.Completed() {
		s.fail(w, r, http.StatusNotFound, "not_found", "setup already completed")
		return
	}
	token, err := s.setup.IssueSession(s.setup.Now())
	if err != nil {
		s.logger.Error("setup session issue failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	state := s.setup.state(clientIP(r))
	state.SetupSession = token
	s.respondJSON(w, r, http.StatusOK, state)
}

// handleSetupLanguage serves POST /api/v1/setup/language.
func (s *Server) handleSetupLanguage(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	if !s.requireSetupSession(w, r) {
		return
	}
	var body setupLanguageBody
	if !s.decodeSetupBody(w, r, &body) {
		return
	}
	if err := s.setup.SetLanguage(r.Context(), body.Language); err != nil {
		s.failSetup(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, s.setup.state(clientIP(r)))
}

// handleSetupSite serves POST /api/v1/setup/site.
func (s *Server) handleSetupSite(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	if !s.requireSetupSession(w, r) {
		return
	}
	var body setupSiteBody
	if !s.decodeSetupBody(w, r, &body) {
		return
	}
	zones := body.Zones
	if zones == nil {
		zones = []domain.Zone{}
	}
	site := domain.Site{SiteID: body.SiteID, Name: body.Name, Country: body.Country, Timezone: body.Timezone,
		Status: domain.SiteUnknown, Zones: zones, Tags: []string{}}
	if err := s.setup.SetSite(r.Context(), site); err != nil {
		s.failSetup(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, s.setup.state(clientIP(r)))
}

// handleSetupWhitelist serves POST /api/v1/setup/whitelist.
func (s *Server) handleSetupWhitelist(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	if !s.requireSetupSession(w, r) {
		return
	}
	var body setupWhitelistBody
	if !s.decodeSetupBody(w, r, &body) {
		return
	}
	if err := s.setup.SetWhitelist(r.Context(), body.CIDRs); err != nil {
		s.failSetup(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, s.setup.state(clientIP(r)))
}

// handleSetupAdmin serves POST /api/v1/setup/admin. The token is returned once.
func (s *Server) handleSetupAdmin(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	if !s.requireSetupSession(w, r) {
		return
	}
	var body setupAdminBody
	if !s.decodeSetupBody(w, r, &body) {
		return
	}
	token, hash, err := s.setup.SetAdmin(r.Context(), string(body.UserID), body.Name)
	if err != nil {
		s.failSetup(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, map[string]string{"user_id": string(body.UserID), "token": token, "token_sha256": hash})
}

// handleSetupCollectors serves POST /api/v1/setup/collectors.
func (s *Server) handleSetupCollectors(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	if !s.requireSetupSession(w, r) {
		return
	}
	var body setupCollectorsBody
	if !s.decodeSetupBody(w, r, &body) {
		return
	}
	if err := s.setup.SetCollectors(r.Context(), body.Adapters); err != nil {
		s.failSetup(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, s.setup.state(clientIP(r)))
}

// handleSetupComplete serves POST /api/v1/setup/complete.
func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	if !s.requireSetupSession(w, r) {
		return
	}
	result, err := s.setup.Complete(r.Context())
	if err != nil {
		s.failSetup(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, result)
}

// failSetup maps setup errors onto the fixed API error codes.
func (s *Server) failSetup(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrSetupIncomplete):
		s.fail(w, r, http.StatusConflict, "conflict", "setup is incomplete: admin and whitelist are required")
	case errors.Is(err, ErrSetupDisabled):
		s.fail(w, r, http.StatusNotFound, "not_found", "setup already completed")
	case errors.Is(err, ErrAdminExists):
		// F-SW-03: no second token, no hash change, no secret in the response.
		s.fail(w, r, http.StatusConflict, "admin_exists", "admin already configured")
	case errors.Is(err, ErrSetupAudit):
		s.logger.Error("setup audit failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
	case errors.Is(err, ErrSetupInvalid):
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "invalid setup input")
	default:
		s.logger.Error("setup step failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
	}
}

// serveSetup handles a wizard route: only loopback, only while incomplete, and
// only for same-origin loopback requests with an allowed Host (F-SW-01). Every
// wizard request is rate limited in its own bucket (F-SW-06).
func (s *Server) serveSetup(w http.ResponseWriter, r *http.Request, matched *route, routeParams params) {
	if s.setup == nil || s.setup.Completed() {
		s.fail(w, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	addr, loopback := s.setupLoopback(r)
	if !loopback {
		s.denyIP(w, r, addr)
		return
	}
	if !s.setupHostOK(r) || !s.setupOriginOK(r) || !s.setupFetchSiteOK(r) {
		s.fail(w, r, http.StatusForbidden, "forbidden", "request denied")
		return
	}
	if allowedNow, retryAfter := s.setupLimiter.allow("setup:" + clientIP(r)); !allowedNow {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		s.fail(w, r, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}
	matched.handler(w, r, routeParams, identity{})
}

// containsLang reports wizard language membership.
func containsLang(list []string, value string) bool {
	for _, candidate := range list {
		if candidate == value {
			return true
		}
	}
	return false
}
