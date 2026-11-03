package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/policy"
)

// policyVersionSummary is the operator-visible version row.
type policyVersionSummary struct {
	Version   int           `json:"version"`
	UpdatedAt time.Time     `json:"updated_at"`
	UpdatedBy domain.UserID `json:"updated_by,omitempty"`
	Reason    string        `json:"reason"`
	Hash      string        `json:"hash"`
}

// policiesResponse is the policy payload.
type policiesResponse struct {
	Current  domain.Policy          `json:"current"`
	Versions []policyVersionSummary `json:"versions"`
}

// handlePolicies serves GET /api/v1/policies.
func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	q := parseQuery(r, "site_id")
	siteID := domain.SiteID(q.idValue("site_id", validateSiteID))
	if !s.checkQuery(w, r, q) {
		return
	}
	if siteID != "" && siteID != s.deps.Policy.Site() {
		s.fail(w, r, http.StatusNotFound, "not_found", "site not found")
		return
	}
	versions := s.deps.Policy.Versions(0)
	summaries := make([]policyVersionSummary, 0, len(versions))
	for _, record := range versions {
		summaries = append(summaries, policyVersionSummary{
			Version:   record.Policy.Version,
			UpdatedAt: record.Policy.UpdatedAt,
			UpdatedBy: record.Policy.UpdatedBy,
			Reason:    record.Policy.Reason,
			Hash:      record.Policy.Hash,
		})
	}
	s.respondJSON(w, r, http.StatusOK, policiesResponse{Current: s.deps.Policy.Current(), Versions: summaries})
}

// policyVersionResponse wraps one stored policy version.
type policyVersionResponse struct {
	Version domain.PolicyVersion `json:"version"`
}

// handlePolicyVersion serves GET /api/v1/policies/{site_id}/versions/{version}.
func (s *Server) handlePolicyVersion(w http.ResponseWriter, r *http.Request, p params, _ identity) {
	siteID := domain.SiteID(pathParam(p, "site_id"))
	if err := siteID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "site_id is not a valid identifier")
		return
	}
	version, err := strconv.Atoi(pathParam(p, "version"))
	if err != nil || version < 1 {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "version must be a positive integer")
		return
	}
	if siteID != s.deps.Policy.Site() {
		s.fail(w, r, http.StatusNotFound, "not_found", "policy version not found")
		return
	}
	record, ok := s.deps.Policy.Get(version)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "not_found", "policy version not found")
		return
	}
	s.respondJSON(w, r, http.StatusOK, policyVersionResponse{Version: record})
}

// handlePolicyReload serves POST /api/v1/policies/reload.
func (s *Server) handlePolicyReload(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	record, err := s.deps.Policy.Reload()
	if err != nil {
		switch {
		case errors.Is(err, policy.ErrNoPolicyFile):
			s.fail(w, r, http.StatusBadRequest, "invalid_request", "policy.json does not exist")
		case errors.Is(err, policy.ErrCorruptState):
			s.fail(w, r, http.StatusConflict, "conflict", "persisted policy history is inconsistent")
		default:
			s.logger.Error("policy reload failed", "request_id", requestID(r), "error", err)
			s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		}
		return
	}
	s.respondJSON(w, r, http.StatusOK, policyVersionResponse{Version: record})
}

// auditResponse is the audit payload.
type auditResponse struct {
	Items            []domain.AuditEntry `json:"items"`
	ChainOK          bool                `json:"chain_ok"`
	FirstVerifiedSeq uint64              `json:"first_verified_seq"`
	// CheckedAt is when the (cached) chain verification ran.
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

// handleAudit serves GET /api/v1/audit.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	q := parseQuery(r, "limit")
	limit := q.intValue("limit", defaultListLimit, 1, maxListLimit)
	if !s.checkQuery(w, r, q) {
		return
	}
	entries, err := s.deps.Audit.List(r.Context(), limit)
	if err != nil {
		s.logger.Error("audit list failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if entries == nil {
		entries = []domain.AuditEntry{}
	}
	// The chain verification is cached (see auditcache.go): listing entries is
	// already O(limit), re-hashing the whole chain per request adds no value.
	chain := s.auditChain.Status(r.Context())
	if chain.Err != nil {
		s.logger.Error("audit verify failed", "request_id", requestID(r), "error", chain.Err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	firstSeq := uint64(1)
	if chain.OK {
		if chain.FirstSeq > 0 {
			firstSeq = chain.FirstSeq
		}
	} else {
		firstSeq = chain.BadSeq
	}
	s.respondJSON(w, r, http.StatusOK, auditResponse{
		Items:            entries,
		ChainOK:          chain.OK,
		FirstVerifiedSeq: firstSeq,
		CheckedAt:        chain.CheckedAt,
	})
}
