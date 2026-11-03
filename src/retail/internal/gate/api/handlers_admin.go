package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/approval"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
)

// failsafeView is the fail-safe block of health/status.
type failsafeView struct {
	Active bool   `json:"active"`
	Reason string `json:"reason"`
}

// healthView is the public health payload.
type healthView struct {
	Status       string                `json:"status"`
	Product      string                `json:"product"`
	Version      string                `json:"version"`
	Now          time.Time             `json:"now"`
	UptimeS      int64                 `json:"uptime_s"`
	AuditChainOK bool                  `json:"audit_chain_ok"`
	Targets      []config.TargetStatus `json:"targets"`
	Failsafe     failsafeView          `json:"failsafe"`
}

// handleHealth serves GET /api/v1/gate/health (no auth).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, _ params, _ apiSession) {
	chainOK := s.audit.chainOK(r.Context())
	active, reason := s.failsafeState()
	status := "ok"
	if !chainOK || active {
		status = "degraded"
	}
	s.respondJSON(w, r, http.StatusOK, healthView{
		Status:       status,
		Product:      s.deps.Info.Product,
		Version:      s.deps.Info.Version,
		Now:          s.now(),
		UptimeS:      int64(time.Since(s.started).Seconds()),
		AuditChainOK: chainOK,
		Targets:      s.targetStatus(),
		Failsafe:     failsafeView{Active: active, Reason: reason},
	})
}

// policyView is the policy metadata block of the status payload.
type policyView struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// statusView is the management status payload.
type statusView struct {
	Plans    approval.PlanCounts    `json:"plans"`
	Sessions approval.SessionCounts `json:"sessions"`
	Denies   approval.DenyStats     `json:"denies"`
	Policy   policyView             `json:"policy"`
	Audit    approval.AuditStats    `json:"audit"`
	Failsafe failsafeView           `json:"failsafe"`
	Targets  []config.TargetStatus  `json:"targets"`
}

// handleStatus serves GET /api/v1/gate/status.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, _ params, _ apiSession) {
	status, err := s.deps.Gate.Status(r.Context())
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	policy := s.policy()
	active, reason := s.failsafeState()
	s.respondJSON(w, r, http.StatusOK, statusView{
		Plans:    status.Plans,
		Sessions: status.Sessions,
		Denies:   status.Denies,
		Policy:   policyView{Version: policy.Version, UpdatedAt: policy.UpdatedAt, UpdatedBy: policy.UpdatedBy},
		Audit:    status.Audit,
		Failsafe: failsafeView{Active: active, Reason: reason},
		Targets:  s.targetStatus(),
	})
}

// deniesView is the denial list payload.
type deniesView struct {
	Items []domain.DeniedWriteAttempt `json:"items"`
	Total int                         `json:"total"`
}

// handleDenies serves GET /api/v1/gate/denies.
func (s *Server) handleDenies(w http.ResponseWriter, r *http.Request, _ params, _ apiSession) {
	q := parseQuery(r, "limit", "target_id")
	limit := q.limit()
	targetFilter := domain.TargetID(q.targetID("target_id"))
	if !s.checkQuery(w, r, q) {
		return
	}
	denies, err := s.deps.Gate.ListDenies(r.Context(), maxListLimit)
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	filtered := make([]domain.DeniedWriteAttempt, 0, len(denies))
	for _, deny := range denies {
		if targetFilter != "" && deny.TargetID != targetFilter {
			continue
		}
		filtered = append(filtered, deny)
	}
	total := len(filtered)
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	s.respondJSON(w, r, http.StatusOK, deniesView{Items: filtered, Total: total})
}

// auditView is the audit list payload.
type auditView struct {
	Items     []domain.AuditEntry `json:"items"`
	ChainOK   bool                `json:"chain_ok"`
	CheckedAt time.Time           `json:"checked_at,omitempty"`
}

// handleAudit serves GET /api/v1/gate/audit.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ params, _ apiSession) {
	q := parseQuery(r, "limit")
	limit := q.limit()
	if !s.checkQuery(w, r, q) {
		return
	}
	entries, err := s.deps.Gate.ListAudit(r.Context(), limit)
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	chain := s.audit.statusOf(r.Context())
	s.respondJSON(w, r, http.StatusOK, auditView{
		Items:     entries,
		ChainOK:   chain.Err == nil && chain.OK,
		CheckedAt: chain.CheckedAt,
	})
}

// policyEnvelope wraps the active policy.
type policyEnvelope struct {
	Policy config.Policy `json:"policy"`
}

// handlePolicy serves GET /api/v1/gate/policy.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request, _ params, _ apiSession) {
	s.respondJSON(w, r, http.StatusOK, policyEnvelope{Policy: s.policy()})
}

// handlePolicyReload serves POST /api/v1/gate/policy/reload.
func (s *Server) handlePolicyReload(w http.ResponseWriter, r *http.Request, _ params, session apiSession) {
	if err := s.verifyMFAHeader(r, session); err != nil {
		s.auditLogin(r, string(session.User.UserID), roleList(session.User), approval.ActionLoginFailed, "policy reload mfa failed")
		s.fail(w, r, http.StatusForbidden, "mfa_required", "MFA confirmation is required")
		return
	}
	loaded, err := s.deps.LoadPolicy()
	if err != nil {
		switch {
		case errors.Is(err, config.ErrPolicyMissing):
			s.fail(w, r, http.StatusServiceUnavailable, "unavailable", "policy file is missing")
		case errors.Is(err, config.ErrInvalidPolicy):
			s.fail(w, r, http.StatusConflict, "conflict", "policy is invalid")
		default:
			s.logger.Error("load gate policy failed", "request_id", requestID(r), "error", err)
			s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		}
		return
	}
	// Audit before activation (fail-closed).
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.deps.Gate.RecordAudit(ctx, string(session.User.UserID), roleList(session.User),
		approval.ActionPolicyReload, approval.ObjectGatePolicy, loaded.PolicyID,
		"version="+itoa(loaded.Version)+" hash pending"); err != nil {
		s.logger.Error("audit policy reload failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusServiceUnavailable, "unavailable", "audit unavailable")
		return
	}
	if err := s.deps.ActivatePolicy(loaded); err != nil {
		s.logger.Error("activate gate policy failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	s.respondJSON(w, r, http.StatusOK, policyEnvelope{Policy: loaded})
}

// usersView is the user list payload.
type usersView struct {
	Items []userView `json:"items"`
}

// handleUsers serves GET /api/v1/gate/users (master_admin).
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, _ params, _ apiSession) {
	users := s.deps.Identity.Users()
	items := make([]userView, 0, len(users))
	for _, user := range users {
		items = append(items, publicUser(user, s.deps.Identity.LastLogin(user.UserID)))
	}
	s.respondJSON(w, r, http.StatusOK, usersView{Items: items})
}

// notifyTestView is the notify test payload.
type notifyTestView struct {
	Sent    bool   `json:"sent"`
	Channel string `json:"channel"`
}

// handleNotifyTest serves POST /api/v1/gate/notify/test (master_admin).
func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request, _ params, session apiSession) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := s.deps.Gate.RecordAudit(ctx, string(session.User.UserID), roleList(session.User),
		approval.ActionNotifyTest, approval.ObjectGateNotify, "notify", "operator triggered test notification"); err != nil {
		s.failGate(w, r, err)
		return
	}
	if s.deps.NotifyTest == nil {
		s.fail(w, r, http.StatusServiceUnavailable, "notifier_failed", "notifier is not configured")
		return
	}
	if err := s.deps.NotifyTest(ctx); err != nil {
		s.logger.Error("notify test failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusServiceUnavailable, "notifier_failed", "notifier delivery failed")
		return
	}
	s.respondJSON(w, r, http.StatusOK, notifyTestView{Sent: true, Channel: "webhook"})
}

// itoa renders a small integer without importing strconv at every call site.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	digits := make([]byte, 0, 8)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	if negative {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
