package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/approval"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/identity"
)

// userView is the public identity projection (never contains secrets).
type userView struct {
	UserID      domain.GateUserID     `json:"user_id"`
	Name        string                `json:"name"`
	Kind        domain.GateUserKind   `json:"kind"`
	Roles       []domain.GateRole     `json:"roles"`
	Status      domain.GateUserStatus `json:"status,omitempty"`
	LastLoginAt time.Time             `json:"last_login_at,omitempty"`
}

// loginRequest is the credential body.
type loginRequest struct {
	UserID   string `json:"user_id"`
	Password string `json:"password"`
	TOTP     string `json:"totp"`
}

// loginResponse is the successful login payload.
type loginResponse struct {
	SessionToken string    `json:"session_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	User         userView  `json:"user"`
	MFAOK        bool      `json:"mfa_ok"`
}

// meResponse is the session projection.
type meResponse struct {
	User      userView  `json:"user"`
	MFAOK     bool      `json:"mfa_ok"`
	ExpiresAt time.Time `json:"expires_at"`
}

// publicUser projects a configured identity without secrets.
func publicUser(user domain.GateUser, lastLogin time.Time) userView {
	return userView{
		UserID:      user.UserID,
		Name:        user.Name,
		Kind:        user.Kind,
		Roles:       append([]domain.GateRole(nil), user.Roles...),
		Status:      user.Status,
		LastLoginAt: lastLogin,
	}
}

// auditLogin records a login attempt outcome without any credential material.
func (s *Server) auditLogin(r *http.Request, actor, role, action, reason string) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.deps.Gate.RecordAudit(ctx, actor, role, action, approval.ObjectGateLogin, actor, reason); err != nil {
		s.logger.Error("audit login failed", "request_id", requestID(r), "action", action, "error", err)
	}
}

// handleLogin serves POST /api/v1/gate/auth/login.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, _ params, _ apiSession) {
	var body loginRequest
	if !s.decodeJSON(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.UserID) == "" || body.Password == "" {
		s.auditLogin(r, strings.TrimSpace(body.UserID), "", approval.ActionLoginFailed, "missing credential fields")
		s.fail(w, r, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
		return
	}
	result, err := s.deps.Identity.Authenticate(r.Context(), identity.LoginRequest{
		UserID:            body.UserID,
		Password:          body.Password,
		TOTP:              body.TOTP,
		DeviceFingerprint: deviceFingerprint(r),
		SourceIP:          clientIP(r),
	})
	if err != nil {
		s.auditLogin(r, strings.TrimSpace(body.UserID), "", approval.ActionLoginFailed, loginErrorReason(err))
		switch {
		case errors.Is(err, identity.ErrDeviceNotBound):
			s.fail(w, r, http.StatusForbidden, "device_not_bound", "client certificate is not bound to this user")
		case errors.Is(err, identity.ErrUserDisabled):
			s.fail(w, r, http.StatusForbidden, "user_disabled", "user is disabled")
		case errors.Is(err, identity.ErrLockedOut):
			w.Header().Set("Retry-After", "60")
			s.fail(w, r, http.StatusTooManyRequests, "rate_limited", "too many failed attempts")
		default:
			s.fail(w, r, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
		}
		return
	}
	now := s.now()
	ttl := s.deps.Config.Timeouts.SessionTTL()
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	// Audit before creating the session (fail-closed when the audit chain is broken).
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.deps.Gate.RecordAudit(ctx, string(result.User.UserID), roleList(result.User),
		approval.ActionLoginOK, approval.ObjectGateLogin, string(result.User.UserID), "successful login"); err != nil {
		s.logger.Error("audit login success failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusServiceUnavailable, "unavailable", "audit unavailable")
		return
	}
	token, session, err := s.sessions.create(result.User, result.MFAOK, ttl, now)
	if err != nil {
		s.logger.Error("create api session failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusServiceUnavailable, "unavailable", "could not create session")
		return
	}
	s.respondJSON(w, r, http.StatusOK, loginResponse{
		SessionToken: token,
		ExpiresAt:    session.ExpiresAt,
		User:         publicUser(result.User, s.deps.Identity.LastLogin(result.User.UserID)),
		MFAOK:        result.MFAOK,
	})
}

// loginErrorReason maps an identity error onto a stable audit reason (no secrets).
func loginErrorReason(err error) string {
	switch {
	case errors.Is(err, identity.ErrDeviceNotBound):
		return "device_not_bound"
	case errors.Is(err, identity.ErrUserDisabled):
		return "user_disabled"
	case errors.Is(err, identity.ErrLockedOut):
		return "locked_out"
	case errors.Is(err, identity.ErrMFARequired):
		return "mfa_required"
	case errors.Is(err, identity.ErrTOTPReplay):
		return "totp_replay"
	default:
		return "invalid_credentials"
	}
}

// handleMe serves GET /api/v1/gate/auth/me.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, _ params, session apiSession) {
	s.respondJSON(w, r, http.StatusOK, meResponse{
		User:      publicUser(session.User, s.deps.Identity.LastLogin(session.User.UserID)),
		MFAOK:     session.MFAOK,
		ExpiresAt: session.ExpiresAt,
	})
}

// handleLogout serves POST /api/v1/gate/auth/logout.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, _ params, session apiSession) {
	token := bearerToken(r)
	s.sessions.revoke(token)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	_ = s.deps.Gate.RecordAudit(ctx, string(session.User.UserID), roleList(session.User), approval.ActionLogout,
		approval.ObjectGateLogin, string(session.User.UserID), "logout")
	s.respondNoContent(w)
}
