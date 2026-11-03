package api

import (
	"net/http"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/approval"
)

// sessionEnvelope wraps one write session.
type sessionEnvelope struct {
	Session domain.WriteSession `json:"session"`
}

// sessionsEnvelope is the session list payload.
type sessionsEnvelope struct {
	Items []domain.WriteSession `json:"items"`
	Total int                   `json:"total"`
}

// createSessionBody redeems a one-time token.
type createSessionBody struct {
	PlanID domain.PlanID `json:"plan_id"`
	Token  string        `json:"token"`
}

// handleCreateSession serves POST /api/v1/gate/sessions.
func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request, _ params, session apiSession) {
	var body createSessionBody
	if !s.decodeJSON(w, r, &body) {
		return
	}
	writeSession, err := s.deps.Gate.RedeemToken(r.Context(), session.User, approval.RedeemRequest{
		PlanID:   body.PlanID,
		Token:    body.Token,
		SourceIP: clientIP(r),
	})
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusCreated, sessionEnvelope{Session: writeSession})
}

// handleSessions serves GET /api/v1/gate/sessions.
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request, _ params, _ apiSession) {
	q := parseQuery(r, "active", "limit", "offset")
	activeOnly := q.boolValue("active")
	limit, offset := q.limit(), q.offset()
	if !s.checkQuery(w, r, q) {
		return
	}
	sessions, err := s.deps.Gate.ListSessions(r.Context())
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	now := s.now()
	filtered := make([]domain.WriteSession, 0, len(sessions))
	for _, session := range sessions {
		if activeOnly && !session.Usable(now) {
			continue
		}
		filtered = append(filtered, session)
	}
	total := len(filtered)
	if offset >= total {
		filtered = []domain.WriteSession{}
	} else {
		end := offset + limit
		if end > total {
			end = total
		}
		filtered = filtered[offset:end]
	}
	s.respondJSON(w, r, http.StatusOK, sessionsEnvelope{Items: filtered, Total: total})
}

// handleRevokeSession serves DELETE /api/v1/gate/sessions/{session_id}.
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request, p params, session apiSession) {
	sessionID := domain.SessionID(pathParam(p, "session_id"))
	if err := sessionID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "session_id is not a valid identifier")
		return
	}
	revoked, err := s.deps.Gate.RevokeSession(r.Context(), session.User, sessionID, "revoked via management API")
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, sessionEnvelope{Session: revoked})
}
