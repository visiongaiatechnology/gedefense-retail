package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/approval"
)

// escalationIDPattern bounds the notification identifier of the notifier.
var escalationIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// EscalationView is one 24/7 escalation as exposed by the API (no secrets).
type EscalationView struct {
	NotificationID string          `json:"notification_id"`
	AlertID        string          `json:"alert_id,omitempty"`
	Severity       domain.Severity `json:"severity"`
	CreatedAt      time.Time       `json:"created_at"`
	Level          int             `json:"level"`
	Delivered      bool            `json:"delivered"`
	Acked          bool            `json:"acked"`
	AckedBy        string          `json:"acked_by,omitempty"`
	AckedAt        time.Time       `json:"acked_at,omitempty"`
}

// EscalationHooks connect the API to the notifier escalation state. The
// composition root wires notify.Escalator; the API package stays independent.
type EscalationHooks struct {
	List func() []EscalationView
	Ack  func(ctx context.Context, notificationID, actor, note string) (EscalationView, error)
}

// escalationsView is the escalation list payload.
type escalationsView struct {
	Items []EscalationView `json:"items"`
}

// escalationEnvelope wraps one escalation.
type escalationEnvelope struct {
	Notification EscalationView `json:"notification"`
}

// ackEscalationBody is the POST ack body.
type ackEscalationBody struct {
	Note string `json:"note,omitempty"`
}

// handleEscalations serves GET /api/v1/gate/escalations.
func (s *Server) handleEscalations(w http.ResponseWriter, r *http.Request, _ params, _ apiSession) {
	if s.deps.Escalations == nil || s.deps.Escalations.List == nil {
		s.fail(w, r, http.StatusServiceUnavailable, "unavailable", "notifier is not configured")
		return
	}
	items := s.deps.Escalations.List()
	if items == nil {
		items = []EscalationView{}
	}
	s.respondJSON(w, r, http.StatusOK, escalationsView{Items: items})
}

// handleEscalationAck serves POST /api/v1/gate/escalations/{notification_id}/ack.
// The acknowledgement is always a human action; the gate never acks by itself.
func (s *Server) handleEscalationAck(w http.ResponseWriter, r *http.Request, p params, session apiSession) {
	notificationID := strings.TrimSpace(pathParam(p, "notification_id"))
	if !escalationIDPattern.MatchString(notificationID) {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "notification_id is not a valid identifier")
		return
	}
	var body ackEscalationBody
	if !s.decodeJSONOptional(w, r, &body) {
		return
	}
	var note = strings.TrimSpace(body.Note)
	if len(note) > 512 {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "note is too long")
		return
	}
	if s.deps.Escalations == nil || s.deps.Escalations.Ack == nil {
		s.fail(w, r, http.StatusServiceUnavailable, "unavailable", "notifier is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Audit before the ack takes effect (fail-closed like every other mutation).
	if err := s.deps.Gate.RecordAudit(ctx, string(session.User.UserID), roleList(session.User),
		approval.ActionEscalationAck, approval.ObjectGateEscalation, notificationID,
		"escalation acknowledged by "+string(session.User.UserID)+noteSuffix(note)); err != nil {
		s.failGate(w, r, err)
		return
	}
	view, err := s.deps.Escalations.Ack(ctx, notificationID, string(session.User.UserID), note)
	if err != nil {
		if errors.Is(err, approval.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, "not_found", "escalation not found")
			return
		}
		s.logger.Error("acknowledge escalation failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	s.respondJSON(w, r, http.StatusOK, escalationEnvelope{Notification: view})
}

// noteSuffix formats the optional ack note for the audit reason.
func noteSuffix(note string) string {
	if note == "" {
		return ""
	}
	return ": " + note
}
