package api

import (
	"errors"
	"net/http"

	"github.com/visiongaiatechnology/gedefense/retail/internal/alert"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// alertResponse wraps one alert.
type alertResponse struct {
	Alert domain.Alert `json:"alert"`
}

// alertDetailResponse is the alert detail payload with its evidence events.
type alertDetailResponse struct {
	Alert          domain.Alert   `json:"alert"`
	EvidenceEvents []domain.Event `json:"evidence_events"`
}

// noteRequest is the body of operator actions that only carry a note.
type noteRequest struct {
	Note string `json:"note"`
}

// assignRequest is the body of the assign action.
type assignRequest struct {
	Assignee domain.UserID `json:"assignee"`
	Note     string        `json:"note"`
}

// closeRequest is the body of the close action.
type closeRequest struct {
	Status domain.AlertStatus `json:"status"`
	Note   string             `json:"note"`
}

// handleAlerts serves GET /api/v1/alerts.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	q := parseQuery(r, "site_id", "status", "severity", "category", "limit", "offset")
	siteID := domain.SiteID(q.idValue("site_id", validateSiteID))
	status := q.parseStatus("status")
	severity := q.parseSeverity("severity")
	category := q.parseCategory("category")
	limit, offset := q.limit(), q.offset()
	if !s.checkQuery(w, r, q) {
		return
	}
	alerts, ok := s.snapshotAlerts(w, r)
	if !ok {
		return
	}
	filtered := filterAlerts(alerts, siteID, status, severity, category)
	sortAlertsBySeverity(filtered)
	page, total := paginate(filtered, limit, offset)
	s.respondJSON(w, r, http.StatusOK, newList(page, total, limit, offset))
}

// handleAlert serves GET /api/v1/alerts/{alert_id}.
func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request, p params, _ identity) {
	alertID := domain.AlertID(pathParam(p, "alert_id"))
	if err := alertID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "alert_id is not a valid identifier")
		return
	}
	stored, found, err := s.deps.Alerts.Get(r.Context(), alertID)
	if err != nil {
		s.failEngine(w, r, err)
		return
	}
	if !found {
		s.fail(w, r, http.StatusNotFound, "not_found", "alert not found")
		return
	}
	events, err := s.evidenceEvents(r, stored)
	if err != nil {
		s.logger.Error("load evidence events failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	s.respondJSON(w, r, http.StatusOK, alertDetailResponse{Alert: stored, EvidenceEvents: events})
}

// evidenceEvents resolves the event references of an alert from the durable
// event store.
func (s *Server) evidenceEvents(r *http.Request, stored domain.Alert) ([]domain.Event, error) {
	wanted := make(map[string]struct{}, len(stored.Evidence))
	for _, evidence := range stored.Evidence {
		if evidence.Kind == "event" && evidence.RefID != "" {
			wanted[evidence.RefID] = struct{}{}
		}
	}
	out := make([]domain.Event, 0, len(wanted))
	if len(wanted) == 0 {
		return out, nil
	}
	recent, err := s.deps.Events.Recent(r.Context(), ports.EventQuery{
		SiteID: stored.SiteID,
		Limit:  500,
	})
	if err != nil {
		return nil, err
	}
	for _, event := range recent {
		if _, ok := wanted[string(event.EventID)]; ok {
			out = append(out, event)
		}
	}
	return out, nil
}

// handleAlertAck serves POST /api/v1/alerts/{alert_id}/ack.
func (s *Server) handleAlertAck(w http.ResponseWriter, r *http.Request, p params, ident identity) {
	alertID := domain.AlertID(pathParam(p, "alert_id"))
	if err := alertID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "alert_id is not a valid identifier")
		return
	}
	var body noteRequest
	if !s.decodeJSON(w, r, &body) {
		return
	}
	updated, err := s.deps.Alerts.Ack(r.Context(), alertID, ident.UserID, string(ident.Role), body.Note)
	if err != nil {
		s.failEngine(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, alertResponse{Alert: updated})
}

// handleAlertAssign serves POST /api/v1/alerts/{alert_id}/assign.
func (s *Server) handleAlertAssign(w http.ResponseWriter, r *http.Request, p params, ident identity) {
	alertID := domain.AlertID(pathParam(p, "alert_id"))
	if err := alertID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "alert_id is not a valid identifier")
		return
	}
	var body assignRequest
	if !s.decodeJSON(w, r, &body) {
		return
	}
	if err := body.Assignee.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "assignee is not a valid user id")
		return
	}
	if !s.userExists(body.Assignee) {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "assignee is not an active user")
		return
	}
	updated, err := s.deps.Alerts.Assign(r.Context(), alertID, ident.UserID, string(ident.Role), body.Assignee, body.Note)
	if err != nil {
		s.failEngine(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, alertResponse{Alert: updated})
}

// handleAlertClose serves POST /api/v1/alerts/{alert_id}/close.
func (s *Server) handleAlertClose(w http.ResponseWriter, r *http.Request, p params, ident identity) {
	alertID := domain.AlertID(pathParam(p, "alert_id"))
	if err := alertID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "alert_id is not a valid identifier")
		return
	}
	var body closeRequest
	if !s.decodeJSON(w, r, &body) {
		return
	}
	updated, err := s.deps.Alerts.Close(r.Context(), alertID, ident.UserID, string(ident.Role), body.Status, body.Note)
	if err != nil {
		s.failEngine(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, alertResponse{Alert: updated})
}

// failEngine maps alert engine errors onto the HTTP contract.
func (s *Server) failEngine(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, alert.ErrNotFound):
		s.fail(w, r, http.StatusNotFound, "not_found", "alert not found")
	case errors.Is(err, alert.ErrConflict):
		s.fail(w, r, http.StatusConflict, "conflict", "alert is already closed")
	case errors.Is(err, alert.ErrForbidden):
		s.fail(w, r, http.StatusForbidden, "forbidden", "insufficient permissions")
	case errors.Is(err, alert.ErrInvalidActor), errors.Is(err, alert.ErrInvalidStatus),
		errors.Is(err, alert.ErrInvalidAssignee):
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "invalid alert action")
	case errors.Is(err, alert.ErrNoStore):
		s.fail(w, r, http.StatusServiceUnavailable, "unavailable", "alert store unavailable")
	default:
		s.logger.Error("alert action failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
	}
}
