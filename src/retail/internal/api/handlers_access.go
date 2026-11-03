package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/state"
)

// accessResponse is the access/maintenance payload.
type accessResponse struct {
	Windows   []domain.MaintenanceWindow `json:"windows"`
	Sessions  []domain.AccessSession     `json:"sessions"`
	Anomalies []domain.Alert             `json:"anomalies"`
}

// handleAccess serves GET /api/v1/access.
func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	q := parseQuery(r, "site_id", "since")
	siteID := domain.SiteID(q.idValue("site_id", validateSiteID))
	since := q.timeValue("since")
	if !s.checkQuery(w, r, q) {
		return
	}
	if since.IsZero() {
		since = time.Now().UTC().Add(-24 * time.Hour)
	}

	anomalies, ok := s.snapshotAlerts(w, r)
	if !ok {
		return
	}
	filtered := make([]domain.Alert, 0, 8)
	for _, alert := range anomalies {
		if alert.Category != domain.CategoryAccess || !isActiveAlert(alert) {
			continue
		}
		if siteID != "" && alert.SiteID != siteID {
			continue
		}
		filtered = append(filtered, alert)
	}
	sortAlertsBySeverity(filtered)
	if len(filtered) > 50 {
		filtered = filtered[:50]
	}

	s.respondJSON(w, r, http.StatusOK, accessResponse{
		Windows:   s.deps.Sites.Windows(siteID),
		Sessions:  s.deps.Sites.AccessSessions(siteID, since),
		Anomalies: filtered,
	})
}

// windowResponse wraps one maintenance window.
type windowResponse struct {
	Window domain.MaintenanceWindow `json:"window"`
}

// handleWindowCreate serves POST /api/v1/windows.
func (s *Server) handleWindowCreate(w http.ResponseWriter, r *http.Request, _ params, ident identity) {
	var window domain.MaintenanceWindow
	if !s.decodeJSON(w, r, &window) {
		return
	}
	if window.WindowID == "" {
		id, err := newPrefixedID("win_")
		if err != nil {
			s.logger.Error("generate window id failed", "request_id", requestID(r), "error", err)
			s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		window.WindowID = domain.MaintenanceWindowID(id)
	}
	now := time.Now().UTC()
	if window.SiteID == "" {
		window.SiteID = s.defaultSiteID()
	}
	if window.SiteID != "" {
		if _, exists := s.deps.Sites.Site(window.SiteID); !exists {
			s.fail(w, r, http.StatusBadRequest, "invalid_request", "site_id does not reference a configured site")
			return
		}
	}
	if window.Status == "" {
		window.Status = domain.WindowPlanned
	}
	if window.CreatedAt.IsZero() {
		window.CreatedAt = now
	}
	if window.CreatedBy == "" {
		window.CreatedBy = ident.UserID
	}
	if window.ApprovedBy == "" {
		window.ApprovedBy = ident.UserID
		window.ApprovedAt = now
	}
	if err := s.deps.Sites.UpsertWindow(window); err != nil {
		if errors.Is(err, state.ErrConflict) {
			s.fail(w, r, http.StatusConflict, "conflict", "maintenance window cannot be modified")
			return
		}
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "invalid maintenance window")
		return
	}
	stored, ok := s.deps.Sites.Window(window.WindowID)
	if !ok {
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if err := s.appendAudit(r, ident, "window.create", "window", string(stored.WindowID), stored.Notes); err != nil {
		s.logger.Error("audit window.create failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	s.respondJSON(w, r, http.StatusOK, windowResponse{Window: stored})
}

// handleWindowClose serves POST /api/v1/windows/{window_id}/close.
func (s *Server) handleWindowClose(w http.ResponseWriter, r *http.Request, p params, ident identity) {
	windowID := domain.MaintenanceWindowID(pathParam(p, "window_id"))
	if err := windowID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "window_id is not a valid identifier")
		return
	}
	var body noteRequest
	if !s.decodeJSON(w, r, &body) {
		return
	}
	closed, err := s.deps.Sites.CloseWindow(windowID, ident.UserID)
	if err != nil {
		switch {
		case errors.Is(err, state.ErrNotFound):
			s.fail(w, r, http.StatusNotFound, "not_found", "maintenance window not found")
		case errors.Is(err, state.ErrConflict):
			s.fail(w, r, http.StatusConflict, "conflict", "maintenance window is already closed")
		default:
			s.fail(w, r, http.StatusBadRequest, "invalid_request", "invalid maintenance window action")
		}
		return
	}
	if err := s.appendAudit(r, ident, "window.close", "window", string(closed.WindowID), body.Note); err != nil {
		s.logger.Error("audit window.close failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	s.respondJSON(w, r, http.StatusOK, windowResponse{Window: closed})
}

// appendAudit records one operator action in the hash-chained audit log.
func (s *Server) appendAudit(r *http.Request, ident identity, action, objectType, objectID, reason string) error {
	_, err := s.deps.Audit.Append(r.Context(), domain.AuditEntry{
		At:         time.Now().UTC(),
		Actor:      string(ident.UserID),
		Role:       string(ident.Role),
		Action:     action,
		ObjectType: objectType,
		ObjectID:   objectID,
		Reason:     reason,
	})
	return err
}
