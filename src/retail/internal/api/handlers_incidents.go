package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
	"github.com/visiongaiatechnology/gedefense/retail/internal/state"
)

// timelineItem is one entry of the fact-only timeline.
type timelineItem struct {
	At       time.Time       `json:"at"`
	Kind     string          `json:"kind"`
	Severity domain.Severity `json:"severity,omitempty"`
	Title    string          `json:"title"`
	RefID    string          `json:"ref_id"`
	Category domain.Category `json:"category,omitempty"`
	SiteID   domain.SiteID   `json:"site_id"`
}

// timelineResponse is the timeline payload.
type timelineResponse struct {
	Items []timelineItem `json:"items"`
	Total int            `json:"total"`
}

// handleTimeline serves GET /api/v1/timeline.
func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	q := parseQuery(r, "site_id", "since", "limit")
	siteID := domain.SiteID(q.idValue("site_id", validateSiteID))
	since := q.timeValue("since")
	limit := q.intValue("limit", defaultListLimit, 1, maxListLimit)
	if !s.checkQuery(w, r, q) {
		return
	}
	if since.IsZero() {
		since = time.Now().UTC().Add(-24 * time.Hour)
	}

	alerts, ok := s.snapshotAlerts(w, r)
	if !ok {
		return
	}
	items := make([]timelineItem, 0, 64)
	for _, alert := range alerts {
		if siteID != "" && alert.SiteID != siteID {
			continue
		}
		if alert.LastSeenAt.Before(since) {
			continue
		}
		items = append(items, timelineItem{
			At:       alert.LastSeenAt,
			Kind:     "alert",
			Severity: alert.Severity,
			Title:    alert.Title,
			RefID:    string(alert.AlertID),
			Category: alert.Category,
			SiteID:   alert.SiteID,
		})
	}
	for _, incident := range s.deps.Sites.Incidents(siteID) {
		if incident.LastSeenAt.Before(since) {
			continue
		}
		items = append(items, timelineItem{
			At:       incident.LastSeenAt,
			Kind:     "incident",
			Severity: incident.Severity,
			Title:    incident.Title,
			RefID:    string(incident.IncidentID),
			SiteID:   incident.SiteID,
		})
	}
	for _, event := range s.deps.Sites.Events(ports.EventQuery{
		SiteID: siteID,
		Since:  since.Format(time.RFC3339),
		Limit:  maxEventTimeline,
	}) {
		kind := "event"
		if event.Kind == domain.EventAccess {
			kind = "access"
		}
		items = append(items, timelineItem{
			At:     event.ObservedAt,
			Kind:   kind,
			Title:  eventTitle(event),
			RefID:  string(event.EventID),
			SiteID: event.SiteID,
		})
	}

	sort.SliceStable(items, func(i, j int) bool {
		if !items[i].At.Equal(items[j].At) {
			return items[i].At.After(items[j].At)
		}
		return items[i].RefID < items[j].RefID
	})
	total := len(items)
	if len(items) > limit {
		items = items[:limit]
	}
	s.respondJSON(w, r, http.StatusOK, timelineResponse{Items: items, Total: total})
}

// eventTitle renders a factual, non-interpretive event title.
func eventTitle(event domain.Event) string {
	switch event.Kind {
	case domain.EventTelemetry:
		if event.Measurement != nil {
			return fmt.Sprintf("Telemetry %s from %s", event.Measurement.Metric, event.SensorID)
		}
		return "Telemetry"
	case domain.EventFlow:
		if event.Flow != nil {
			return fmt.Sprintf("Passive flow %s %s -> %s", event.Flow.Protocol, event.Flow.SrcIP, event.Flow.DstIP)
		}
		return "Passive flow"
	case domain.EventAssetSeen:
		return "Asset observed: " + string(event.AssetID)
	case domain.EventAccess:
		if event.Access != nil && event.Access.Vendor != "" {
			return "Maintenance access: " + event.Access.Vendor
		}
		return "Maintenance access"
	case domain.EventWriteAttempt:
		return "Observed write attempt"
	case domain.EventConfigChange:
		return "Configuration change observed"
	case domain.EventIntegrity:
		return "Integrity observation"
	case domain.EventClockSkew:
		return "Clock skew observed"
	case domain.EventDeviceHealth:
		return "Device health observation"
	default:
		return string(event.Kind)
	}
}

// integrityItem aggregates one observed configuration subject.
type integrityItem struct {
	Subject     string         `json:"subject"`
	AssetID     domain.AssetID `json:"asset_id,omitempty"`
	ZoneID      domain.ZoneID  `json:"zone_id,omitempty"`
	Version     string         `json:"version,omitempty"`
	SHA256      string         `json:"sha256,omitempty"`
	Changed     bool           `json:"changed"`
	Approved    bool           `json:"approved"`
	FirstSeenAt time.Time      `json:"first_seen_at"`
	LastSeenAt  time.Time      `json:"last_seen_at"`
}

// integrityChange is one observed integrity change.
type integrityChange struct {
	AssetID  domain.AssetID `json:"asset_id,omitempty"`
	Subject  string         `json:"subject"`
	At       time.Time      `json:"at"`
	Approved bool           `json:"approved"`
	AlertID  domain.AlertID `json:"alert_id,omitempty"`
}

// integrityResponse is the integrity payload.
type integrityResponse struct {
	Items   []integrityItem   `json:"items"`
	Changes []integrityChange `json:"changes"`
}

// handleIntegrity serves GET /api/v1/integrity.
func (s *Server) handleIntegrity(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	q := parseQuery(r, "site_id")
	siteID := domain.SiteID(q.idValue("site_id", validateSiteID))
	if !s.checkQuery(w, r, q) {
		return
	}

	events := s.deps.Sites.Events(ports.EventQuery{SiteID: siteID, Limit: maxIntegrityEvents})
	bySubject := make(map[string]*integrityItem, 8)
	changes := make([]integrityChange, 0, 8)
	for _, event := range events {
		if event.Integrity == nil {
			continue
		}
		if event.Kind != domain.EventIntegrity && event.Kind != domain.EventConfigChange {
			continue
		}
		integrity := event.Integrity
		key := string(event.AssetID) + "|" + integrity.Subject
		item, ok := bySubject[key]
		if !ok {
			item = &integrityItem{
				Subject:     integrity.Subject,
				AssetID:     event.AssetID,
				ZoneID:      event.ZoneID,
				Version:     integrity.Version,
				SHA256:      integrity.SHA256,
				Changed:     integrity.Changed,
				Approved:    integrity.Approved,
				FirstSeenAt: event.ObservedAt,
				LastSeenAt:  event.ObservedAt,
			}
			bySubject[key] = item
		}
		if !event.ObservedAt.Before(item.LastSeenAt) {
			item.LastSeenAt = event.ObservedAt
			item.Version = integrity.Version
			item.SHA256 = integrity.SHA256
			item.Changed = integrity.Changed
			item.Approved = integrity.Approved
		}
		if event.ObservedAt.Before(item.FirstSeenAt) {
			item.FirstSeenAt = event.ObservedAt
		}
		if integrity.Changed {
			changes = append(changes, integrityChange{
				AssetID:  event.AssetID,
				Subject:  integrity.Subject,
				At:       event.ObservedAt,
				Approved: integrity.Approved,
			})
		}
	}

	items := make([]integrityItem, 0, len(bySubject))
	for _, item := range bySubject {
		items = append(items, *item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].AssetID != items[j].AssetID {
			return items[i].AssetID < items[j].AssetID
		}
		return items[i].Subject < items[j].Subject
	})
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].At.After(changes[j].At) })
	if len(changes) > maxIntegrityChanges {
		changes = changes[:maxIntegrityChanges]
	}
	s.respondJSON(w, r, http.StatusOK, integrityResponse{Items: items, Changes: changes})
}

// incidentsResponse is the incident list payload.
type incidentsResponse struct {
	Items []domain.Incident `json:"items"`
	Total int               `json:"total"`
}

// incidentDetailResponse is the incident detail payload.
type incidentDetailResponse struct {
	Incident domain.Incident `json:"incident"`
	Alerts   []domain.Alert  `json:"alerts"`
	Events   []domain.Event  `json:"events"`
}

// handleIncidents serves GET /api/v1/incidents.
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	q := parseQuery(r, "site_id", "status")
	siteID := domain.SiteID(q.idValue("site_id", validateSiteID))
	status := q.enumValue("status", []string{
		string(domain.IncidentOpen), string(domain.IncidentInvestigating), string(domain.IncidentContained),
		string(domain.IncidentResolved), string(domain.IncidentClosed),
	})
	if !s.checkQuery(w, r, q) {
		return
	}
	incidents := s.deps.Sites.Incidents(siteID)
	filtered := make([]domain.Incident, 0, len(incidents))
	for _, incident := range incidents {
		if status != "" && string(incident.Status) != status {
			continue
		}
		filtered = append(filtered, incident)
	}
	s.respondJSON(w, r, http.StatusOK, incidentsResponse{Items: filtered, Total: len(filtered)})
}

// handleIncident serves GET /api/v1/incidents/{incident_id}.
func (s *Server) handleIncident(w http.ResponseWriter, r *http.Request, p params, _ identity) {
	incidentID := domain.IncidentID(pathParam(p, "incident_id"))
	if err := incidentID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "incident_id is not a valid identifier")
		return
	}
	incident, ok := s.deps.Sites.Incident(incidentID)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "not_found", "incident not found")
		return
	}
	alerts := s.incidentAlerts(w, r, incident)
	if alerts == nil {
		return
	}
	events, err := s.incidentEvents(w, r, incident)
	if err != nil {
		s.logger.Error("load incident events failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	s.respondJSON(w, r, http.StatusOK, incidentDetailResponse{Incident: incident, Alerts: alerts, Events: events})
}

// incidentAlerts loads the alerts of an incident. It returns nil after writing an
// error response.
func (s *Server) incidentAlerts(w http.ResponseWriter, r *http.Request, incident domain.Incident) []domain.Alert {
	out := make([]domain.Alert, 0, len(incident.AlertIDs))
	for _, alertID := range incident.AlertIDs {
		stored, found, err := s.deps.Alerts.Get(r.Context(), alertID)
		if err != nil {
			s.logger.Error("load incident alert failed", "request_id", requestID(r), "error", err)
			s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
			return nil
		}
		if found {
			out = append(out, stored)
		}
	}
	sortAlertsBySeverity(out)
	return out
}

// incidentEvents loads the events of the incident window from the durable store.
func (s *Server) incidentEvents(w http.ResponseWriter, r *http.Request, incident domain.Incident) ([]domain.Event, error) {
	query := ports.EventQuery{SiteID: incident.SiteID, Limit: maxIncidentEvents}
	if !incident.FirstSeenAt.IsZero() {
		query.Since = incident.FirstSeenAt.Format(time.RFC3339)
	}
	events, err := s.deps.Events.Recent(r.Context(), query)
	if err != nil {
		return nil, err
	}
	if events == nil {
		events = []domain.Event{}
	}
	return events, nil
}

// handleIncidentNote serves POST /api/v1/incidents/{incident_id}/note.
func (s *Server) handleIncidentNote(w http.ResponseWriter, r *http.Request, p params, ident identity) {
	incidentID := domain.IncidentID(pathParam(p, "incident_id"))
	if err := incidentID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "incident_id is not a valid identifier")
		return
	}
	var body noteRequest
	if !s.decodeJSON(w, r, &body) {
		return
	}
	updated, err := s.deps.Sites.AddIncidentNote(incidentID, domain.IncidentNote{
		At:    time.Now().UTC(),
		Actor: string(ident.UserID),
		Role:  string(ident.Role),
		Note:  body.Note,
	})
	if err != nil {
		switch {
		case errors.Is(err, state.ErrNotFound):
			s.fail(w, r, http.StatusNotFound, "not_found", "incident not found")
		case errors.Is(err, state.ErrInvalidNote):
			s.fail(w, r, http.StatusBadRequest, "invalid_request", "invalid note")
		case errors.Is(err, state.ErrConflict):
			s.fail(w, r, http.StatusConflict, "conflict", "incident cannot accept more notes")
		default:
			s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		}
		return
	}
	s.respondJSON(w, r, http.StatusOK, map[string]domain.Incident{"incident": updated})
}

// handleIncidentExport serves GET /api/v1/incidents/{incident_id}/export.
func (s *Server) handleIncidentExport(w http.ResponseWriter, r *http.Request, p params, _ identity) {
	incidentID := domain.IncidentID(pathParam(p, "incident_id"))
	if err := incidentID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "incident_id is not a valid identifier")
		return
	}
	incident, ok := s.deps.Sites.Incident(incidentID)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "not_found", "incident not found")
		return
	}
	alerts := s.incidentAlerts(w, r, incident)
	if alerts == nil {
		return
	}
	events, err := s.incidentEvents(w, r, incident)
	if err != nil {
		s.logger.Error("load incident export events failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	auditEntries, err := s.deps.Audit.List(r.Context(), maxListLimit)
	if err != nil {
		s.logger.Error("load incident export audit failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if auditEntries == nil {
		auditEntries = []domain.AuditEntry{}
	}
	assets := make([]domain.Asset, 0, len(incident.AssetIDs))
	for _, assetID := range incident.AssetIDs {
		if asset, found := s.deps.Sites.Asset(assetID); found {
			assets = append(assets, asset)
		}
	}
	export := domain.IncidentExport{
		GeneratedAt: time.Now().UTC(),
		Product:     s.deps.Version.Product,
		Version:     s.deps.Version.Version,
		Incident:    incident,
		Alerts:      alerts,
		Events:      events,
		Assets:      assets,
		Audit:       auditEntries,
		Constraints: []string{"read-only", "no plant control"},
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "incident-"+string(incident.IncidentID)+".json"))
	s.respondJSON(w, r, http.StatusOK, export)
}
