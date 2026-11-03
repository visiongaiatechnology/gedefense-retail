package api

import (
	"context"
	"net/http"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

const (
	// simulatorHeader is the mandatory header of the dev ingest path.
	simulatorHeader = "X-GeDefense-Sim"
	// maxDevEvents bounds one simulator batch.
	maxDevEvents = 200
)

// devIngestRequest is the simulator batch body.
type devIngestRequest struct {
	Events []domain.Event `json:"events"`
}

// devIngestError reports one rejected event.
type devIngestError struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

// devIngestResponse is the simulator batch result.
type devIngestResponse struct {
	Accepted int              `json:"accepted"`
	Rejected int              `json:"rejected"`
	Errors   []devIngestError `json:"errors"`
}

// eventMetadata is the SSE payload of an ingested event (metadata only).
type eventMetadata struct {
	EventID    domain.EventID   `json:"event_id"`
	Kind       domain.EventKind `json:"kind"`
	SiteID     domain.SiteID    `json:"site_id"`
	AssetID    domain.AssetID   `json:"asset_id,omitempty"`
	ObservedAt time.Time        `json:"observed_at"`
}

// handleDevEvents serves POST /api/v1/dev/events.
//
// The full guard chain runs before anything is decoded: the gateway must be in
// simulation mode, the peer must be loopback and the simulator header must be
// present. If any guard fails the answer is 404, never 403, so the path cannot be
// used to learn whether simulation mode is active. Only then is an admin token
// required.
func (s *Server) handleDevEvents(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	if !s.deps.SimulationEnabled || !isLoopbackClient(r) || r.Header.Get(simulatorHeader) != "1" {
		s.fail(w, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	ident, authenticated := s.authenticate(r)
	if !authenticated {
		w.Header().Set("WWW-Authenticate", `Bearer realm="gedefense-retail"`)
		s.fail(w, r, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	if !ident.Role.Allows(config.RoleAdmin) {
		s.fail(w, r, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}

	var body devIngestRequest
	if !s.decodeJSON(w, r, &body) {
		return
	}
	if len(body.Events) == 0 || len(body.Events) > maxDevEvents {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "events must contain between 1 and 200 items")
		return
	}

	accepted := make([]domain.Event, 0, len(body.Events))
	rejectedErrors := make([]devIngestError, 0, 4)
	for index, event := range body.Events {
		if err := event.Validate(); err != nil {
			rejectedErrors = append(rejectedErrors, devIngestError{Index: index, Reason: err.Error()})
			continue
		}
		accepted = append(accepted, event)
	}

	if len(accepted) > 0 {
		if err := s.ingestEvents(r.Context(), accepted); err != nil {
			s.logger.Error("dev ingest failed", "request_id", requestID(r), "error", err)
			s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		for _, event := range accepted {
			s.hub.Publish("event", eventMetadata{
				EventID:    event.EventID,
				Kind:       event.Kind,
				SiteID:     event.SiteID,
				AssetID:    event.AssetID,
				ObservedAt: event.ObservedAt,
			})
		}
	}

	s.respondJSON(w, r, http.StatusOK, devIngestResponse{
		Accepted: len(accepted),
		Rejected: len(rejectedErrors),
		Errors:   rejectedErrors,
	})
}

// ingestEvents pushes validated events into the pipeline. When the composition
// root wired a full pipeline it is used; otherwise the events are persisted and
// applied to the world model directly.
func (s *Server) ingestEvents(ctx context.Context, events []domain.Event) error {
	if s.deps.Ingest != nil {
		return s.deps.Ingest(ctx, events)
	}
	for _, event := range events {
		if err := s.deps.Events.Append(ctx, event); err != nil {
			return err
		}
		if err := s.deps.Sites.Apply(ctx, event); err != nil {
			return err
		}
	}
	return nil
}
