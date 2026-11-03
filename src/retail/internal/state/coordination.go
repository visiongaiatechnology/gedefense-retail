package state

import (
	"fmt"
	"sort"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

const maxIncidentAlerts = 256

// Windows returns the maintenance windows of a site ordered by start time.
func (r *Registry) Windows(site domain.SiteID) []domain.MaintenanceWindow {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]domain.MaintenanceWindow, 0, len(r.windows))
	for _, window := range r.windows {
		if site != "" && window.SiteID != site {
			continue
		}
		out = append(out, copyWindow(window))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartsAt.Equal(out[j].StartsAt) {
			return out[i].StartsAt.Before(out[j].StartsAt)
		}
		return out[i].WindowID < out[j].WindowID
	})
	return out
}

// Window returns one maintenance window.
func (r *Registry) Window(id domain.MaintenanceWindowID) (domain.MaintenanceWindow, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	window, ok := r.windows[id]
	if !ok {
		return domain.MaintenanceWindow{}, false
	}
	return copyWindow(window), true
}

// WindowsAt returns the windows that are valid at the given instant: planned or
// active, and containing at.
func (r *Registry) WindowsAt(site domain.SiteID, at time.Time) []domain.MaintenanceWindow {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]domain.MaintenanceWindow, 0, len(r.windows))
	for _, window := range r.windows {
		if site != "" && window.SiteID != site {
			continue
		}
		if window.Status != domain.WindowPlanned && window.Status != domain.WindowActive {
			continue
		}
		if !window.Contains(at) {
			continue
		}
		out = append(out, copyWindow(window))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartsAt.Equal(out[j].StartsAt) {
			return out[i].StartsAt.Before(out[j].StartsAt)
		}
		return out[i].WindowID < out[j].WindowID
	})
	return out
}

// UpsertWindow validates and stores one maintenance window. A closed or
// cancelled window is terminal: reopening it would rewrite history, so a new
// window must be created instead.
func (r *Registry) UpsertWindow(window domain.MaintenanceWindow) error {
	if window.Status == "" {
		window.Status = domain.WindowPlanned
	}
	if err := window.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.windows[window.WindowID]; ok {
		if existing.Status == domain.WindowClosed || existing.Status == domain.WindowCancelled {
			return fmt.Errorf("%w: window %q is %s and cannot be modified", ErrConflict, window.WindowID, existing.Status)
		}
		if window.CreatedAt.IsZero() {
			window.CreatedAt = existing.CreatedAt
		}
		if window.CreatedBy == "" {
			window.CreatedBy = existing.CreatedBy
		}
		if window.ApprovedAt.IsZero() {
			window.ApprovedAt = existing.ApprovedAt
		}
		if window.ApprovedBy == "" {
			window.ApprovedBy = existing.ApprovedBy
		}
	} else if window.CreatedAt.IsZero() {
		window.CreatedAt = r.clock.Now().UTC()
	}
	r.windows[window.WindowID] = copyWindow(window)
	return nil
}

// CloseWindow closes an open maintenance window. The actor is validated here and
// recorded by the caller's audit trail.
func (r *Registry) CloseWindow(id domain.MaintenanceWindowID, actor domain.UserID) (domain.MaintenanceWindow, error) {
	if err := actor.Validate(); err != nil {
		return domain.MaintenanceWindow{}, fmt.Errorf("state: close window: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	window, ok := r.windows[id]
	if !ok {
		return domain.MaintenanceWindow{}, fmt.Errorf("%w: window %q", ErrNotFound, id)
	}
	if window.Status == domain.WindowClosed || window.Status == domain.WindowCancelled {
		return domain.MaintenanceWindow{}, fmt.Errorf("%w: window %q is already %s", ErrConflict, id, window.Status)
	}
	window.Status = domain.WindowClosed
	r.windows[id] = window
	return copyWindow(window), nil
}

// Incidents returns the incidents of a site, newest activity first.
func (r *Registry) Incidents(site domain.SiteID) []domain.Incident {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]domain.Incident, 0, len(r.incident))
	for _, incident := range r.incident {
		if site != "" && incident.SiteID != site {
			continue
		}
		out = append(out, copyIncident(incident))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeenAt.Equal(out[j].LastSeenAt) {
			return out[i].LastSeenAt.After(out[j].LastSeenAt)
		}
		return out[i].IncidentID < out[j].IncidentID
	})
	return out
}

// Incident returns one incident.
func (r *Registry) Incident(id domain.IncidentID) (domain.Incident, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	incident, ok := r.incident[id]
	if !ok {
		return domain.Incident{}, false
	}
	return copyIncident(incident), true
}

// UpsertIncident validates and merges one incident. First-seen, creation time and
// existing notes are never rewritten by a re-observation.
func (r *Registry) UpsertIncident(incident domain.Incident) error {
	if err := incident.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock.Now().UTC()
	if existing, ok := r.incident[incident.IncidentID]; ok {
		merged := incident
		merged.CreatedAt = minTime(existing.CreatedAt, incident.CreatedAt)
		merged.FirstSeenAt = minTime(existing.FirstSeenAt, incident.FirstSeenAt)
		merged.LastSeenAt = maxTime(existing.LastSeenAt, incident.LastSeenAt)
		merged.AlertIDs = mergeIDs(existing.AlertIDs, incident.AlertIDs, maxIncidentAlerts)
		merged.ZoneIDs = mergeIDs(existing.ZoneIDs, incident.ZoneIDs, maxProtocols)
		merged.AssetIDs = mergeIDs(existing.AssetIDs, incident.AssetIDs, maxIncidentAlerts)
		merged.Notes = mergeNotes(existing.Notes, incident.Notes)
		if merged.ClosedAt.IsZero() {
			merged.ClosedAt = existing.ClosedAt
		}
		if merged.CreatedAt.IsZero() {
			merged.CreatedAt = now
		}
		if merged.Correlation == nil {
			merged.Correlation = existing.Correlation
		}
		r.incident[incident.IncidentID] = copyIncident(merged)
		return nil
	}
	if incident.CreatedAt.IsZero() {
		incident.CreatedAt = now
	}
	incident.Notes = mergeNotes(nil, incident.Notes)
	r.incident[incident.IncidentID] = copyIncident(incident)
	return nil
}

// AddIncidentNote appends one operator note to an incident.
func (r *Registry) AddIncidentNote(id domain.IncidentID, note domain.IncidentNote) (domain.Incident, error) {
	if err := id.Validate(); err != nil {
		return domain.Incident{}, fmt.Errorf("state: add note: %w", err)
	}
	if note.Actor == "" {
		return domain.Incident{}, fmt.Errorf("%w: note actor is required", ErrInvalidNote)
	}
	if note.Note == "" || len(note.Note) > maxNoteLength {
		return domain.Incident{}, fmt.Errorf("%w: note must be 1..%d characters", ErrInvalidNote, maxNoteLength)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	incident, ok := r.incident[id]
	if !ok {
		return domain.Incident{}, fmt.Errorf("%w: incident %q", ErrNotFound, id)
	}
	if len(incident.Notes) >= maxIncidentNotes {
		return domain.Incident{}, fmt.Errorf("%w: incident %q has too many notes", ErrConflict, id)
	}
	if note.At.IsZero() {
		note.At = r.clock.Now().UTC()
	}
	incident.Notes = append(incident.Notes, note)
	incident.UpdatedAt = r.clock.Now().UTC()
	incident.LastSeenAt = maxTime(incident.LastSeenAt, note.At)
	r.incident[id] = incident
	return copyIncident(incident), nil
}

// AccessSessions derives observed maintenance sessions from the event window.
// Only facts that were actually observed are returned; nothing is inferred.
func (r *Registry) AccessSessions(site domain.SiteID, since time.Time) []domain.AccessSession {
	events := r.Events(ports.EventQuery{Kind: domain.EventAccess, SiteID: site, Limit: maxEventQueryLimit})
	out := make([]domain.AccessSession, 0, len(events))
	for _, ev := range events {
		if ev.Access == nil {
			continue
		}
		if ev.ObservedAt.Before(since) {
			continue
		}
		session := domain.AccessSession{
			SessionID:    ev.Access.SessionID,
			SiteID:       ev.SiteID,
			Vendor:       ev.Access.Vendor,
			User:         ev.Access.User,
			Method:       ev.Access.Method,
			TargetAsset:  ev.Access.TargetAsset,
			SourceDevice: ev.Access.SourceDevice,
			WindowID:     ev.Access.WindowID,
			InWindow:     ev.Access.InWindow,
			StartedAt:    ev.ObservedAt,
			Observed:     true,
		}
		if session.SessionID == "" {
			session.SessionID = string(ev.EventID)
		}
		out = append(out, session)
	}
	return out
}

// mergeIDs appends identifiers that are not yet present, bounded by limit.
func mergeIDs[T comparable](existing, incoming []T, limit int) []T {
	out := append([]T(nil), existing...)
	for _, candidate := range incoming {
		duplicate := false
		for _, value := range out {
			if value == candidate {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, candidate)
	}
	return out
}

// mergeNotes appends notes that are not already present.
func mergeNotes(existing, incoming []domain.IncidentNote) []domain.IncidentNote {
	out := append([]domain.IncidentNote(nil), existing...)
	for _, candidate := range incoming {
		duplicate := false
		for _, value := range out {
			if value.At.Equal(candidate.At) && value.Actor == candidate.Actor && value.Note == candidate.Note {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if len(out) >= maxIncidentNotes {
			break
		}
		out = append(out, candidate)
	}
	return out
}
