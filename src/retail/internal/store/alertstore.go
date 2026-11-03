package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

const (
	alertStateFile     = "alerts.json"
	alertStateSchemaV1 = 1
	defaultAlertDays   = 180
	pruneInterval      = time.Hour
)

// alertState is the persistent document of the alert store.
type alertState struct {
	Schema int            `json:"schema"`
	Alerts []domain.Alert `json:"alerts"`
}

// AlertStore keeps the current alert state in memory and persists it atomically
// to alerts.json. The per-alert workflow history is part of the alert document.
type AlertStore struct {
	dir           string
	path          string
	retentionDays int
	clock         ports.Clock

	mu        sync.RWMutex
	alerts    map[domain.AlertID]domain.Alert
	order     []domain.AlertID
	lastPrune time.Time
	closed    bool
}

// OpenAlertStore opens (and if necessary creates) the alert state store.
func OpenAlertStore(opts Options) (*AlertStore, error) {
	norm, err := normalizeOptions(opts, defaultEventMaxMB)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(norm.Dir, "alerts")
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	st := &AlertStore{
		dir:           dir,
		path:          filepath.Join(dir, alertStateFile),
		retentionDays: norm.RetentionDays,
		clock:         norm.Clock,
		alerts:        make(map[domain.AlertID]domain.Alert),
		order:         make([]domain.AlertID, 0, 64),
	}
	if st.retentionDays == 0 {
		st.retentionDays = defaultAlertDays
	}
	if err := st.load(); err != nil {
		return nil, err
	}
	st.lastPrune = st.clock.Now()
	if pruned := st.pruneLocked(st.lastPrune); pruned > 0 {
		if err := st.persistLocked(); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// load reads alerts.json if it exists and rejects state that does not verify.
func (st *AlertStore) load() error {
	raw, err := readPrivateFile(st.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("store: %w: read alert state: %v", ErrCorruptState, err)
	}
	var state alertState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&state); derr != nil {
		return fmt.Errorf("store: %w: decode alert state: %v", ErrCorruptState, derr)
	}
	if state.Schema != alertStateSchemaV1 {
		return fmt.Errorf("store: %w: unsupported alert state schema %d", ErrCorruptState, state.Schema)
	}
	for i, a := range state.Alerts {
		if verr := a.Validate(); verr != nil {
			return fmt.Errorf("store: %w: alerts[%d]: %v", ErrCorruptState, i, verr)
		}
		if _, dup := st.alerts[a.AlertID]; dup {
			return fmt.Errorf("store: %w: duplicate alert_id %q", ErrCorruptState, a.AlertID)
		}
		st.alerts[a.AlertID] = alertCopy(a)
		st.order = append(st.order, a.AlertID)
	}
	return nil
}

// Upsert stores the alert and atomically rewrites alerts.json.
func (st *AlertStore) Upsert(ctx context.Context, alert domain.Alert) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("store: upsert alert: %w", err)
	}
	if err := alert.Validate(); err != nil {
		return fmt.Errorf("store: upsert alert: %w", err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return ErrClosed
	}
	if existing, ok := st.alerts[alert.AlertID]; ok {
		if alert.CreatedAt.IsZero() {
			alert.CreatedAt = existing.CreatedAt
		}
		if alert.FirstSeenAt.IsZero() {
			alert.FirstSeenAt = existing.FirstSeenAt
		}
	} else {
		alert.CreatedAt = nonZeroTime(alert.CreatedAt, st.clock.Now())
		alert.FirstSeenAt = nonZeroTime(alert.FirstSeenAt, alert.CreatedAt)
		st.order = append(st.order, alert.AlertID)
	}
	alert.UpdatedAt = nonZeroTime(alert.UpdatedAt, st.clock.Now())
	st.alerts[alert.AlertID] = alertCopy(alert)
	if now := st.clock.Now(); now.Sub(st.lastPrune) >= pruneInterval {
		st.pruneLocked(now)
		st.lastPrune = now
	}
	return st.persistLocked()
}

// Get returns one alert by identifier.
func (st *AlertStore) Get(ctx context.Context, id domain.AlertID) (domain.Alert, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Alert{}, false, fmt.Errorf("store: get alert: %w", err)
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	if st.closed {
		return domain.Alert{}, false, ErrClosed
	}
	alert, ok := st.alerts[id]
	if !ok {
		return domain.Alert{}, false, nil
	}
	return alertCopy(alert), true, nil
}

// List returns the filtered alerts sorted by severity (descending) and
// last_seen_at (descending).
func (st *AlertStore) List(ctx context.Context, q ports.AlertQuery) ([]domain.Alert, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("store: list alerts: %w", err)
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	if st.closed {
		return nil, ErrClosed
	}
	out := make([]domain.Alert, 0, len(st.alerts))
	for _, a := range st.alerts {
		if q.SiteID != "" && a.SiteID != q.SiteID {
			continue
		}
		if q.Status != "" && a.Status != q.Status {
			continue
		}
		if q.Severity != "" && a.Severity != q.Severity {
			continue
		}
		if q.Category != "" && a.Category != q.Category {
			continue
		}
		out = append(out, alertCopy(a))
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := out[i].Severity.Rank(), out[j].Severity.Rank()
		if ri != rj {
			return ri > rj
		}
		if !out[i].LastSeenAt.Equal(out[j].LastSeenAt) {
			return out[i].LastSeenAt.After(out[j].LastSeenAt)
		}
		return out[i].AlertID < out[j].AlertID
	})
	if limit := clampLimit(q.Limit); len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ListAll returns every stored alert in insertion order. It is used by the
// alert engine for dedup lookups and by the API for aggregate counters.
func (st *AlertStore) ListAll(ctx context.Context) ([]domain.Alert, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("store: list all alerts: %w", err)
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	if st.closed {
		return nil, ErrClosed
	}
	out := make([]domain.Alert, 0, len(st.order))
	for _, id := range st.order {
		if a, ok := st.alerts[id]; ok {
			out = append(out, alertCopy(a))
		}
	}
	return out, nil
}

// FindByDedupKey returns the most recent non-terminal alert with the given dedup
// key. It is the store side of the alert dedup contract.
func (st *AlertStore) FindByDedupKey(ctx context.Context, key string) (domain.Alert, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Alert{}, false, fmt.Errorf("store: find alert by dedup key: %w", err)
	}
	if key == "" {
		return domain.Alert{}, false, nil
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	if st.closed {
		return domain.Alert{}, false, ErrClosed
	}
	var best domain.Alert
	var found bool
	for _, a := range st.alerts {
		if a.DedupKey != key || !isActiveStatus(a.Status) {
			continue
		}
		if !found || a.LastSeenAt.After(best.LastSeenAt) {
			best, found = a, true
		}
	}
	if !found {
		return domain.Alert{}, false, nil
	}
	return alertCopy(best), true, nil
}

// Count returns the number of stored alerts.
func (st *AlertStore) Count() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.alerts)
}

// Close persists pending state. It is idempotent.
func (st *AlertStore) Close() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return nil
	}
	st.closed = true
	return st.persistLocked()
}

// persistLocked writes the whole state atomically. The store is a single-writer
// document: serialising the write under the state mutex is what keeps
// alerts.json consistent, and the document stays small by design.
func (st *AlertStore) persistLocked() error {
	state := alertState{Schema: alertStateSchemaV1, Alerts: make([]domain.Alert, 0, len(st.alerts))}
	for _, id := range st.order {
		if a, ok := st.alerts[id]; ok {
			state.Alerts = append(state.Alerts, a)
		}
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal alert state: %w", err)
	}
	if err := writeFileAtomic(st.path, append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

// pruneLocked drops alerts older than the retention window.
func (st *AlertStore) pruneLocked(now time.Time) int {
	if st.retentionDays <= 0 {
		return 0
	}
	cutoff := now.AddDate(0, 0, -st.retentionDays)
	pruned := 0
	kept := st.order[:0]
	for _, id := range st.order {
		a, ok := st.alerts[id]
		if !ok {
			continue
		}
		if a.LastSeenAt.Before(cutoff) {
			delete(st.alerts, id)
			pruned++
			continue
		}
		kept = append(kept, id)
	}
	st.order = kept
	return pruned
}

// isActiveStatus reports whether the workflow status still participates in
// deduplication.
func isActiveStatus(status domain.AlertStatus) bool {
	switch status {
	case domain.AlertOpen, domain.AlertAcknowledged, domain.AlertInvestigating:
		return true
	}
	return false
}

// alertCopy deep-copies the slice and pointer fields of an alert so that readers
// can never mutate stored state through a returned value.
func alertCopy(a domain.Alert) domain.Alert {
	out := a
	out.AssetIDs = append([]domain.AssetID(nil), a.AssetIDs...)
	out.ZoneIDs = append([]domain.ZoneID(nil), a.ZoneIDs...)
	out.SensorIDs = append([]domain.SensorID(nil), a.SensorIDs...)
	out.Evidence = append([]domain.Evidence(nil), a.Evidence...)
	out.RecommendedActions = append([]domain.RecommendedAction(nil), a.RecommendedActions...)
	out.SafetyConstraints = append([]string(nil), a.SafetyConstraints...)
	out.AuditHistory = append([]domain.AlertAuditEntry(nil), a.AuditHistory...)
	if a.Correlation != nil {
		correlation := *a.Correlation
		correlation.ObservedFacts = append([]string(nil), a.Correlation.ObservedFacts...)
		correlation.AlternativeExplanations = append([]string(nil), a.Correlation.AlternativeExplanations...)
		correlation.RecommendedChecks = append([]string(nil), a.Correlation.RecommendedChecks...)
		correlation.Indicators = append([]string(nil), a.Correlation.Indicators...)
		out.Correlation = &correlation
	}
	return out
}

// nonZeroTime returns value when set, otherwise fallback.
func nonZeroTime(value, fallback time.Time) time.Time {
	if value.IsZero() {
		return fallback
	}
	return value
}
