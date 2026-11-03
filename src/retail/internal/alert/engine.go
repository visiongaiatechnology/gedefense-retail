// Package alert implements the local alert workflow: deduplication and merging
// of repeated detections, severity escalation, operator acknowledgement,
// assignment and closure, best-effort notification and the audit trail.
//
// The engine is the only component that mutates alert state. It never touches a
// plant: every action here is documentation and operator coordination.
package alert

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Bounded collections keep a re-observed alert from growing without limit.
const (
	maxEvidence        = 32
	maxLinkedIDs       = 32
	maxActions         = 16
	maxConstraints     = 8
	maxAuditHistory    = 200
	defaultMinNotify   = domain.SeverityHigh
	alertIDPrefixBytes = 16
)

// Sentinel errors returned by the engine.
var (
	// ErrNoStore reports an engine without an alert store.
	ErrNoStore = errors.New("alert: no alert store configured")
	// ErrNotFound reports an unknown alert.
	ErrNotFound = errors.New("alert: alert not found")
	// ErrConflict reports an action that contradicts the workflow state.
	ErrConflict = errors.New("alert: alert is already in a terminal state")
	// ErrForbidden reports an action by a role that may not perform it.
	ErrForbidden = errors.New("alert: role not permitted")
	// ErrInvalidActor reports a missing or malformed actor.
	ErrInvalidActor = errors.New("alert: invalid actor")
	// ErrInvalidStatus reports an unsupported close status.
	ErrInvalidStatus = errors.New("alert: invalid close status")
	// ErrInvalidAssignee reports a missing or malformed assignee.
	ErrInvalidAssignee = errors.New("alert: invalid assignee")
)

// Options configures the alert engine.
type Options struct {
	// Store is the alert persistence. It is mandatory.
	Store ports.AlertStore
	// Notifier delivers local notifications (webhook, syslog, log sink). Optional;
	// a failing notifier never blocks the detection pipeline.
	Notifier ports.Notifier
	// Clock provides UTC timestamps; nil uses the system clock.
	Clock ports.Clock
	// Audit receives hash-chained entries for operator actions. Optional for unit
	// tests; the composition root always wires it.
	Audit ports.AuditStore
	// Publish is called for every alert change (SSE fan-out). Optional.
	Publish func(kind string, payload any)
	// MinNotify returns the minimum severity that triggers a notification.
	MinNotify func() domain.Severity
}

// wallClock is the default ports.Clock implementation.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

// Engine owns the alert workflow.
type Engine struct {
	store     ports.AlertStore
	notifier  ports.Notifier
	clock     ports.Clock
	audit     ports.AuditStore
	publish   func(kind string, payload any)
	minNotify func() domain.Severity

	// mu serialises all state-changing engine operations. The dedup decision is
	// a check-then-act sequence over the store and must not interleave, otherwise
	// two concurrent detections would create two alerts for the same dedup key.
	// It is never held while a notifier, publisher or audit write blocks on I/O.
	mu sync.Mutex

	notifyFailures  atomic.Uint64
	publishFailures atomic.Uint64
}

// NewEngine builds an alert engine.
func NewEngine(opts Options) *Engine {
	engine := &Engine{
		store:     opts.Store,
		notifier:  opts.Notifier,
		clock:     opts.Clock,
		audit:     opts.Audit,
		publish:   opts.Publish,
		minNotify: opts.MinNotify,
	}
	if engine.clock == nil {
		engine.clock = wallClock{}
	}
	if engine.minNotify == nil {
		engine.minNotify = func() domain.Severity { return defaultMinNotify }
	}
	return engine
}

// Now returns the engine clock (UTC).
func (e *Engine) Now() time.Time { return e.clock.Now().UTC() }

// List returns the filtered alert list.
func (e *Engine) List(ctx context.Context, q ports.AlertQuery) ([]domain.Alert, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("alert: list: %w", err)
	}
	if e.store == nil {
		return nil, ErrNoStore
	}
	return e.store.List(ctx, q)
}

// Get returns one alert.
func (e *Engine) Get(ctx context.Context, id domain.AlertID) (domain.Alert, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Alert{}, false, fmt.Errorf("alert: get: %w", err)
	}
	if e.store == nil {
		return domain.Alert{}, false, ErrNoStore
	}
	if err := id.Validate(); err != nil {
		return domain.Alert{}, false, err
	}
	return e.store.Get(ctx, id)
}

// Snapshot returns every stored alert. It is used by the API for the aggregate
// counters of the overview and the health endpoint.
func (e *Engine) Snapshot(ctx context.Context) ([]domain.Alert, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("alert: snapshot: %w", err)
	}
	if e.store == nil {
		return nil, ErrNoStore
	}
	if lister, ok := e.store.(interface {
		ListAll(context.Context) ([]domain.Alert, error)
	}); ok {
		return lister.ListAll(ctx)
	}
	return e.store.List(ctx, ports.AlertQuery{Limit: 200})
}

// Count returns the number of stored alerts.
func (e *Engine) Count(ctx context.Context) (int, error) {
	alerts, err := e.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	return len(alerts), nil
}

// NotifyFailures returns the number of failed best-effort notifications.
func (e *Engine) NotifyFailures() uint64 { return e.notifyFailures.Load() }

// PublishFailures returns the number of failed publish callbacks.
func (e *Engine) PublishFailures() uint64 { return e.publishFailures.Load() }

// findOpenByDedup returns the most recent active alert with the given dedup key.
func (e *Engine) findOpenByDedup(ctx context.Context, key string) (domain.Alert, bool, error) {
	if key == "" {
		return domain.Alert{}, false, nil
	}
	if finder, ok := e.store.(interface {
		FindByDedupKey(context.Context, string) (domain.Alert, bool, error)
	}); ok {
		return finder.FindByDedupKey(ctx, key)
	}
	// Fallback for stores without the optional fast path.
	alerts, err := e.Snapshot(ctx)
	if err != nil {
		return domain.Alert{}, false, err
	}
	var best domain.Alert
	found := false
	for _, alert := range alerts {
		if alert.DedupKey != key || !isActive(alert.Status) {
			continue
		}
		if !found || alert.LastSeenAt.After(best.LastSeenAt) {
			best, found = alert, true
		}
	}
	return best, found, nil
}

// notify delivers one alert best-effort. A notifier panic or error is counted
// and never propagated into the detection pipeline.
func (e *Engine) notify(ctx context.Context, alert domain.Alert) {
	if e.notifier == nil {
		return
	}
	if min := e.minNotify(); !e.minNotifyAllowed(alert, min) {
		return
	}
	defer func() {
		if recover() != nil {
			e.notifyFailures.Add(1)
		}
	}()
	if err := e.notifier.Notify(ctx, alert); err != nil {
		e.notifyFailures.Add(1)
	}
}

// minNotifyAllowed applies the notification threshold.
func (e *Engine) minNotifyAllowed(alert domain.Alert, min domain.Severity) bool {
	if alert.Status != domain.AlertOpen {
		return false
	}
	if !alert.Severity.Valid() {
		return false
	}
	if !min.Valid() {
		return alert.Severity.Rank() >= defaultMinNotify.Rank()
	}
	return alert.Severity.Rank() >= min.Rank()
}

// publishAlert fans one alert change out to the SSE hub.
func (e *Engine) publishAlert(alert domain.Alert) {
	if e.publish == nil {
		return
	}
	defer func() {
		if recover() != nil {
			e.publishFailures.Add(1)
		}
	}()
	e.publish("alert", alert)
}

// appendOperatorAudit records one operator action in the hash-chained audit log.
func (e *Engine) appendOperatorAudit(ctx context.Context, alert domain.Alert, actor domain.UserID, role, action, note string) error {
	if e.audit == nil {
		return nil
	}
	entry := domain.AuditEntry{
		At:         e.clock.Now().UTC(),
		Actor:      string(actor),
		Role:       role,
		Action:     action,
		ObjectType: "alert",
		ObjectID:   string(alert.AlertID),
		Reason:     note,
		AfterHash:  alert.DedupKey,
	}
	if _, err := e.audit.Append(ctx, entry); err != nil {
		return fmt.Errorf("alert: append audit entry: %w", err)
	}
	return nil
}

// newAlertID creates an unpredictable alert identifier.
func newAlertID() (domain.AlertID, error) {
	raw := make([]byte, alertIDPrefixBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("alert: generate alert id: %w", err)
	}
	return domain.AlertID("alr_" + hex.EncodeToString(raw)), nil
}

// isActive reports whether the workflow status still participates in dedup.
func isActive(status domain.AlertStatus) bool {
	switch status {
	case domain.AlertOpen, domain.AlertAcknowledged, domain.AlertInvestigating:
		return true
	}
	return false
}

// statusRank orders the active workflow states for monotonic progression.
func statusRank(status domain.AlertStatus) int {
	switch status {
	case domain.AlertOpen:
		return 1
	case domain.AlertAcknowledged:
		return 2
	case domain.AlertInvestigating:
		return 3
	}
	return 0
}

// isOperatorRole reports whether the role may perform workflow actions.
func isOperatorRole(role string) bool { return role == "operator" || role == "admin" }

// copyAlert deep-copies an alert.
func copyAlert(a domain.Alert) domain.Alert {
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

// maxTime returns the later of two timestamps.
func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
