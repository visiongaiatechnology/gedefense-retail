package alert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/notify"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// AuditSink appends one hash-chained audit entry. The implementation owns the
// chain (sequence number, previous hash, final hash), because the alert layer
// must not invent an audit position. A failing append is returned to the caller:
// the deny path then reports "degraded" instead of claiming an audited alert.
type AuditSink interface {
	Append(ctx context.Context, entry domain.AuditEntry) error
}

// Publisher forwards an alert to the SSE hub / dashboard. Implementations must
// not block; a slow consumer must be dropped by the hub, never by the gate.
type Publisher interface {
	Publish(alert Alert)
}

// PublisherFunc adapts a function to Publisher.
type PublisherFunc func(alert Alert)

// Publish implements Publisher.
func (f PublisherFunc) Publish(alert Alert) {
	if f != nil {
		f(alert)
	}
}

// Options configures the gate alert engine.
type Options struct {
	// Clock is mandatory: alert timestamps and the dedup window must be
	// deterministic and injectable.
	Clock     ports.Clock
	SiteID    domain.SiteID
	Audit     AuditSink
	Publisher Publisher
	Notifier  notify.Notifier
	// MinNotify is the severity threshold for notifications (default medium).
	MinNotify domain.Severity
	// DedupWindow merges identical dedup keys within the window (default 5 min).
	DedupWindow time.Duration
	// MaxTracked bounds the dedup cache (default 1024).
	MaxTracked int
}

// Stats are the engine counters exposed to the gate status API.
type Stats struct {
	Emitted      uint64 `json:"emitted"`
	Deduped      uint64 `json:"deduped"`
	Notified     uint64 `json:"notified"`
	NotifyFailed uint64 `json:"notify_failed"`
	Published    uint64 `json:"published"`
	AuditFailed  uint64 `json:"audit_failed"`
}

// Engine converts gate events into deduplicated, audited and delivered alerts.
// It is safe for concurrent use; the dedup cache is bounded.
type Engine struct {
	clock       ports.Clock
	siteID      domain.SiteID
	audit       AuditSink
	publisher   Publisher
	notifier    notify.Notifier
	minNotify   domain.Severity
	dedupWindow time.Duration
	maxTracked  int

	mu     sync.Mutex
	recent map[string]*Alert
	order  []string
	stats  Stats
}

// New validates the options and creates the alert engine.
func New(opts Options) (*Engine, error) {
	if opts.Clock == nil {
		return nil, errors.New("alert: clock is required")
	}
	if opts.MinNotify == "" {
		opts.MinNotify = domain.SeverityMedium
	}
	if !opts.MinNotify.Valid() {
		return nil, fmt.Errorf("alert: invalid minimum notify severity %q", opts.MinNotify)
	}
	if opts.DedupWindow == 0 {
		opts.DedupWindow = 5 * time.Minute
	}
	if opts.DedupWindow < time.Second || opts.DedupWindow > 24*time.Hour {
		return nil, fmt.Errorf("alert: dedup window must be in [1s, 24h]")
	}
	if opts.MaxTracked == 0 {
		opts.MaxTracked = 1024
	}
	if opts.MaxTracked < 1 || opts.MaxTracked > 65536 {
		return nil, fmt.Errorf("alert: max tracked must be in [1, 65536]")
	}
	return &Engine{
		clock:       opts.Clock,
		siteID:      opts.SiteID,
		audit:       opts.Audit,
		publisher:   opts.Publisher,
		notifier:    opts.Notifier,
		minNotify:   opts.MinNotify,
		dedupWindow: opts.DedupWindow,
		maxTracked:  opts.MaxTracked,
		recent:      make(map[string]*Alert, 16),
	}, nil
}

// Stats returns a consistent snapshot of the engine counters.
func (e *Engine) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

// Emit validates, deduplicates, audits, publishes and notifies one alert.
//
// Ordering is deliberate: a failing audit returns an error and suppresses
// publication/notification (no unaudited alert is claimed). A failing notifier
// (full queue, dead webhook) is counted but never returned as an error: the deny
// path must stay independent of delivery health.
func (e *Engine) Emit(ctx context.Context, a Alert) (Alert, error) {
	if e == nil {
		return Alert{}, errors.New("alert: nil engine")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Alert{}, err
	}
	now := e.clock.Now().UTC()
	if now.IsZero() {
		return Alert{}, errors.New("alert: clock returned zero time")
	}
	if a.SiteID == "" {
		a.SiteID = e.siteID
	}
	if a.At.IsZero() || a.At.After(now) {
		a.At = now
	}
	if a.LastSeenAt.IsZero() || a.LastSeenAt.Before(a.At) {
		a.LastSeenAt = a.At
	}
	if a.Count <= 0 {
		a.Count = 1
	}
	if a.DedupKey == "" {
		a.DedupKey = dedupKey(a.RuleID, string(a.Kind), string(a.TargetID), a.SourceIP, a.Function, a.Address)
	}

	e.mu.Lock()
	existing, deduped := e.recent[a.DedupKey]
	var (
		result       Alert
		notifyNeeded bool
		auditAction  string
	)
	if deduped && now.Sub(existing.LastSeenAt) <= e.dedupWindow {
		merged := *existing
		merged.LastSeenAt = a.LastSeenAt
		if merged.LastSeenAt.Before(merged.At) {
			merged.LastSeenAt = merged.At
		}
		merged.Count++
		if a.Severity.Rank() > merged.Severity.Rank() {
			merged.Severity = a.Severity
			notifyNeeded = true
			auditAction = "gate.alert.escalated"
		}
		merged.Evidence = mergeEvidence(merged.Evidence, a.Evidence)
		*existing = merged
		result = merged
		e.stats.Deduped++
	} else {
		a.AlertID = newAlertID()
		if err := a.Validate(); err != nil {
			e.mu.Unlock()
			return Alert{}, err
		}
		e.recent[a.DedupKey] = &a
		e.order = append(e.order, a.DedupKey)
		e.pruneLocked()
		result = a
		notifyNeeded = true
		auditAction = "gate.alert.raised"
		e.stats.Emitted++
	}
	e.mu.Unlock()

	if auditAction != "" {
		if err := e.auditAlert(ctx, result, auditAction, now); err != nil {
			// Do not keep an unaudited alert in the dedup cache: the next attempt
			// must retry the audit instead of being merged into a phantom alert.
			e.mu.Lock()
			e.stats.AuditFailed++
			e.evictLocked(result)
			e.mu.Unlock()
			return result, fmt.Errorf("alert: audit append failed: %w", err)
		}
	}
	if e.publisher != nil {
		e.publisher.Publish(result)
		e.mu.Lock()
		e.stats.Published++
		e.mu.Unlock()
	}
	if notifyNeeded && e.notifier != nil && result.Severity.Rank() >= e.minNotify.Rank() {
		err := e.notifier.Notify(ctx, e.notificationFor(result))
		e.mu.Lock()
		if err != nil {
			e.stats.NotifyFailed++ // tolerated: delivery health never blocks the gate
		} else {
			e.stats.Notified++
		}
		e.mu.Unlock()
	}
	return result, nil
}

// OnDeniedWrite converts one refused write attempt into an alert.
func (e *Engine) OnDeniedWrite(ctx context.Context, d domain.DeniedWriteAttempt) (Alert, error) {
	if e == nil {
		return Alert{}, errors.New("alert: nil engine")
	}
	if err := d.Validate(); err != nil {
		return Alert{}, fmt.Errorf("alert: invalid denied write: %w", err)
	}
	return e.Emit(ctx, NewDeniedWriteAlert(d, e.siteID))
}

// OnWriteUnknown converts a write with an unclear device outcome into the
// critical gate.write.unknown alert.
func (e *Engine) OnWriteUnknown(ctx context.Context, u UnknownWrite) (Alert, error) {
	if e == nil {
		return Alert{}, errors.New("alert: nil engine")
	}
	if u.At.IsZero() {
		return Alert{}, errors.New("alert: write-unknown requires at")
	}
	if u.SourceIP == "" || u.TargetID == "" || u.Protocol == "" || u.Function == "" {
		return Alert{}, errors.New("alert: write-unknown requires source, target, protocol and function")
	}
	return e.Emit(ctx, NewWriteUnknownAlert(u, e.siteID))
}

// OnGateEvent maps one GateEvent onto an alert. Routine lifecycle events
// (plan_created/approved, session_open/close, write_allowed) are acknowledged as
// SSE events but do not raise alerts; rejected/expired plans, denials, bypass
// suspicion, write-unknown and fail-safe conditions do.
func (e *Engine) OnGateEvent(ctx context.Context, ev domain.GateEvent) (Alert, bool, error) {
	if e == nil {
		return Alert{}, false, errors.New("alert: nil engine")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Alert{}, false, err
	}
	site := ev.SiteID
	if site == "" && e != nil {
		site = e.siteID
	}
	switch ev.Kind {
	case domain.GateEventWriteDenied:
		var attempt domain.DeniedWriteAttempt
		if len(ev.Payload) == 0 {
			return Alert{}, false, errors.New("alert: write_denied event without payload")
		}
		if err := json.Unmarshal(ev.Payload, &attempt); err != nil {
			return Alert{}, false, fmt.Errorf("alert: decode write_denied payload: %w", err)
		}
		alert, err := e.OnDeniedWrite(ctx, attempt)
		return alert, true, err
	case domain.GateEventKind(KindWriteUnknown):
		var unknown UnknownWrite
		if len(ev.Payload) == 0 {
			return Alert{}, false, errors.New("alert: write_unknown event without payload")
		}
		if err := json.Unmarshal(ev.Payload, &unknown); err != nil {
			return Alert{}, false, fmt.Errorf("alert: decode write_unknown payload: %w", err)
		}
		alert, err := e.OnWriteUnknown(ctx, unknown)
		return alert, true, err
	case domain.GateEventFailsafe:
		var payload struct {
			Reason string `json:"reason"`
			Detail string `json:"detail"`
		}
		if len(ev.Payload) > 0 {
			if err := json.Unmarshal(ev.Payload, &payload); err != nil {
				return Alert{}, false, fmt.Errorf("alert: decode failsafe payload: %w", err)
			}
		}
		at := ev.At
		if at.IsZero() {
			at = e.clock.Now().UTC()
		}
		alert, err := e.Emit(ctx, NewFailsafeAlert(site, at, payload.Reason, payload.Detail))
		return alert, true, err
	case domain.GateEventBypass:
		var payload struct {
			TargetID       string `json:"target_id"`
			AssetID        string `json:"asset_id"`
			SourceIP       string `json:"source_ip"`
			Protocol       string `json:"protocol"`
			Function       string `json:"function"`
			Address        string `json:"address"`
			ValueHint      string `json:"value_hint"`
			ObservedTarget string `json:"observed_target"`
			Allowed        bool   `json:"allowed"`
		}
		if len(ev.Payload) > 0 {
			if err := json.Unmarshal(ev.Payload, &payload); err != nil {
				return Alert{}, false, fmt.Errorf("alert: decode bypass payload: %w", err)
			}
		}
		at := ev.At
		if at.IsZero() {
			at = e.clock.Now().UTC()
		}
		alert, err := e.Emit(ctx, NewBypassAlert(BypassDetails{
			SiteID: site, At: at,
			TargetID: domain.TargetID(payload.TargetID), AssetID: domain.AssetID(payload.AssetID),
			SourceIP: payload.SourceIP, Protocol: payload.Protocol, Function: payload.Function,
			Address: payload.Address, ValueHint: payload.ValueHint,
			ObservedTarget: payload.ObservedTarget, Allowed: payload.Allowed,
		}))
		return alert, true, err
	case domain.GateEventPlanRejected, domain.GateEventPlanExpired:
		var payload struct {
			PlanID string `json:"plan_id"`
			Reason string `json:"reason"`
			Actor  string `json:"actor"`
		}
		if len(ev.Payload) > 0 {
			if err := json.Unmarshal(ev.Payload, &payload); err != nil {
				return Alert{}, false, fmt.Errorf("alert: decode plan event payload: %w", err)
			}
		}
		at := ev.At
		if at.IsZero() {
			at = e.clock.Now().UTC()
		}
		alert, err := e.Emit(ctx, NewApprovalAlert(site, at, ev.Kind, domain.PlanID(payload.PlanID), payload.Reason, payload.Actor))
		return alert, true, err
	case domain.GateEventPlanCreated, domain.GateEventPlanApproved,
		domain.GateEventSessionOpen, domain.GateEventSessionClose, domain.GateEventWriteAllowed:
		return Alert{}, false, nil // routine lifecycle event: SSE only, no alert
	default:
		return Alert{}, false, fmt.Errorf("alert: unsupported gate event kind %q", ev.Kind)
	}
}

// auditAlert appends the alert audit entry. The store owns the hash chain.
func (e *Engine) auditAlert(ctx context.Context, a Alert, action string, now time.Time) error {
	if e.audit == nil {
		return nil
	}
	reason := a.Title
	if a.Reason != "" {
		reason = fmt.Sprintf("%s (%s)", a.Title, a.Reason)
	}
	return e.audit.Append(ctx, domain.AuditEntry{
		At:         now,
		Actor:      "retailgate",
		Role:       "system",
		Action:     action,
		ObjectType: "gate.alert",
		ObjectID:   a.AlertID,
		Reason:     reason,
	})
}

// notificationFor maps an alert to the transport payload.
func (e *Engine) notificationFor(a Alert) notify.Notification {
	return notify.Notification{
		ID:                a.AlertID,
		Kind:              string(a.Kind),
		At:                a.At,
		Severity:          a.Severity,
		Title:             a.Title,
		Summary:           a.Summary,
		DedupKey:          a.DedupKey,
		SiteID:            a.SiteID,
		TargetID:          a.TargetID,
		SourceIP:          a.SourceIP,
		Reason:            a.Reason,
		ObservedFacts:     append([]string(nil), a.ObservedFacts...),
		Hypothesis:        a.Hypothesis,
		RecommendedChecks: append([]string(nil), a.RecommendedChecks...),
		AckRequired:       a.Severity.Rank() >= domain.SeverityHigh.Rank(),
	}
}

// evictLocked removes one alert from the dedup cache (audit failure path).
func (e *Engine) evictLocked(a Alert) {
	if current, ok := e.recent[a.DedupKey]; ok && current.AlertID == a.AlertID {
		delete(e.recent, a.DedupKey)
	}
	kept := e.order[:0]
	for _, key := range e.order {
		if _, ok := e.recent[key]; ok {
			kept = append(kept, key)
		}
	}
	e.order = kept
}

// pruneLocked bounds the dedup cache by removing the oldest entries.
func (e *Engine) pruneLocked() {
	if len(e.recent) <= e.maxTracked {
		return
	}
	type entry struct {
		key  string
		last time.Time
	}
	entries := make([]entry, 0, len(e.recent))
	for key, alert := range e.recent {
		entries = append(entries, entry{key: key, last: alert.LastSeenAt})
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].last.Equal(entries[j].last) {
			return entries[i].last.Before(entries[j].last)
		}
		return entries[i].key < entries[j].key
	})
	remove := len(entries) - e.maxTracked + 1
	for i := 0; i < remove && i < len(entries); i++ {
		delete(e.recent, entries[i].key)
	}
	kept := e.order[:0]
	for _, key := range e.order {
		if _, ok := e.recent[key]; ok {
			kept = append(kept, key)
		}
	}
	e.order = kept
}

func mergeEvidence(existing, incoming []Evidence) []Evidence {
	const maxEvidence = 16
	out := append([]Evidence(nil), existing...)
	for _, evidence := range incoming {
		if len(out) >= maxEvidence {
			break
		}
		duplicate := false
		for _, present := range out {
			if present.Kind == evidence.Kind && present.RefID == evidence.RefID && present.Description == evidence.Description {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, evidence)
		}
	}
	return out
}
