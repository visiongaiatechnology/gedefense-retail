package alert

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// outcome is the result of one observe operation, applied after the engine lock
// has been released so that callbacks never run under the lock.
type outcome struct {
	alert  domain.Alert
	notify bool
}

// Observe normalises and persists a batch of detection results. Every alert is
// either created, merged into its open counterpart (dedup key) or rejected with a
// typed error; one bad alert never discards the rest of the batch.
func (e *Engine) Observe(ctx context.Context, alerts []domain.Alert) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("alert: observe: %w", err)
	}
	if e.store == nil {
		return ErrNoStore
	}

	e.mu.Lock()
	outcomes := make([]outcome, 0, len(alerts))
	var errs []error
	for _, incoming := range alerts {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		o, err := e.observeOneLocked(ctx, incoming)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		outcomes = append(outcomes, o)
	}
	e.mu.Unlock()

	for _, o := range outcomes {
		e.publishAlert(o.alert)
		if o.notify {
			e.notify(ctx, o.alert)
		}
	}
	return errors.Join(errs...)
}

// observeOneLocked applies the dedup/merge/create decision for a single alert.
// The caller holds e.mu.
func (e *Engine) observeOneLocked(ctx context.Context, incoming domain.Alert) (outcome, error) {
	now := e.clock.Now().UTC()
	normalized, err := e.normalize(incoming, now)
	if err != nil {
		return outcome{}, err
	}

	existing, found, err := e.store.Get(ctx, normalized.AlertID)
	if err != nil {
		return outcome{}, fmt.Errorf("alert: load %q: %w", normalized.AlertID, err)
	}
	if found {
		if !isActive(existing.Status) {
			return outcome{}, fmt.Errorf("%w: alert %q is %s", ErrConflict, existing.AlertID, existing.Status)
		}
		return e.mergeAndStoreLocked(ctx, existing, normalized, now)
	}

	target, ok, err := e.findOpenByDedup(ctx, normalized.DedupKey)
	if err != nil {
		return outcome{}, fmt.Errorf("alert: dedup lookup: %w", err)
	}
	if ok {
		return e.mergeAndStoreLocked(ctx, target, normalized, now)
	}

	created := copyAlert(normalized)
	created.CreatedAt = now
	created.UpdatedAt = now
	created.AuditHistory = appendHistory(created.AuditHistory, domain.AlertAuditEntry{
		At:     now,
		Actor:  "detector",
		Role:   "system",
		Action: "alert.created",
		Note:   "detection rule " + string(created.RuleID) + " version " + created.RuleVersion,
	})
	if err := created.Validate(); err != nil {
		return outcome{}, fmt.Errorf("alert: created alert is invalid: %w", err)
	}
	if err := e.store.Upsert(ctx, created); err != nil {
		return outcome{}, fmt.Errorf("alert: store %q: %w", created.AlertID, err)
	}
	return outcome{alert: created, notify: true}, nil
}

// normalize fills the defensively defaultable fields and rejects the rest.
func (e *Engine) normalize(incoming domain.Alert, now time.Time) (domain.Alert, error) {
	alert := copyAlert(incoming)
	if alert.AlertID == "" {
		id, err := newAlertID()
		if err != nil {
			return domain.Alert{}, err
		}
		alert.AlertID = id
	}
	if err := alert.AlertID.Validate(); err != nil {
		return domain.Alert{}, err
	}
	if alert.DedupKey == "" {
		alert.DedupKey = string(alert.AlertID)
	}
	if !isActive(alert.Status) {
		// A detection is an observation: it enters the workflow as open, never as
		// a closed or acknowledged result.
		alert.Status = domain.AlertOpen
	}
	if alert.FirstSeenAt.IsZero() {
		alert.FirstSeenAt = now
	}
	if alert.LastSeenAt.IsZero() {
		alert.LastSeenAt = alert.FirstSeenAt
	}
	if alert.LastSeenAt.Before(alert.FirstSeenAt) {
		alert.LastSeenAt = alert.FirstSeenAt
	}
	if alert.CreatedAt.IsZero() {
		alert.CreatedAt = now
	}
	if alert.UpdatedAt.IsZero() {
		alert.UpdatedAt = now
	}
	if err := alert.Validate(); err != nil {
		return domain.Alert{}, fmt.Errorf("alert: invalid detection result: %w", err)
	}
	return alert, nil
}

// mergeAndStoreLocked merges a repeated detection into its open counterpart.
// The caller holds e.mu.
func (e *Engine) mergeAndStoreLocked(ctx context.Context, existing, incoming domain.Alert, now time.Time) (outcome, error) {
	merged := copyAlert(existing)
	escalated := false

	if incoming.Severity.Rank() > merged.Severity.Rank() {
		merged.Severity = incoming.Severity
		escalated = true
	}
	if incoming.Confidence > merged.Confidence {
		merged.Confidence = incoming.Confidence
	}
	if later := maxTime(merged.LastSeenAt, incoming.LastSeenAt); !later.Equal(merged.LastSeenAt) {
		merged.LastSeenAt = later
	}

	merged.Evidence = mergeEvidence(merged.Evidence, incoming.Evidence)
	merged.AssetIDs = mergeUnique(merged.AssetIDs, incoming.AssetIDs, maxLinkedIDs)
	merged.ZoneIDs = mergeUnique(merged.ZoneIDs, incoming.ZoneIDs, maxLinkedIDs)
	merged.SensorIDs = mergeUnique(merged.SensorIDs, incoming.SensorIDs, maxLinkedIDs)
	merged.RecommendedActions = mergeActions(merged.RecommendedActions, incoming.RecommendedActions)
	merged.SafetyConstraints = mergeStrings(merged.SafetyConstraints, incoming.SafetyConstraints, maxConstraints)

	if incoming.Correlation != nil && (merged.Correlation == nil || escalated) {
		merged.Correlation = copyAlert(incoming).Correlation
	}
	if escalated {
		// An escalation is the one case where the new observation may carry the
		// better explanation: facts stay, the summary follows the severest signal.
		merged.Title = incoming.Title
		merged.Summary = incoming.Summary
		merged.AuditHistory = appendHistory(merged.AuditHistory, domain.AlertAuditEntry{
			At:     now,
			Actor:  "detector",
			Role:   "system",
			Action: "alert.escalate",
			Note:   "severity raised to " + string(incoming.Severity),
		})
	}
	if isActive(incoming.Status) && statusRank(incoming.Status) > statusRank(merged.Status) {
		merged.Status = incoming.Status
		merged.AuditHistory = appendHistory(merged.AuditHistory, domain.AlertAuditEntry{
			At:     now,
			Actor:  "detector",
			Role:   "system",
			Action: "alert.status",
			Note:   "status advanced to " + string(incoming.Status),
		})
	}
	if merged.Assignee == "" {
		merged.Assignee = incoming.Assignee
	}
	if merged.IncidentID == "" {
		merged.IncidentID = incoming.IncidentID
	}
	if merged.RuleVersion == "" {
		merged.RuleVersion = incoming.RuleVersion
	}
	merged.UpdatedAt = now

	if err := merged.Validate(); err != nil {
		return outcome{}, fmt.Errorf("alert: merged alert is invalid: %w", err)
	}
	if err := e.store.Upsert(ctx, merged); err != nil {
		return outcome{}, fmt.Errorf("alert: store %q: %w", merged.AlertID, err)
	}
	return outcome{alert: merged, notify: escalated}, nil
}

// mergeEvidence unions evidence by kind/reference/description and keeps the
// newest maxEvidence entries.
func mergeEvidence(existing, incoming []domain.Evidence) []domain.Evidence {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	out := make([]domain.Evidence, 0, len(existing)+len(incoming))
	add := func(evidence domain.Evidence) bool {
		key := evidence.Kind + "|" + evidence.RefID + "|" + evidence.Description
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		out = append(out, evidence)
		return true
	}
	for _, evidence := range existing {
		add(evidence)
	}
	for _, evidence := range incoming {
		add(evidence)
	}
	if len(out) > maxEvidence {
		sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
		out = out[len(out)-maxEvidence:]
	}
	return out
}

// mergeUnique appends the values that are not yet present, bounded by limit.
func mergeUnique[T comparable](existing, incoming []T, limit int) []T {
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

// mergeStrings unions short string lists, bounded by limit.
func mergeStrings(existing, incoming []string, limit int) []string {
	return mergeUnique(existing, incoming, limit)
}

// mergeActions unions recommended actions by their action text.
func mergeActions(existing, incoming []domain.RecommendedAction) []domain.RecommendedAction {
	out := append([]domain.RecommendedAction(nil), existing...)
	for _, candidate := range incoming {
		if candidate.Action == "" {
			continue
		}
		duplicate := false
		for _, value := range out {
			if value.Action == candidate.Action {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if len(out) >= maxActions {
			break
		}
		out = append(out, candidate)
	}
	return out
}

// appendHistory appends one workflow entry, keeping the newest maxAuditHistory.
func appendHistory(history []domain.AlertAuditEntry, entry domain.AlertAuditEntry) []domain.AlertAuditEntry {
	out := append(history, entry)
	if len(out) > maxAuditHistory {
		out = out[len(out)-maxAuditHistory:]
	}
	return out
}
