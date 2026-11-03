package alert

import (
	"context"
	"fmt"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// maxNoteLength bounds operator notes stored in the alert history.
const maxNoteLength = 4096

// Ack acknowledges an open alert. The action is audited in the hash-chained audit
// log before the alert state changes: an unauditable operator action is refused.
func (e *Engine) Ack(ctx context.Context, id domain.AlertID, actor domain.UserID, role, note string) (domain.Alert, error) {
	if err := ctx.Err(); err != nil {
		return domain.Alert{}, fmt.Errorf("alert: ack: %w", err)
	}
	e.mu.Lock()
	alert, err := e.ackLocked(ctx, id, actor, role, note)
	e.mu.Unlock()
	if err != nil {
		return domain.Alert{}, err
	}
	e.publishAlert(alert)
	return alert, nil
}

// Assign assigns an alert to an operator. The API layer verifies that the
// assignee is an active configured user; the engine verifies the identifier shape.
func (e *Engine) Assign(ctx context.Context, id domain.AlertID, actor domain.UserID, role string, assignee domain.UserID, note string) (domain.Alert, error) {
	if err := ctx.Err(); err != nil {
		return domain.Alert{}, fmt.Errorf("alert: assign: %w", err)
	}
	if err := assignee.Validate(); err != nil {
		return domain.Alert{}, fmt.Errorf("%w: %v", ErrInvalidAssignee, err)
	}
	e.mu.Lock()
	alert, err := e.assignLocked(ctx, id, actor, role, assignee, note)
	e.mu.Unlock()
	if err != nil {
		return domain.Alert{}, err
	}
	e.publishAlert(alert)
	return alert, nil
}

// Close closes an alert with a terminal status.
func (e *Engine) Close(ctx context.Context, id domain.AlertID, actor domain.UserID, role string, status domain.AlertStatus, note string) (domain.Alert, error) {
	if err := ctx.Err(); err != nil {
		return domain.Alert{}, fmt.Errorf("alert: close: %w", err)
	}
	switch status {
	case domain.AlertResolved, domain.AlertClosed, domain.AlertFalsePositive:
	default:
		return domain.Alert{}, fmt.Errorf("%w: %q", ErrInvalidStatus, status)
	}
	e.mu.Lock()
	alert, err := e.closeLocked(ctx, id, actor, role, status, note)
	e.mu.Unlock()
	if err != nil {
		return domain.Alert{}, err
	}
	e.publishAlert(alert)
	return alert, nil
}

// ackLocked acknowledges an alert. The caller holds e.mu.
func (e *Engine) ackLocked(ctx context.Context, id domain.AlertID, actor domain.UserID, role, note string) (domain.Alert, error) {
	alert, err := e.workflowAlertLocked(ctx, id, actor, role, note, "alert.ack")
	if err != nil {
		return domain.Alert{}, err
	}
	alert.Status = domain.AlertAcknowledged
	alert.AuditHistory = appendHistory(alert.AuditHistory, domain.AlertAuditEntry{
		At: e.clock.Now().UTC(), Actor: string(actor), Role: role, Action: "alert.ack", Note: note,
	})
	return e.persistWorkflowLocked(ctx, alert)
}

// assignLocked assigns an alert. The caller holds e.mu.
func (e *Engine) assignLocked(ctx context.Context, id domain.AlertID, actor domain.UserID, role string, assignee domain.UserID, note string) (domain.Alert, error) {
	alert, err := e.workflowAlertLocked(ctx, id, actor, role, note, "alert.assign")
	if err != nil {
		return domain.Alert{}, err
	}
	alert.Assignee = assignee
	alert.AuditHistory = appendHistory(alert.AuditHistory, domain.AlertAuditEntry{
		At: e.clock.Now().UTC(), Actor: string(actor), Role: role, Action: "alert.assign",
		Note: "assigned to " + string(assignee) + noteSuffix(note),
	})
	return e.persistWorkflowLocked(ctx, alert)
}

// closeLocked closes an alert. The caller holds e.mu.
func (e *Engine) closeLocked(ctx context.Context, id domain.AlertID, actor domain.UserID, role string, status domain.AlertStatus, note string) (domain.Alert, error) {
	alert, err := e.workflowAlertLocked(ctx, id, actor, role, note, "alert.close")
	if err != nil {
		return domain.Alert{}, err
	}
	alert.Status = status
	if alert.Assignee == "" {
		alert.Assignee = actor
	}
	alert.AuditHistory = appendHistory(alert.AuditHistory, domain.AlertAuditEntry{
		At: e.clock.Now().UTC(), Actor: string(actor), Role: role, Action: "alert.close",
		Note: "status set to " + string(status) + noteSuffix(note),
	})
	return e.persistWorkflowLocked(ctx, alert)
}

// workflowAlertLocked loads an alert and enforces the actor, role and workflow
// preconditions shared by all operator actions. The caller holds e.mu.
func (e *Engine) workflowAlertLocked(ctx context.Context, id domain.AlertID, actor domain.UserID, role, note, action string) (domain.Alert, error) {
	if !isOperatorRole(role) {
		return domain.Alert{}, fmt.Errorf("%w: %q", ErrForbidden, role)
	}
	if err := actor.Validate(); err != nil {
		return domain.Alert{}, fmt.Errorf("%w: %v", ErrInvalidActor, err)
	}
	if len(note) > maxNoteLength {
		return domain.Alert{}, fmt.Errorf("alert: note is longer than %d characters", maxNoteLength)
	}
	if err := id.Validate(); err != nil {
		return domain.Alert{}, fmt.Errorf("alert: %w", err)
	}
	if e.store == nil {
		return domain.Alert{}, ErrNoStore
	}
	stored, ok, err := e.store.Get(ctx, id)
	if err != nil {
		return domain.Alert{}, fmt.Errorf("alert: load %q: %w", id, err)
	}
	if !ok {
		return domain.Alert{}, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	if !isActive(stored.Status) {
		return domain.Alert{}, fmt.Errorf("%w: %q is %s", ErrConflict, id, stored.Status)
	}
	if err := e.appendOperatorAudit(ctx, stored, actor, role, action, note); err != nil {
		return domain.Alert{}, err
	}
	return stored, nil
}

// persistWorkflowLocked stores the mutated alert. The caller holds e.mu; the SSE
// fan-out happens after the lock is released.
func (e *Engine) persistWorkflowLocked(ctx context.Context, alert domain.Alert) (domain.Alert, error) {
	alert.UpdatedAt = e.clock.Now().UTC()
	alert.LastSeenAt = maxTime(alert.LastSeenAt, alert.UpdatedAt)
	if err := alert.Validate(); err != nil {
		return domain.Alert{}, fmt.Errorf("alert: workflow result is invalid: %w", err)
	}
	if err := e.store.Upsert(ctx, alert); err != nil {
		return domain.Alert{}, fmt.Errorf("alert: store %q: %w", alert.AlertID, err)
	}
	return alert, nil
}

// noteSuffix formats the optional operator note.
func noteSuffix(note string) string {
	trimmed := strings.TrimSpace(note)
	if trimmed == "" {
		return ""
	}
	return ": " + trimmed
}
