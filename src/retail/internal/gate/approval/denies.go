package approval

import (
	"context"
	"fmt"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Deny records a refused write attempt: audit first, then the denial evidence and
// the stream event. Proxies deny the wire write regardless of the returned error.
func (s *Service) Deny(ctx context.Context, attempt domain.DeniedWriteAttempt) error {
	now := s.clock.Now().UTC()
	if attempt.DenyID == "" {
		id, err := s.idFunc("den_")
		if err != nil {
			return err
		}
		attempt.DenyID = domain.DenyID(id)
	}
	if attempt.At.IsZero() {
		attempt.At = now
	}
	if !ValidDenyReason(attempt.Reason) {
		return fmt.Errorf("%w: %q", ErrInvalidDenyReason, attempt.Reason)
	}
	if !attempt.Severity.Valid() {
		attempt.Severity = s.policy().DenySeverity()
	}
	if err := attempt.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPlan, err)
	}
	if err := s.recordAudit(ctx, "system", "gate_proxy", ActionWriteDenied, ObjectGateDeny, string(attempt.DenyID),
		fmt.Sprintf("reason=%s target=%s protocol=%s function=%s address=%s source=%s",
			attempt.Reason, attempt.TargetID, attempt.Protocol, attempt.Function, attempt.Address, attempt.SourceIP)); err != nil {
		return err
	}
	if err := s.repo.AppendDeny(ctx, attempt); err != nil {
		return fmt.Errorf("%w: append deny: %v", ErrStore, err)
	}
	s.emit(domain.GateEventWriteDenied, map[string]any{
		"deny_id": attempt.DenyID, "reason": attempt.Reason, "target_id": attempt.TargetID,
		"protocol": attempt.Protocol, "function": attempt.Function, "address": attempt.Address,
		"source_ip": attempt.SourceIP, "severity": attempt.Severity, "session_id": attempt.SessionID,
	})
	return nil
}

// Allowed records one authorised write. Values are deliberately not audited (the
// plan already holds the approved value); only protocol/function/address metadata.
func (s *Service) Allowed(ctx context.Context, sessionID domain.SessionID, op domain.WriteOperation) error {
	s.mu.Lock()
	session, ok := s.sessions[sessionID]
	plan, planOK := domain.WritePlan{}, false
	if ok {
		plan, planOK = s.plans[session.PlanID]
	}
	s.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	reason := fmt.Sprintf("protocol=%s function=%s address=%s", op.Protocol, op.Function, op.Address)
	if planOK {
		reason = fmt.Sprintf("plan=%s %s", plan.PlanID, reason)
	}
	if err := s.recordAudit(ctx, string(session.UserID), "vendor_write_requester", ActionWriteAllowed, ObjectGateSession, string(sessionID), reason); err != nil {
		return err
	}
	s.emit(domain.GateEventWriteAllowed, map[string]any{
		"session_id": sessionID, "plan_id": session.PlanID, "target_id": session.TargetID,
		"protocol": op.Protocol, "function": op.Function, "address": op.Address,
	})
	return nil
}
