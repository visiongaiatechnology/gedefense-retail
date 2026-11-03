package approval

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
)

const (
	maxPlanOperations  = 32
	maxPlanWindow      = 24 * time.Hour
	maxPlanReason      = 512
	maxPlanTicketRef   = 128
	clockSkewTolerance = time.Minute
)

// CreatePlan validates a vendor request against target, policy and window and
// persists it in the pending state.
func (s *Service) CreatePlan(ctx context.Context, actor domain.GateUser, req CreatePlanRequest) (domain.WritePlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sweepLocked(ctx, false); err != nil {
		return domain.WritePlan{}, err
	}
	if !actor.HasRole(domain.GateRoleVendorWriteRequester) {
		return domain.WritePlan{}, ErrRoleRequired
	}
	now := s.clock.Now().UTC()
	policy := s.policy()
	target, ok := s.targets(req.TargetID)
	if !ok {
		return domain.WritePlan{}, fmt.Errorf("%w: target %q", ErrTargetNotAllowed, req.TargetID)
	}
	if target.AssetID != req.AssetID {
		return domain.WritePlan{}, fmt.Errorf("%w: asset %q does not belong to target %q", ErrTargetNotAllowed, req.AssetID, req.TargetID)
	}
	if target.Protocol != req.Protocol {
		return domain.WritePlan{}, fmt.Errorf("%w: protocol mismatch for target %q", ErrTargetNotAllowed, req.TargetID)
	}
	if err := validatePlanWindow(req.WindowStart, req.WindowEnd, now, s.timeouts.PlanTTL()); err != nil {
		return domain.WritePlan{}, err
	}
	if len(req.Operations) == 0 || len(req.Operations) > maxPlanOperations {
		return domain.WritePlan{}, fmt.Errorf("%w: 1..%d operations are required", ErrInvalidPlan, maxPlanOperations)
	}
	if strings.TrimSpace(req.Reason) == "" || len(req.Reason) > maxPlanReason {
		return domain.WritePlan{}, fmt.Errorf("%w: reason is required (max %d characters)", ErrInvalidPlan, maxPlanReason)
	}
	if len(req.TicketRef) > maxPlanTicketRef {
		return domain.WritePlan{}, fmt.Errorf("%w: ticket_ref too long", ErrInvalidPlan)
	}
	operations := make([]domain.WriteOperation, 0, len(req.Operations))
	seen := make(map[string]struct{}, len(req.Operations))
	for i, op := range req.Operations {
		if err := op.Validate(); err != nil {
			return domain.WritePlan{}, fmt.Errorf("%w: operation %d: %v", ErrInvalidPlan, i, err)
		}
		if strings.TrimSpace(op.CurrentValue) == "" {
			return domain.WritePlan{}, fmt.Errorf("%w: operation %d: current_value is required", ErrInvalidPlan, i)
		}
		if op.Protocol != req.Protocol {
			return domain.WritePlan{}, fmt.Errorf("%w: operation %d protocol mismatch", ErrInvalidPlan, i)
		}
		if err := s.validateOperationAgainstTarget(policy, target, op); err != nil {
			return domain.WritePlan{}, err
		}
		key := op.Protocol + "|" + op.Function + "|" + op.Address
		if _, dup := seen[key]; dup {
			return domain.WritePlan{}, fmt.Errorf("%w: duplicate operation for %s", ErrInvalidPlan, key)
		}
		seen[key] = struct{}{}
		operations = append(operations, op)
	}

	planID, err := s.idFunc("pln_")
	if err != nil {
		return domain.WritePlan{}, err
	}
	plan := domain.WritePlan{
		PlanID:      domain.PlanID(planID),
		SiteID:      s.siteID,
		TargetID:    req.TargetID,
		AssetID:     req.AssetID,
		Protocol:    req.Protocol,
		Operations:  operations,
		Reason:      strings.TrimSpace(req.Reason),
		TicketRef:   strings.TrimSpace(req.TicketRef),
		RequestedBy: actor.UserID,
		RequestedAt: now,
		WindowStart: req.WindowStart.UTC(),
		WindowEnd:   req.WindowEnd.UTC(),
		State:       domain.PlanPending,
		Critical:    policy.IsCritical(req.AssetID),
		FourEyes:    policy.NeedsFourEyes(req.AssetID),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	hash, err := plan.ComputePlanHash()
	if err != nil {
		return domain.WritePlan{}, fmt.Errorf("%w: %v", ErrInvalidPlan, err)
	}
	plan.PlanHash = hash
	if err := plan.Validate(); err != nil {
		return domain.WritePlan{}, fmt.Errorf("%w: %v", ErrInvalidPlan, err)
	}
	if err := s.recordAudit(ctx, string(actor.UserID), roleOf(actor), ActionPlanCreate, ObjectGatePlan, string(plan.PlanID),
		fmt.Sprintf("target=%s asset=%s operations=%d critical=%t four_eyes=%t", plan.TargetID, plan.AssetID, len(operations), plan.Critical, plan.FourEyes)); err != nil {
		return domain.WritePlan{}, err
	}
	if err := s.repo.SavePlan(ctx, plan); err != nil {
		return domain.WritePlan{}, fmt.Errorf("%w: save plan: %v", ErrStore, err)
	}
	s.plans[plan.PlanID] = plan
	s.emit(domain.GateEventPlanCreated, map[string]any{
		"plan_id": plan.PlanID, "target_id": plan.TargetID, "state": plan.State,
		"requested_by": plan.RequestedBy, "critical": plan.Critical, "four_eyes": plan.FourEyes,
	})
	return copyPlan(plan), nil
}

// validateOperationAgainstTarget enforces the policy allowlist (necessary, not
// sufficient: a fully approved plan is still required).
func (s *Service) validateOperationAgainstTarget(policy config.Policy, target config.Target, op domain.WriteOperation) error {
	switch target.Protocol {
	case "modbus_tcp":
		fc, err := modbusFunctionCode(op.Function)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPlan, err)
		}
		register, err := registerNumber(op.Address)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPlan, err)
		}
		if !policy.ModbusOperationAllowed(target.TargetID, fc, register) {
			return fmt.Errorf("%w: register %d/fc %d for target %s is not in the policy allowlist", ErrTargetNotAllowed, register, fc, target.TargetID)
		}
	case "http":
		method, err := httpWriteMethod(op.Function)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPlan, err)
		}
		if !strings.HasPrefix(op.Address, "/") {
			return fmt.Errorf("%w: http address must be an absolute path", ErrInvalidPlan)
		}
		if !policy.HTTPOperationAllowed(target.TargetID, method, op.Address) {
			return fmt.Errorf("%w: %s %s for target %s is not in the policy allowlist", ErrTargetNotAllowed, method, op.Address, target.TargetID)
		}
	default:
		return fmt.Errorf("%w: protocol %q has no write allowlist", ErrTargetNotAllowed, target.Protocol)
	}
	return nil
}

// Approve records one approval decision. It returns a plaintext token exactly once,
// when the plan becomes fully approved.
func (s *Service) Approve(ctx context.Context, actor domain.GateUser, planID domain.PlanID, req ApproveRequest) (ApproveResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sweepLocked(ctx, true); err != nil {
		return ApproveResult{}, err
	}
	if !isApprover(actor) {
		return ApproveResult{}, ErrRoleRequired
	}
	plan, ok := s.plans[planID]
	if !ok {
		return ApproveResult{}, ErrNotFound
	}
	if plan.State != domain.PlanPending {
		return ApproveResult{}, ErrAlreadyDecided
	}
	if plan.RequestedBy == actor.UserID {
		return ApproveResult{}, ErrSelfApproval
	}
	now := s.clock.Now().UTC()
	if !now.Before(plan.WindowEnd) || now.After(plan.RequestedAt.Add(s.timeouts.ApprovalTTL())) {
		if err := s.expirePlanLocked(ctx, planID, plan, now); err != nil {
			return ApproveResult{}, err
		}
		return ApproveResult{}, ErrWindowExpired
	}
	hash, err := plan.ComputePlanHash()
	if err != nil {
		return ApproveResult{}, fmt.Errorf("%w: %v", ErrInvalidPlan, err)
	}
	if plan.PlanHash != hash {
		return ApproveResult{}, ErrPlanHashMismatch
	}
	if req.PlanHash != "" && req.PlanHash != hash {
		return ApproveResult{}, ErrPlanHashMismatch
	}
	if !req.MFAUsed {
		return ApproveResult{}, ErrMFARequired
	}
	if plan.ApprovedBy(actor.UserID) {
		return ApproveResult{}, ErrAlreadyApproved
	}
	approvalID, err := s.idFunc("apr_")
	if err != nil {
		return ApproveResult{}, err
	}
	plan.Approvals = append(plan.Approvals, domain.GateApproval{
		ApprovalID: domain.ApprovalID(approvalID),
		PlanID:     plan.PlanID,
		ApproverID: actor.UserID,
		Role:       highestRole(actor),
		Approved:   true,
		Comment:    strings.TrimSpace(req.Comment),
		PlanHash:   hash,
		MFAUsed:    true,
		At:         now,
	})
	masterApproved := false
	for _, approval := range plan.Approvals {
		if approval.Approved && approval.Role == domain.GateRoleMasterAdmin {
			masterApproved = true
			break
		}
	}
	plan.UpdatedAt = now
	if !plan.FullyApproved(masterApproved) {
		if err := s.recordAudit(ctx, string(actor.UserID), roleOf(actor), ActionPlanApproveWait, ObjectGatePlan, string(plan.PlanID),
			fmt.Sprintf("approvals=%d/%d master=%t comment=%q", plan.ApprovalCount(), plan.RequiredApprovals(), masterApproved, req.Comment)); err != nil {
			return ApproveResult{}, err
		}
		if err := s.repo.SavePlan(ctx, plan); err != nil {
			return ApproveResult{}, fmt.Errorf("%w: save plan: %v", ErrStore, err)
		}
		s.plans[plan.PlanID] = plan
		return ApproveResult{Plan: copyPlan(plan)}, nil
	}

	tokenPlain, token, err := s.createTokenLocked(ctx, plan, now)
	if err != nil {
		return ApproveResult{}, err
	}
	if err := s.recordAudit(ctx, string(actor.UserID), roleOf(actor), ActionPlanApprove, ObjectGatePlan, string(plan.PlanID),
		"approved by "+string(actor.UserID)+" comment="+req.Comment); err != nil {
		return ApproveResult{}, err
	}
	plan.State = domain.PlanApproved
	plan.UpdatedAt = now
	if err := s.repo.SaveToken(ctx, token); err != nil {
		return ApproveResult{}, fmt.Errorf("%w: save token: %v", ErrStore, err)
	}
	if err := s.repo.SavePlan(ctx, plan); err != nil {
		return ApproveResult{}, fmt.Errorf("%w: save plan: %v", ErrStore, err)
	}
	s.tokens[token.TokenID] = token
	s.tokenByHash[token.TokenHash] = token.TokenID
	s.plans[plan.PlanID] = plan
	s.emit(domain.GateEventPlanApproved, map[string]any{
		"plan_id": plan.PlanID, "target_id": plan.TargetID, "state": plan.State,
		"approvals": plan.ApprovalCount(), "critical": plan.Critical,
	})
	return ApproveResult{Plan: copyPlan(plan), Token: &TokenGrant{Token: tokenPlain, ExpiresAt: token.ExpiresAt}}, nil
}

// Reject rejects a pending plan.
func (s *Service) Reject(ctx context.Context, actor domain.GateUser, planID domain.PlanID, reason string) (domain.WritePlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sweepLocked(ctx, true); err != nil {
		return domain.WritePlan{}, err
	}
	if !isApprover(actor) {
		return domain.WritePlan{}, ErrRoleRequired
	}
	plan, ok := s.plans[planID]
	if !ok {
		return domain.WritePlan{}, ErrNotFound
	}
	if plan.State != domain.PlanPending {
		return domain.WritePlan{}, ErrAlreadyDecided
	}
	if strings.TrimSpace(reason) == "" {
		return domain.WritePlan{}, fmt.Errorf("%w: rejection reason is required", ErrInvalidPlan)
	}
	now := s.clock.Now().UTC()
	if err := s.recordAudit(ctx, string(actor.UserID), roleOf(actor), ActionPlanReject, ObjectGatePlan, string(planID), reason); err != nil {
		return domain.WritePlan{}, err
	}
	plan.State = domain.PlanRejected
	plan.UpdatedAt = now
	if err := s.repo.SavePlan(ctx, plan); err != nil {
		return domain.WritePlan{}, fmt.Errorf("%w: save plan: %v", ErrStore, err)
	}
	s.plans[planID] = plan
	s.emit(domain.GateEventPlanRejected, map[string]any{"plan_id": planID, "state": plan.State, "reason": reason})
	return copyPlan(plan), nil
}

// Cancel lets the requester cancel their own still-pending plan.
func (s *Service) Cancel(ctx context.Context, actor domain.GateUser, planID domain.PlanID) (domain.WritePlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sweepLocked(ctx, true); err != nil {
		return domain.WritePlan{}, err
	}
	plan, ok := s.plans[planID]
	if !ok {
		return domain.WritePlan{}, ErrNotFound
	}
	if plan.RequestedBy != actor.UserID {
		return domain.WritePlan{}, ErrNotRequester
	}
	if plan.State != domain.PlanPending {
		return domain.WritePlan{}, ErrAlreadyDecided
	}
	now := s.clock.Now().UTC()
	if err := s.recordAudit(ctx, string(actor.UserID), roleOf(actor), ActionPlanCancel, ObjectGatePlan, string(planID), "cancelled by requester"); err != nil {
		return domain.WritePlan{}, err
	}
	plan.State = domain.PlanCancelled
	plan.UpdatedAt = now
	if err := s.repo.SavePlan(ctx, plan); err != nil {
		return domain.WritePlan{}, fmt.Errorf("%w: save plan: %v", ErrStore, err)
	}
	s.plans[planID] = plan
	s.emit(domain.GateEventPlanRejected, map[string]any{"plan_id": planID, "state": plan.State})
	return copyPlan(plan), nil
}

// createTokenLocked creates the one-time token. Only its SHA-256 hash is stored;
// the plaintext is returned once. Older tokens of the plan are revoked first.
func (s *Service) createTokenLocked(ctx context.Context, plan domain.WritePlan, now time.Time) (string, domain.WriteToken, error) {
	for _, token := range s.tokens {
		if token.PlanID != plan.PlanID || token.Revoked {
			continue
		}
		token.Revoked = true
		token.RevokedAt = now
		if err := s.repo.SaveToken(ctx, token); err != nil {
			return "", domain.WriteToken{}, fmt.Errorf("%w: revoke superseded token: %v", ErrStore, err)
		}
		s.tokens[token.TokenID] = token
	}
	tokenID, err := s.idFunc("tok_")
	if err != nil {
		return "", domain.WriteToken{}, err
	}
	plain := make([]byte, 32)
	if _, err := rand.Read(plain); err != nil {
		return "", domain.WriteToken{}, fmt.Errorf("approval: generate token: %w", err)
	}
	plaintext := hex.EncodeToString(plain)
	sum := sha256.Sum256([]byte(plaintext))
	policy := s.policy()
	maxUses := policy.Token.MaxUses
	if maxUses < 1 {
		maxUses = 1
	}
	token := domain.WriteToken{
		TokenID:   domain.TokenID(tokenID),
		PlanID:    plan.PlanID,
		TokenHash: hex.EncodeToString(sum[:]),
		CreatedAt: now,
		ExpiresAt: now.Add(s.timeouts.TokenTTL()),
		MaxUses:   maxUses,
	}
	if err := token.Validate(); err != nil {
		return "", domain.WriteToken{}, fmt.Errorf("%w: token: %v", ErrInvalidPlan, err)
	}
	return plaintext, token, nil
}

// validatePlanWindow enforces the window rules (not in the past, ≤24 h, within TTL).
func validatePlanWindow(start, end, now time.Time, planTTL time.Duration) error {
	if start.IsZero() || end.IsZero() {
		return fmt.Errorf("%w: window_start and window_end are required", ErrInvalidPlan)
	}
	start, end = start.UTC(), end.UTC()
	if !end.After(start) {
		return fmt.Errorf("%w: window_end must be after window_start", ErrInvalidPlan)
	}
	if end.Sub(start) > maxPlanWindow {
		return fmt.Errorf("%w: the window must not exceed 24 hours", ErrInvalidPlan)
	}
	if start.Before(now.Add(-clockSkewTolerance)) {
		return fmt.Errorf("%w: window_start is in the past", ErrInvalidPlan)
	}
	if planTTL > 0 && end.After(now.Add(planTTL)) {
		return fmt.Errorf("%w: window_end exceeds the plan TTL", ErrInvalidPlan)
	}
	return nil
}

// modbusFunctionCode parses "fc6", "FC06" or "6".
func modbusFunctionCode(function string) (int, error) {
	text := strings.ToLower(strings.TrimSpace(function))
	text = strings.TrimPrefix(text, "fc")
	code, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("modbus function %q is not a function code", function)
	}
	if _, ok := map[int]struct{}{5: {}, 6: {}, 15: {}, 16: {}, 22: {}, 23: {}}[code]; !ok {
		return 0, fmt.Errorf("modbus function code %d is not a write function", code)
	}
	return code, nil
}

// registerNumber parses a decimal register address.
func registerNumber(address string) (int, error) {
	register, err := strconv.Atoi(strings.TrimSpace(address))
	if err != nil || register < 0 || register > 65535 {
		return 0, fmt.Errorf("register address %q is invalid", address)
	}
	return register, nil
}

// httpWriteMethod parses "http_post", "post" or "POST".
func httpWriteMethod(function string) (string, error) {
	text := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(function)), "http_")))
	switch text {
	case "POST", "PUT", "PATCH", "DELETE":
		return text, nil
	}
	return "", fmt.Errorf("http function %q is not a write method", function)
}

// isApprover reports whether the user may approve or reject.
func isApprover(user domain.GateUser) bool {
	return user.HasRole(domain.GateRoleApprover) || user.HasRole(domain.GateRoleMasterAdmin)
}

// highestRole returns the most privileged gate role of a user for audit records.
func highestRole(user domain.GateUser) domain.GateRole {
	for _, role := range []domain.GateRole{domain.GateRoleMasterAdmin, domain.GateRoleApprover, domain.GateRoleAuditor,
		domain.GateRoleVendorWriteRequester, domain.GateRoleVendorRead} {
		if user.HasRole(role) {
			return role
		}
	}
	return ""
}

// roleOf renders the audit role string.
func roleOf(user domain.GateUser) string { return string(highestRole(user)) }
