package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// RedeemToken exchanges a one-time token for a write session bound to the
// transport source address.
func (s *Service) RedeemToken(ctx context.Context, actor domain.GateUser, req RedeemRequest) (domain.WriteSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sweepLocked(ctx, true); err != nil {
		return domain.WriteSession{}, err
	}
	if active, reason := s.failsafeActive(); active {
		return domain.WriteSession{}, fmt.Errorf("%w: %s", ErrFailsafe, reason)
	}
	if !actor.HasRole(domain.GateRoleVendorWriteRequester) {
		return domain.WriteSession{}, ErrRoleRequired
	}
	plan, ok := s.plans[req.PlanID]
	if !ok {
		return domain.WriteSession{}, ErrNotFound
	}
	if plan.RequestedBy != actor.UserID {
		return domain.WriteSession{}, ErrForbidden
	}
	if plan.State != domain.PlanApproved {
		return domain.WriteSession{}, ErrNotApproved
	}
	sum := sha256.Sum256([]byte(req.Token))
	tokenID, ok := s.tokenByHash[hex.EncodeToString(sum[:])]
	if !ok {
		return domain.WriteSession{}, ErrTokenInvalid
	}
	token := s.tokens[tokenID]
	if token.PlanID != plan.PlanID {
		return domain.WriteSession{}, ErrTokenInvalid
	}
	now := s.clock.Now().UTC()
	if !now.Before(token.ExpiresAt) {
		return domain.WriteSession{}, ErrTokenExpired
	}
	if token.Uses >= token.MaxUses {
		return domain.WriteSession{}, ErrTokenUsed
	}
	if token.BoundIP != "" && token.BoundIP != req.SourceIP {
		return domain.WriteSession{}, ErrWrongSource
	}
	if token.Revoked {
		return domain.WriteSession{}, ErrTokenInvalid
	}
	hash, err := plan.ComputePlanHash()
	if err != nil || hash != plan.PlanHash {
		return domain.WriteSession{}, ErrPlanHashMismatch
	}
	if !plan.InWindow(now) {
		return domain.WriteSession{}, ErrOutsideWindow
	}
	sessionID, err := s.idFunc("ses_")
	if err != nil {
		return domain.WriteSession{}, err
	}
	expires := now.Add(s.timeouts.SessionTTL())
	if plan.WindowEnd.Before(expires) {
		expires = plan.WindowEnd
	}
	maxUses := s.timeouts.WriteSessionMaxUses
	if maxUses < 1 {
		maxUses = 1
	}
	session := domain.WriteSession{
		SessionID: domain.SessionID(sessionID),
		PlanID:    plan.PlanID,
		TargetID:  plan.TargetID,
		UserID:    actor.UserID,
		SourceIP:  req.SourceIP,
		CreatedAt: now,
		ExpiresAt: expires,
		MaxUses:   maxUses,
	}
	if err := session.Validate(); err != nil {
		return domain.WriteSession{}, fmt.Errorf("%w: %v", ErrInvalidPlan, err)
	}
	if err := s.recordAudit(ctx, string(actor.UserID), roleOf(actor), ActionSessionOpen, ObjectGateSession, string(session.SessionID),
		fmt.Sprintf("plan=%s target=%s source=%s max_uses=%d", plan.PlanID, plan.TargetID, req.SourceIP, maxUses)); err != nil {
		return domain.WriteSession{}, err
	}
	token.Uses++
	if token.Uses >= token.MaxUses {
		token.Revoked = true
		token.RevokedAt = now
	}
	policy := s.policy()
	if policy.Token.BindSourceIP && token.BoundIP == "" {
		token.BoundIP = req.SourceIP
	}
	if err := s.repo.SaveToken(ctx, token); err != nil {
		return domain.WriteSession{}, fmt.Errorf("%w: save token: %v", ErrStore, err)
	}
	if err := s.repo.SaveSession(ctx, session); err != nil {
		return domain.WriteSession{}, fmt.Errorf("%w: save session: %v", ErrStore, err)
	}
	s.tokens[token.TokenID] = token
	s.sessions[session.SessionID] = session
	s.emit(domain.GateEventSessionOpen, map[string]any{
		"session_id": session.SessionID, "plan_id": session.PlanID, "target_id": session.TargetID,
		"user_id": session.UserID, "source_ip": session.SourceIP, "expires_at": session.ExpiresAt,
	})
	return session, nil
}

// RevokeSession revokes a write session immediately (proxies see it on the next
// Lookup). Revocation is audited and published.
func (s *Service) RevokeSession(ctx context.Context, actor domain.GateUser, sessionID domain.SessionID, reason string) (domain.WriteSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !isApprover(actor) {
		return domain.WriteSession{}, ErrRoleRequired
	}
	session, ok := s.sessions[sessionID]
	if !ok {
		return domain.WriteSession{}, ErrNotFound
	}
	if session.Revoked {
		return copySession(session), nil
	}
	now := s.clock.Now().UTC()
	if err := s.recordAudit(ctx, string(actor.UserID), roleOf(actor), ActionSessionRevoke, ObjectGateSession, string(sessionID), reason); err != nil {
		return domain.WriteSession{}, err
	}
	session.Revoked = true
	session.RevokedAt = now
	session.RevokedBy = actor.UserID
	if err := s.repo.SaveSession(ctx, session); err != nil {
		return domain.WriteSession{}, fmt.Errorf("%w: save session: %v", ErrStore, err)
	}
	s.sessions[sessionID] = session
	s.emit(domain.GateEventSessionClose, map[string]any{
		"session_id": session.SessionID, "plan_id": session.PlanID, "reason": reason,
	})
	return copySession(session), nil
}

// Lookup implements SessionLookup: the most recent usable session for the target
// and source address. A fail-safe state blocks every write.
func (s *Service) Lookup(targetID domain.TargetID, sourceIP string, now time.Time) (domain.WriteSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if active, _ := s.failsafeActive(); active {
		return domain.WriteSession{}, false
	}
	var best domain.WriteSession
	found := false
	for _, session := range s.sessions {
		if session.TargetID != targetID || session.SourceIP != sourceIP || !session.Usable(now) {
			continue
		}
		if !found || session.CreatedAt.After(best.CreatedAt) {
			best, found = session, true
		}
	}
	if !found {
		return domain.WriteSession{}, false
	}
	return copySession(best), true
}

// ConsumeUse implements SessionLookup: it counts one use and fails closed when the
// session is not usable or the counter cannot be persisted.
func (s *Service) ConsumeUse(sessionID domain.SessionID, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if active, _ := s.failsafeActive(); active {
		return false
	}
	session, ok := s.sessions[sessionID]
	if !ok || !session.Usable(now) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.recordAudit(ctx, string(session.UserID), "vendor_write_requester", ActionSessionUse, ObjectGateSession, string(sessionID),
		fmt.Sprintf("plan=%s target=%s use=%d/%d", session.PlanID, session.TargetID, session.Uses+1, session.MaxUses)); err != nil {
		return false
	}
	previous := session
	session.Uses++
	exhausted := session.Uses >= session.MaxUses
	if err := s.repo.SaveSession(ctx, session); err != nil {
		s.sessions[sessionID] = previous
		return false
	}
	s.sessions[sessionID] = session
	if !exhausted {
		return true
	}
	plan, planOK := s.plans[session.PlanID]
	if !planOK {
		return true
	}
	if err := s.recordAudit(ctx, string(session.UserID), "vendor_write_requester", ActionPlanExecuted, ObjectGatePlan, string(plan.PlanID),
		"session exhausted after authorised use"); err != nil {
		return false
	}
	plan.State = domain.PlanExecuted
	plan.ExecutedAt = now
	plan.ExecutedBy = session.UserID
	plan.UpdatedAt = now
	if err := s.repo.SavePlan(ctx, plan); err != nil {
		return false
	}
	s.plans[plan.PlanID] = plan
	s.emit(domain.GateEventSessionClose, map[string]any{
		"session_id": session.SessionID, "plan_id": session.PlanID, "state": plan.State,
	})
	return true
}

// PlanFor implements SessionLookup: the approved plan behind a session.
func (s *Service) PlanFor(sessionID domain.SessionID) (domain.WritePlan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return domain.WritePlan{}, false
	}
	plan, ok := s.plans[session.PlanID]
	if !ok {
		return domain.WritePlan{}, false
	}
	return copyPlan(plan), true
}

// ReportWriteUnknown records a write whose device outcome is unknown (timeout,
// client disconnect, read error). The session is revoked fail-closed, the plan is
// NOT marked executed and no automatic retry happens.
func (s *Service) ReportWriteUnknown(ctx context.Context, sessionID domain.SessionID, op domain.WriteOperation, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return ErrNotFound
	}
	now := s.clock.Now().UTC()
	unknownID, err := s.idFunc("unk_")
	if err != nil {
		return err
	}
	record := WriteUnknown{
		UnknownID:   unknownID,
		At:          now,
		PlanID:      session.PlanID,
		SessionID:   session.SessionID,
		UserID:      session.UserID,
		TargetID:    session.TargetID,
		Protocol:    op.Protocol,
		Function:    op.Function,
		Address:     op.Address,
		Reason:      reason,
		Severity:    domain.SeverityCritical,
		Recommended: "do not retry; read back the device value and verify the configuration before any new approval",
	}
	if op.Protocol == "" {
		record.Protocol = "unknown"
	}
	if op.Function == "" {
		record.Function = "unknown"
	}
	if verr := record.Validate(); verr != nil {
		return verr
	}
	if err := s.recordAudit(ctx, string(session.UserID), "vendor_write_requester", ActionWriteUnknown, ObjectGateWriteUnknown, unknownID,
		fmt.Sprintf("plan=%s target=%s protocol=%s function=%s address=%s reason=%s",
			record.PlanID, record.TargetID, record.Protocol, record.Function, record.Address, record.Reason)); err != nil {
		return err
	}
	if err := s.repo.SaveWriteUnknown(ctx, unknownID, record); err != nil {
		return fmt.Errorf("%w: save write-unknown: %v", ErrStore, err)
	}
	// Fail-closed: the session can never be used again after an ambiguous write.
	session.Revoked = true
	session.RevokedAt = now
	if err := s.repo.SaveSession(ctx, session); err != nil {
		s.sessions[sessionID] = session
		return fmt.Errorf("%w: revoke session: %v", ErrStore, err)
	}
	s.sessions[sessionID] = session
	s.emit(domain.GateEventWriteUnknown, map[string]any{
		"unknown_id": unknownID, "plan_id": record.PlanID, "session_id": record.SessionID,
		"target_id": record.TargetID, "reason": record.Reason, "severity": record.Severity,
		"protocol": record.Protocol, "function": record.Function, "address": record.Address,
	})
	return nil
}

// ListWriteUnknown returns the write-unknown records, optionally filtered by plan.
func (s *Service) ListWriteUnknown(ctx context.Context, planID domain.PlanID) ([]WriteUnknown, error) {
	documents, err := s.repo.ListWriteUnknown(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: list write-unknown: %v", ErrStore, err)
	}
	out := make([]WriteUnknown, 0, len(documents))
	for _, document := range documents {
		var record WriteUnknown
		if derr := json.Unmarshal(document, &record); derr != nil {
			return nil, fmt.Errorf("%w: decode write-unknown: %v", ErrCorruptState, derr)
		}
		if verr := record.Validate(); verr != nil {
			return nil, verr
		}
		if planID != "" && record.PlanID != planID {
			continue
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return out[i].UnknownID < out[j].UnknownID
	})
	return out, nil
}
