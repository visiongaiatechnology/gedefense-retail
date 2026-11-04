// Authorization decisions for Modbus writes (default-deny).
package modbusproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Protocol is the protocol label used in plans and deny evidence.
const Protocol = "modbus_tcp"

// Stable deny reasons from the gate engineering contract §5.
const (
	ReasonNoSession              = "no_session"
	ReasonSessionExpired         = "session_expired"
	ReasonSessionRevoked         = "session_revoked"
	ReasonWrongSource            = "wrong_source"
	ReasonWrongTarget            = "wrong_target"
	ReasonNotApproved            = "not_approved"
	ReasonOperationNotApproved   = "operation_not_approved"
	ReasonValueMismatch          = "value_mismatch"
	ReasonAddressMismatch        = "address_mismatch"
	ReasonOutsideWindow          = "outside_window"
	ReasonFailsafeStore          = "failsafe_store"
	ReasonCurrentValueMissing    = "current_value_missing"
	ReasonCurrentValueMismatch   = "current_value_mismatch"
	ReasonCurrentValueUnreadable = "current_value_unreadable"
)

// SessionLookup is the consumer-defined seam to the gate core (contract §2).
// The proxies never import approval/store directly.
type SessionLookup interface {
	// Lookup returns the active session for target+source IP (false = none).
	Lookup(targetID domain.TargetID, sourceIP string, now time.Time) (domain.WriteSession, bool)
	// ConsumeUse counts one use; false means the session is exhausted/invalid.
	ConsumeUse(sessionID domain.SessionID, now time.Time) bool
	// PlanFor returns the approved plan behind a session.
	PlanFor(sessionID domain.SessionID) (domain.WritePlan, bool)
	// Deny reports a refused write attempt (audit + alert + counter).
	Deny(ctx context.Context, attempt domain.DeniedWriteAttempt) error
	// Allowed audits an allowed write operation (no secret values).
	Allowed(ctx context.Context, sessionID domain.SessionID, op domain.WriteOperation) error
}

// WriteUnknownReporter is an optional Alpha extension to SessionLookup: it is
// called when a forwarded write has an unknown effect (timeout after the ADU
// left the gate). The gate core may implement it to audit `write_unknown` and
// raise an alarm. It is never used for retries.
type WriteUnknownReporter interface {
	WriteUnknown(ctx context.Context, sessionID domain.SessionID, op domain.WriteOperation, detail string) error
}

// writeDecision is the outcome of the authorization check.
type writeDecision struct {
	allowed   bool
	reason    string
	exception uint8
	session   domain.WriteSession
	plan      domain.WritePlan
	ops       []domain.WriteOperation
}

// authorizeWrite implements the fail-closed write policy:
//
//	session -> target -> source -> plan -> window -> exact match -> use -> audit
//
// Any error or missing evidence denies and never forwards a byte.
func (p *Proxy) authorizeWrite(ctx context.Context, clientIP string, intent writeIntent) writeDecision {
	now := p.now()
	sessions := p.sessions
	if sessions == nil {
		return writeDecision{reason: ReasonNoSession, exception: 0x01}
	}
	session, ok := sessions.Lookup(p.cfg.TargetID, clientIP, now)
	if !ok {
		return writeDecision{reason: ReasonNoSession, exception: 0x01}
	}
	decision := writeDecision{session: session}
	if session.Revoked {
		decision.reason = ReasonSessionRevoked
		decision.exception = 0x01
		return decision
	}
	if !now.Before(session.ExpiresAt) || session.Uses >= session.MaxUses {
		decision.reason = ReasonSessionExpired
		decision.exception = 0x01
		return decision
	}
	if session.TargetID != p.cfg.TargetID {
		decision.reason = ReasonWrongTarget
		decision.exception = 0x01
		return decision
	}
	if session.SourceIP != clientIP {
		decision.reason = ReasonWrongSource
		decision.exception = 0x01
		return decision
	}
	plan, ok := sessions.PlanFor(session.SessionID)
	if !ok {
		decision.reason = ReasonNotApproved
		decision.exception = 0x01
		return decision
	}
	decision.plan = plan
	if plan.TargetID != p.cfg.TargetID {
		decision.reason = ReasonWrongTarget
		decision.exception = 0x01
		return decision
	}
	if plan.State != domain.PlanApproved && plan.State != domain.PlanExecuted {
		// Only an approved (or already executing) plan can authorise a write.
		decision.reason = ReasonNotApproved
		decision.exception = 0x01
		return decision
	}
	if !plan.InWindow(now) {
		decision.reason = ReasonOutsideWindow
		decision.exception = 0x02
		return decision
	}
	// FC23 embeds a read part: it must also fit the configured read window.
	if intent.hasRead && !readAllowed(p.cfg.ReadRegisters, intent.readFC, intent.readAddr, intent.readQty) {
		decision.reason = ReasonOperationNotApproved
		decision.exception = 0x02
		return decision
	}
	ops, matchReason := matchOperations(plan, intent)
	if matchReason != "" {
		decision.reason = matchReason
		decision.exception = 0x02
		return decision
	}
	decision.ops = ops
	// The use counter and the allowed-audit are committed only after the
	// read-before-write verification succeeded (commitWrite).
	decision.allowed = true
	return decision
}

// commitWrite consumes one session use and audits every allowed operation. It
// must be called only after a successful authorizeWrite + readback verification.
// A store failure stays fail-closed: the write is denied and never forwarded.
func (p *Proxy) commitWrite(ctx context.Context, decision writeDecision) (string, uint8) {
	if p.sessions == nil {
		return ReasonNoSession, 0x01
	}
	if !p.sessions.ConsumeUse(decision.session.SessionID, p.now()) {
		return ReasonSessionExpired, 0x01
	}
	for _, op := range decision.ops {
		if err := p.sessions.Allowed(ctx, decision.session.SessionID, op); err != nil {
			return ReasonFailsafeStore, exServerFailure
		}
	}
	return "", 0
}

// matchOperations maps every canonical write operation onto the approved plan.
// A single mismatch denies the whole PDU: no partial writes.
func matchOperations(plan domain.WritePlan, intent writeIntent) ([]domain.WriteOperation, string) {
	function := functionName(intent.Function)
	matched := make([]domain.WriteOperation, 0, len(intent.Ops))
	for _, op := range intent.Ops {
		found, ok := plan.MatchOperation(Protocol, function, op.Address, op.Value)
		if ok {
			matched = append(matched, found)
			continue
		}
		// Classify the mismatch for the deny evidence: same address with another
		// value is a value mismatch, an unknown address is an address mismatch,
		// an entirely unapproved function is operation_not_approved.
		addressKnown := false
		for _, planned := range plan.Operations {
			if planned.Protocol != Protocol || planned.Function != function {
				continue
			}
			if planned.Address == op.Address {
				addressKnown = true
				break
			}
		}
		if addressKnown {
			return nil, ReasonValueMismatch
		}
		return nil, ReasonAddressMismatch
	}
	return matched, ""
}

// deny reports one refused write to the gate core. Reporting failures never
// change the response: the write is denied either way (fail-closed).
func (p *Proxy) deny(ctx context.Context, clientIP string, intent writeIntent, decision writeDecision) {
	attempt := domain.DeniedWriteAttempt{
		DenyID:    newDenyID(p.now()),
		At:        p.now(),
		SessionID: decision.session.SessionID,
		PlanID:    decision.plan.PlanID,
		UserID:    decision.session.UserID,
		SourceIP:  clientIP,
		TargetID:  p.cfg.TargetID,
		Protocol:  Protocol,
		Function:  functionName(intent.Function),
		Address:   intent.primaryAddress(),
		ValueHint: fmt.Sprintf("items=%d", len(intent.Ops)),
		Reason:    decision.reason,
		Severity:  denySeverity(decision.reason),
	}
	if err := attempt.Validate(); err != nil {
		p.recordError("deny evidence: " + err.Error())
		return
	}
	if p.sessions == nil {
		return
	}
	if err := p.sessions.Deny(ctx, attempt); err != nil {
		p.recordError("deny report: " + err.Error())
	}
}

// newDenyID creates a random deny identifier; the fallback keeps the evidence
// path working even if the entropy source fails (still fail-closed).
func newDenyID(now time.Time) domain.DenyID {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return domain.DenyID("dny_" + hex.EncodeToString(raw[:]))
	}
	return domain.DenyID(fmt.Sprintf("dny_fallback_%d", now.UnixNano()))
}

// denySeverity maps a deny reason onto the alert severity used by the gate core.
func denySeverity(reason string) domain.Severity {
	switch reason {
	case ReasonCurrentValueMismatch,
		ReasonOperationNotApproved, ReasonValueMismatch, ReasonAddressMismatch,
		ReasonOutsideWindow, ReasonNotApproved, ReasonSessionRevoked, ReasonFailsafeStore:
		return domain.SeverityCritical
	default:
		return domain.SeverityHigh
	}
}

// now returns the injected clock time in UTC.
func (p *Proxy) now() time.Time {
	if p.clock != nil {
		return p.clock.Now().UTC()
	}
	return time.Now().UTC()
}
