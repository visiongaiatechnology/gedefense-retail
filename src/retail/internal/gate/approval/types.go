package approval

import (
	"context"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// CreatePlanRequest is one vendor write request.
type CreatePlanRequest struct {
	TargetID    domain.TargetID
	AssetID     domain.AssetID
	Protocol    string
	Operations  []domain.WriteOperation
	Reason      string
	TicketRef   string
	WindowStart time.Time
	WindowEnd   time.Time
}

// ApproveRequest is one approval decision.
type ApproveRequest struct {
	Comment string
	// PlanHash is the hash the approver saw; empty disables the stale-hash check.
	PlanHash string
	// MFAUsed must be true: the API verifies the X-Gate-MFA TOTP before calling.
	MFAUsed bool
}

// TokenGrant is the single plaintext presentation of a one-time token. It is
// returned exactly once and never stored, logged or audited.
type TokenGrant struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ApproveResult is the outcome of an approval. Token is non-nil only when the
// plan reached the final approved state.
type ApproveResult struct {
	Plan  domain.WritePlan
	Token *TokenGrant
}

// RedeemRequest redeems a one-time token for a write session.
type RedeemRequest struct {
	PlanID domain.PlanID
	Token  string
	// SourceIP must be the transport peer address, never a client header.
	SourceIP string
}

// PlanCounts aggregates plan states for the status endpoint.
type PlanCounts struct {
	Pending   int `json:"pending"`
	Approved  int `json:"approved"`
	Executed  int `json:"executed"`
	Rejected  int `json:"rejected"`
	Expired   int `json:"expired"`
	Cancelled int `json:"cancelled"`
}

// SessionCounts aggregates session states for the status endpoint.
type SessionCounts struct {
	Active       int `json:"active"`
	RevokedToday int `json:"revoked_today"`
}

// DenyStats aggregates denial evidence for the status endpoint.
type DenyStats struct {
	Last24h int                         `json:"last_24h"`
	Last    []domain.DeniedWriteAttempt `json:"last"`
}

// AuditStats is the verified audit chain summary.
type AuditStats struct {
	ChainOK  bool   `json:"chain_ok"`
	Entries  int    `json:"entries"`
	FirstSeq uint64 `json:"first_seq"`
}

// Status is the management status snapshot.
type Status struct {
	Plans    PlanCounts    `json:"plans"`
	Sessions SessionCounts `json:"sessions"`
	Denies   DenyStats     `json:"denies"`
	Audit    AuditStats    `json:"audit"`
}

// WriteUnknown records a write attempt whose device outcome is unknown (timeout,
// client disconnect, read error). It is never counted as success and the gate
// never retries automatically (double-write risk): the operator must read back
// the device value first.
type WriteUnknown struct {
	UnknownID   string            `json:"unknown_id"`
	At          time.Time         `json:"at"`
	PlanID      domain.PlanID     `json:"plan_id,omitempty"`
	SessionID   domain.SessionID  `json:"session_id,omitempty"`
	UserID      domain.GateUserID `json:"user_id,omitempty"`
	TargetID    domain.TargetID   `json:"target_id"`
	Protocol    string            `json:"protocol"`
	Function    string            `json:"function"`
	Address     string            `json:"address,omitempty"`
	Reason      string            `json:"reason"`
	Severity    domain.Severity   `json:"severity"`
	Recommended string            `json:"recommended"`
}

// Validate checks the write-unknown evidence record.
func (u WriteUnknown) Validate() error {
	if u.UnknownID == "" || len(u.UnknownID) > 128 {
		return fmt.Errorf("%w: unknown_id is required", ErrInvalidWriteUnknown)
	}
	if u.At.IsZero() || u.TargetID == "" || u.Protocol == "" || u.Function == "" {
		return fmt.Errorf("%w: at, target, protocol and function are required", ErrInvalidWriteUnknown)
	}
	switch u.Reason {
	case WriteUnknownTimeout, WriteUnknownClientDisconnect, WriteUnknownReadError:
	default:
		return fmt.Errorf("%w: reason %q is not timeout, client_disconnect or read_error", ErrInvalidWriteUnknown, u.Reason)
	}
	if !u.Severity.Valid() {
		return fmt.Errorf("%w: invalid severity", ErrInvalidWriteUnknown)
	}
	return nil
}

// SessionLookup is the data-plane seam used by the protocol proxies. Proxies
// import only this interface; they never import the store or the approval
// internals. The Service implements it.
type SessionLookup interface {
	// Lookup returns the active session for target and source address.
	Lookup(targetID domain.TargetID, sourceIP string, now time.Time) (domain.WriteSession, bool)
	// ConsumeUse counts one write use; it returns false when the session is not
	// usable (expired, revoked, exhausted, fail-safe, persistence failure).
	ConsumeUse(sessionID domain.SessionID, now time.Time) bool
	// PlanFor returns the approved plan behind a session.
	PlanFor(sessionID domain.SessionID) (domain.WritePlan, bool)
	// Deny records a refused write attempt (audit + denial evidence + event).
	Deny(ctx context.Context, attempt domain.DeniedWriteAttempt) error
	// Allowed records an authorised write (audit without values).
	Allowed(ctx context.Context, sessionID domain.SessionID, op domain.WriteOperation) error
}

// WriteUnknownReporter is the optional alpha extension of the data-plane seam: a
// proxy reports a write whose device outcome is unknown. It is deliberately a
// separate interface so the documented SessionLookup contract stays unchanged.
type WriteUnknownReporter interface {
	// ReportWriteUnknown records the ambiguous outcome, revokes the session
	// (fail-closed) and audits gate.write.unknown. No automatic retry.
	ReportWriteUnknown(ctx context.Context, sessionID domain.SessionID, op domain.WriteOperation, reason string) error
}
