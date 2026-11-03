package approval

import (
	"errors"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Sentinel errors of the approval service. The API maps them onto the documented
// HTTP status and semantic error codes.
var (
	// ErrRoleRequired reports a missing role for the action.
	ErrRoleRequired = errors.New("approval: role required")
	// ErrInvalidPlan reports a plan that fails validation.
	ErrInvalidPlan = errors.New("approval: invalid plan")
	// ErrTargetNotAllowed reports an unknown target or an operation outside the
	// operator policy allowlist.
	ErrTargetNotAllowed = errors.New("approval: target or operation not allowed")
	// ErrNotRequester reports a non-requester acting on a plan.
	ErrNotRequester = errors.New("approval: requester required")
	// ErrAlreadyDecided reports an action on a plan that is no longer pending.
	ErrAlreadyDecided = errors.New("approval: plan already decided")
	// ErrAlreadyApproved reports a second approval by the same user.
	ErrAlreadyApproved = errors.New("approval: user already approved")
	// ErrSelfApproval reports an approver acting on their own plan.
	ErrSelfApproval = errors.New("approval: self approval is forbidden")
	// ErrPlanHashMismatch reports tampered or stale plan content.
	ErrPlanHashMismatch = errors.New("approval: plan hash mismatch")
	// ErrWindowExpired reports an approval outside the requested window.
	ErrWindowExpired = errors.New("approval: plan window expired")
	// ErrNotApproved reports a token redemption for a plan that is not approved.
	ErrNotApproved = errors.New("approval: plan is not approved")
	// ErrTokenInvalid reports an unknown or revoked token.
	ErrTokenInvalid = errors.New("approval: token invalid")
	// ErrTokenExpired reports an expired token.
	ErrTokenExpired = errors.New("approval: token expired")
	// ErrTokenUsed reports an exhausted token.
	ErrTokenUsed = errors.New("approval: token already used")
	// ErrWrongSource reports a token/session bound to a different source address.
	ErrWrongSource = errors.New("approval: source address does not match")
	// ErrOutsideWindow reports a session creation outside the approved window.
	ErrOutsideWindow = errors.New("approval: outside the approved window")
	// ErrMFARequired reports a missing MFA confirmation on a step-up action.
	ErrMFARequired = errors.New("approval: MFA required")
	// ErrForbidden reports a state conflict the caller may not resolve.
	ErrForbidden = errors.New("approval: forbidden")
	// ErrFailsafe reports that the fail-safe state blocks writes/sessions.
	ErrFailsafe = errors.New("approval: fail-safe active")
	// ErrStore reports a persistence/audit failure (fail-closed).
	ErrStore = errors.New("approval: store failure")
	// ErrNotFound reports a missing plan or session.
	ErrNotFound = errors.New("approval: not found")
	// ErrInvalidDenyReason reports an unknown deny reason code.
	ErrInvalidDenyReason = errors.New("approval: invalid deny reason")
	// ErrInvalidWriteUnknown reports an invalid write-unknown reason.
	ErrInvalidWriteUnknown = errors.New("approval: invalid write-unknown reason")
	// ErrCorruptState reports persisted write-unknown evidence that cannot be decoded.
	ErrCorruptState = errors.New("approval: corrupt persisted evidence")
)

// Audit object types. There is exactly one audit structure (0.1
// domain.AuditEntry); these types keep the gate records distinguishable in the
// shared audit trail and the incident export.
const (
	ObjectGatePlan         = "gate_plan"
	ObjectGateSession      = "gate_session"
	ObjectGateDeny         = "gate_deny"
	ObjectGatePolicy       = "gate_policy"
	ObjectGateLogin        = "gate_login"
	ObjectGateWriteUnknown = "gate_write_unknown"
	ObjectGateStore        = "gate_store"
	ObjectGateEscalation   = "gate_escalation"
	ObjectGateNotify       = "gate_notify"
)

// Audit action names (stable machine identifiers).
const (
	ActionPlanCreate      = "gate.plan.create"
	ActionPlanApprove     = "gate.plan.approve"
	ActionPlanApproveWait = "gate.plan.approve.partial"
	ActionPlanReject      = "gate.plan.reject"
	ActionPlanCancel      = "gate.plan.cancel"
	ActionPlanExpire      = "gate.plan.expire"
	ActionPlanExecuted    = "gate.plan.executed"
	ActionSessionOpen     = "gate.session.open"
	ActionSessionUse      = "gate.session.use"
	ActionSessionRevoke   = "gate.session.revoke"
	ActionWriteAllowed    = "gate.write.allowed"
	ActionWriteDenied     = "gate.write.denied"
	ActionWriteUnknown    = "gate.write.unknown"
	ActionPolicyReload    = "gate.policy.reload"
	ActionLoginOK         = "gate.login.success"
	ActionLoginFailed     = "gate.login.failed"
	ActionLogout          = "gate.logout"
	ActionEscalationAck   = "gate.escalation.ack"
	ActionNotifyTest      = "gate.notify.test"
)

// validDenyReasons is the closed set of stable deny reason codes from the domain
// package. Unknown reasons are rejected so alerts/UI never see ad-hoc strings.
var validDenyReasons = map[string]struct{}{
	domain.DenyNoSession:            {},
	domain.DenySessionExpired:       {},
	domain.DenySessionRevoked:       {},
	domain.DenyWrongSource:          {},
	domain.DenyWrongTarget:          {},
	domain.DenyNotApproved:          {},
	domain.DenyOperationNotApproved: {},
	domain.DenyValueMismatch:        {},
	domain.DenyAddressMismatch:      {},
	domain.DenyOutsideWindow:        {},
	domain.DenyTokenInvalid:         {},
	domain.DenyTokenExpired:         {},
	domain.DenyTokenUsed:            {},
	domain.DenyMFARequired:          {},
	domain.DenyPolicyMissing:        {},
	domain.DenyFailsafeClock:        {},
	domain.DenyFailsafeStore:        {},
}

// ValidDenyReason reports whether reason is a stable domain deny code.
func ValidDenyReason(reason string) bool {
	_, ok := validDenyReasons[reason]
	return ok
}

// Write-unknown reasons: the device outcome of a write attempt is unclear.
const (
	WriteUnknownTimeout          = "timeout"
	WriteUnknownClientDisconnect = "client_disconnect"
	WriteUnknownReadError        = "read_error"
)
