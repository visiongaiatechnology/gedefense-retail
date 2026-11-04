package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Gate identifier types. They are separate from the monitoring IDs so that a
// plan ID can never be mistaken for an alert ID, and vice versa.
type (
	GateUserID string
	TargetID   string
	PlanID     string
	ApprovalID string
	SessionID  string
	TokenID    string
	DenyID     string
)

func (id GateUserID) Validate() error { return validID("gate_user_id", string(id), false) }
func (id TargetID) Validate() error   { return validID("target_id", string(id), false) }
func (id PlanID) Validate() error     { return validID("plan_id", string(id), false) }
func (id ApprovalID) Validate() error { return validID("approval_id", string(id), false) }
func (id SessionID) Validate() error  { return validID("session_id", string(id), false) }
func (id TokenID) Validate() error    { return validID("token_id", string(id), false) }
func (id DenyID) Validate() error     { return validID("deny_id", string(id), false) }

// GateRole is a role inside the Access Gate. Roles are deliberately separate
// from the monitoring API roles: reading the gate is not the same as approving
// a write, and approving is not the same as requesting.
type GateRole string

const (
	GateRoleVendorRead           GateRole = "vendor_read"
	GateRoleVendorWriteRequester GateRole = "vendor_write_requester"
	GateRoleApprover             GateRole = "approver"
	GateRoleMasterAdmin          GateRole = "master_admin"
	GateRoleAuditor              GateRole = "auditor"
)

func (r GateRole) Valid() bool {
	switch r {
	case GateRoleVendorRead, GateRoleVendorWriteRequester, GateRoleApprover, GateRoleMasterAdmin, GateRoleAuditor:
		return true
	}
	return false
}

// GateUserKind distinguishes external service partners from the operator and
// platform administrators.
type GateUserKind string

const (
	GateUserVendor   GateUserKind = "vendor"
	GateUserOperator GateUserKind = "operator"
	GateUserAdmin    GateUserKind = "admin"
)

func (k GateUserKind) Valid() bool {
	switch k {
	case GateUserVendor, GateUserOperator, GateUserAdmin:
		return true
	}
	return false
}

// GateUserStatus controls whether an identity may authenticate at all.
type GateUserStatus string

const (
	GateUserActive   GateUserStatus = "active"
	GateUserDisabled GateUserStatus = "disabled"
)

// GateUser is a local identity for the Access Gate. Passwords are only stored as
// PBKDF2-HMAC-SHA256 digests; TOTP secrets are stored so that the gate can
// verify codes offline (the file is 0600 and never logged).
type GateUser struct {
	UserID             GateUserID     `json:"user_id"`
	Name               string         `json:"name"`
	Kind               GateUserKind   `json:"kind"`
	Roles              []GateRole     `json:"roles"`
	PasswordHash       string         `json:"password_hash"` // pbkdf2-sha256$<iter>$<saltB64>$<hashB64>
	TOTPSecret         string         `json:"totp_secret,omitempty"`
	TOTPEnabled        bool           `json:"totp_enabled,omitempty"`
	DeviceFingerprints []string       `json:"device_fingerprints,omitempty"` // SHA-256 hex of client cert DER
	Status             GateUserStatus `json:"status"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
	LastLoginAt        time.Time      `json:"last_login_at,omitempty"`
}

// Validate enforces the identity invariants.
func (u GateUser) Validate() error {
	if err := u.UserID.Validate(); err != nil {
		return fmt.Errorf("gate user: %w", err)
	}
	if u.Name == "" {
		return fmt.Errorf("gate user %q: name is required", u.UserID)
	}
	if !u.Kind.Valid() {
		return fmt.Errorf("gate user %q: invalid kind %q", u.UserID, u.Kind)
	}
	if len(u.Roles) == 0 {
		return fmt.Errorf("gate user %q: at least one role is required", u.UserID)
	}
	for _, r := range u.Roles {
		if !r.Valid() {
			return fmt.Errorf("gate user %q: invalid role %q", u.UserID, r)
		}
	}
	if u.Status != GateUserActive && u.Status != GateUserDisabled {
		return fmt.Errorf("gate user %q: invalid status %q", u.UserID, u.Status)
	}
	// Password is mandatory unless the identity is bound to a client certificate
	// (mTLS-only vendor account). A user without any factor cannot authenticate.
	if u.PasswordHash == "" && len(u.DeviceFingerprints) == 0 {
		return fmt.Errorf("gate user %q: password hash or device binding is required", u.UserID)
	}
	return nil
}

// HasRole reports whether the identity carries the role.
func (u GateUser) HasRole(role GateRole) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// WritePlanState is the lifecycle of one approved configuration change.
type WritePlanState string

const (
	PlanPending   WritePlanState = "pending"
	PlanApproved  WritePlanState = "approved"
	PlanRejected  WritePlanState = "rejected"
	PlanExpired   WritePlanState = "expired"
	PlanExecuted  WritePlanState = "executed"
	PlanCancelled WritePlanState = "cancelled"
)

func (s WritePlanState) Valid() bool {
	switch s {
	case PlanPending, PlanApproved, PlanRejected, PlanExpired, PlanExecuted, PlanCancelled:
		return true
	}
	return false
}

// WriteOperation is exactly one value change that was requested and approved.
// A plan with several operations must have each of them approved as a unit.
// CurrentValue/NewValue are operator-facing display values; ValueScale maps them
// to wire values (raw = round(display / scale), default 1.0). For example a
// temperature shown as 4.0 degC with scale 0.1 maps to raw register value 40.
type WriteOperation struct {
	OperationID  string  `json:"operation_id"`
	Protocol     string  `json:"protocol"` // modbus_tcp, http, bacnet_ip, mqtt
	Function     string  `json:"function"` // e.g. "fc6", "http_post", "write_property"
	Address      string  `json:"address"`  // register, object instance, or URL path
	CurrentValue string  `json:"current_value"`
	NewValue     string  `json:"new_value"`
	ValueScale   float64 `json:"value_scale,omitempty"`
	Unit         string  `json:"unit,omitempty"`
	Notes        string  `json:"notes,omitempty"`
}

// EffectiveScale returns the applied scale, defaulting to 1.0 for omitted/zero.
func (o WriteOperation) EffectiveScale() float64 {
	if o.ValueScale <= 0 {
		return 1
	}
	return o.ValueScale
}

// HasDecimalValues reports whether the display values carry a decimal point
// (such values require an explicit value_scale to be unambiguous).
func (o WriteOperation) HasDecimalValues() bool {
	return strings.Contains(o.CurrentValue, ".") || strings.Contains(o.NewValue, ".")
}

// ScaleToRaw converts one display value to the wire integer (0..65535).
func ScaleToRaw(value string, scale float64) (string, bool) {
	text := strings.TrimSpace(value)
	if text == "" {
		return "", false
	}
	parsed, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return "", false
	}
	if scale <= 0 {
		scale = 1
	}
	raw := math.Round(parsed / scale)
	if raw < 0 || raw > 65535 {
		return "", false
	}
	return strconv.FormatInt(int64(raw), 10), true
}

// RawNewValue converts the approved display NewValue to the wire value.
func (o WriteOperation) RawNewValue() (string, bool) {
	return ScaleToRaw(o.NewValue, o.EffectiveScale())
}

// RawCurrentValue converts the approved display CurrentValue to the wire value.
func (o WriteOperation) RawCurrentValue() (string, bool) {
	return ScaleToRaw(o.CurrentValue, o.EffectiveScale())
}

// Validate forbids empty operations: an approval without a concrete target is a
// blank cheque.
func (o WriteOperation) Validate() error {
	if o.Protocol == "" || o.Function == "" || o.Address == "" {
		return fmt.Errorf("write operation: protocol, function and address are required")
	}
	if o.NewValue == "" {
		return fmt.Errorf("write operation %q: new value is required", o.Address)
	}
	if len(o.Address) > 256 || len(o.NewValue) > 256 || len(o.CurrentValue) > 256 {
		return fmt.Errorf("write operation %q: value or address too long", o.Address)
	}
	if o.ValueScale < 0 || o.ValueScale > 1_000_000 {
		return fmt.Errorf("write operation %q: value_scale must be between 0 (default 1.0) and 1000000", o.Address)
	}
	if o.HasDecimalValues() && o.ValueScale <= 0 {
		return fmt.Errorf("write operation %q: decimal values require value_scale (for example 0.1)", o.Address)
	}
	return nil
}

// GateApproval is one approval (or rejection) signature over the immutable plan
// hash. Four-eyes means a critical plan needs approvals by two distinct users.
type GateApproval struct {
	ApprovalID ApprovalID `json:"approval_id"`
	PlanID     PlanID     `json:"plan_id"`
	ApproverID GateUserID `json:"approver_id"`
	Role       GateRole   `json:"role"`
	Approved   bool       `json:"approved"`
	Comment    string     `json:"comment,omitempty"`
	PlanHash   string     `json:"plan_hash"`
	MFAUsed    bool       `json:"mfa_used"`
	At         time.Time  `json:"at"`
}

// WritePlan is a request to change concrete configuration values on one OT
// asset. It is the ONLY object that can authorise a write on the wire.
type WritePlan struct {
	PlanID      PlanID           `json:"plan_id"`
	SiteID      SiteID           `json:"site_id"`
	TargetID    TargetID         `json:"target_id"`
	AssetID     AssetID          `json:"asset_id"`
	Protocol    string           `json:"protocol"`
	Operations  []WriteOperation `json:"operations"`
	Reason      string           `json:"reason"`
	TicketRef   string           `json:"ticket_ref,omitempty"`
	RequestedBy GateUserID       `json:"requested_by"`
	RequestedAt time.Time        `json:"requested_at"`
	WindowStart time.Time        `json:"window_start"`
	WindowEnd   time.Time        `json:"window_end"`
	State       WritePlanState   `json:"state"`
	Approvals   []GateApproval   `json:"approvals,omitempty"`
	PlanHash    string           `json:"plan_hash"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	ExecutedAt  time.Time        `json:"executed_at,omitempty"`
	ExecutedBy  GateUserID       `json:"executed_by,omitempty"`
	Critical    bool             `json:"critical"`
	FourEyes    bool             `json:"four_eyes"`
}

// Validate checks the plan contract. The hash is computed separately so that
// approvals can be collected without invalidating it.
func (p WritePlan) Validate() error {
	if err := p.PlanID.Validate(); err != nil {
		return fmt.Errorf("write plan: %w", err)
	}
	if err := p.SiteID.Validate(); err != nil {
		return fmt.Errorf("write plan %q: %w", p.PlanID, err)
	}
	if err := p.TargetID.Validate(); err != nil {
		return fmt.Errorf("write plan %q: %w", p.PlanID, err)
	}
	if len(p.Operations) == 0 {
		return fmt.Errorf("write plan %q: at least one operation is required", p.PlanID)
	}
	for i, op := range p.Operations {
		if err := op.Validate(); err != nil {
			return fmt.Errorf("write plan %q operation %d: %w", p.PlanID, i, err)
		}
	}
	if p.Reason == "" {
		return fmt.Errorf("write plan %q: reason is required", p.PlanID)
	}
	if p.WindowStart.IsZero() || p.WindowEnd.IsZero() || !p.WindowEnd.After(p.WindowStart) {
		return fmt.Errorf("write plan %q: valid window is required", p.PlanID)
	}
	if !p.State.Valid() {
		return fmt.Errorf("write plan %q: invalid state %q", p.PlanID, p.State)
	}
	return nil
}

// hashInput is the canonical immutable content of a plan. Only fields in this
// struct are signed; state/approvals/execution metadata are deliberately not.
type hashInput struct {
	PlanID      PlanID           `json:"plan_id"`
	SiteID      SiteID           `json:"site_id"`
	TargetID    TargetID         `json:"target_id"`
	AssetID     AssetID          `json:"asset_id"`
	Protocol    string           `json:"protocol"`
	Operations  []WriteOperation `json:"operations"`
	Reason      string           `json:"reason"`
	TicketRef   string           `json:"ticket_ref,omitempty"`
	RequestedBy GateUserID       `json:"requested_by"`
	RequestedAt time.Time        `json:"requested_at"`
	WindowStart time.Time        `json:"window_start"`
	WindowEnd   time.Time        `json:"window_end"`
	// Critical and FourEyes are part of the signed content: otherwise the
	// approval requirement could be downgraded after a signature.
	Critical bool `json:"critical"`
	FourEyes bool `json:"four_eyes"`
}

// ComputePlanHash returns the canonical SHA-256 of the immutable plan content.
// It must be recomputed before every approval and before execution; a mismatch
// means the plan was modified and MUST be rejected.
func (p WritePlan) ComputePlanHash() (string, error) {
	in := hashInput{
		PlanID: p.PlanID, SiteID: p.SiteID, TargetID: p.TargetID, AssetID: p.AssetID,
		Protocol: p.Protocol, Operations: p.Operations, Reason: p.Reason,
		TicketRef: p.TicketRef, RequestedBy: p.RequestedBy,
		RequestedAt: p.RequestedAt.UTC(), WindowStart: p.WindowStart.UTC(), WindowEnd: p.WindowEnd.UTC(),
		Critical: p.Critical, FourEyes: p.FourEyes,
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return "", fmt.Errorf("write plan %q: canonical hash: %w", p.PlanID, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// NeedsFourEyes reports whether the plan requires two independent approvers.
func (p WritePlan) NeedsFourEyes() bool { return p.FourEyes || p.Critical }

// ApprovedBy reports whether the given user already approved this plan.
func (p WritePlan) ApprovedBy(user GateUserID) bool {
	for _, a := range p.Approvals {
		if a.ApproverID == user && a.Approved {
			return true
		}
	}
	return false
}

// RequiredApprovals returns how many distinct positive approvals are needed.
func (p WritePlan) RequiredApprovals() int {
	if p.NeedsFourEyes() {
		return 2
	}
	return 1
}

// FullyApproved reports whether the plan carries all required approvals. For
// four-eyes plans the caller must additionally confirm that one of the
// approvals came from a master_admin (pass masterApproved=true).
func (p WritePlan) FullyApproved(masterApproved bool) bool {
	if p.ApprovalCount() < p.RequiredApprovals() {
		return false
	}
	if p.NeedsFourEyes() && !masterApproved {
		return false
	}
	return true
}

// ApprovalCount returns the number of distinct positive approvals.
func (p WritePlan) ApprovalCount() int {
	seen := make(map[GateUserID]struct{}, len(p.Approvals))
	for _, a := range p.Approvals {
		if a.Approved {
			seen[a.ApproverID] = struct{}{}
		}
	}
	return len(seen)
}

// WriteToken is the single-use authorisation handed to the requester after a
// successful approval. Only its SHA-256 hash is stored.
type WriteToken struct {
	TokenID   TokenID   `json:"token_id"`
	PlanID    PlanID    `json:"plan_id"`
	TokenHash string    `json:"token_hash"` // SHA-256 hex of the plaintext token
	BoundIP   string    `json:"bound_ip,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	Uses      int       `json:"uses"`
	Revoked   bool      `json:"revoked"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

// Validate checks the token contract.
func (t WriteToken) Validate() error {
	if err := t.TokenID.Validate(); err != nil {
		return fmt.Errorf("write token: %w", err)
	}
	if err := t.PlanID.Validate(); err != nil {
		return fmt.Errorf("write token %q: %w", t.TokenID, err)
	}
	if t.TokenHash == "" || len(t.TokenHash) != 64 {
		return fmt.Errorf("write token %q: invalid hash", t.TokenID)
	}
	if t.MaxUses < 1 {
		return fmt.Errorf("write token %q: max_uses must be >= 1", t.TokenID)
	}
	if t.ExpiresAt.IsZero() || !t.ExpiresAt.After(t.CreatedAt) {
		return fmt.Errorf("write token %q: invalid expiry", t.TokenID)
	}
	return nil
}

// GateEventKind is the SSE/API event kind of the gate.
type GateEventKind string

const (
	GateEventPlanCreated  GateEventKind = "plan_created"
	GateEventPlanApproved GateEventKind = "plan_approved"
	GateEventPlanRejected GateEventKind = "plan_rejected"
	GateEventPlanExpired  GateEventKind = "plan_expired"
	GateEventSessionOpen  GateEventKind = "session_open"
	GateEventSessionClose GateEventKind = "session_close"
	GateEventWriteDenied  GateEventKind = "write_denied"
	GateEventWriteUnknown GateEventKind = "write_unknown"
	GateEventWriteAllowed GateEventKind = "write_allowed"
	GateEventFailsafe     GateEventKind = "failsafe"
	GateEventBypass       GateEventKind = "bypass_suspected"
)

// GateEvent is the transport envelope between the gate components, the API and
// the dashboard. Payload is a small JSON object (no secrets).
type GateEvent struct {
	Kind    GateEventKind   `json:"kind"`
	At      time.Time       `json:"at"`
	SiteID  SiteID          `json:"site_id,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// MatchOperation reports whether an observed write exactly matches one approved
// operation. Both the address AND the value must match; anything else is a
// denial, even inside an approved window.
func (p WritePlan) MatchOperation(protocol, function, address, newValue string) (WriteOperation, bool) {
	if p.State != PlanApproved {
		// Executed/cancelled/expired plans are terminal: reusing them would
		// turn a one-time approval into a standing write permission.
		return WriteOperation{}, false
	}
	for _, op := range p.Operations {
		if op.Protocol != protocol || op.Function != function || op.Address != address {
			continue
		}
		// Numeric operations compare the wire value derived from the display
		// value and value_scale against the client's raw value. Non-numeric
		// operations (for example fc22 mask expressions) compare literally.
		if raw, ok := op.RawNewValue(); ok {
			if raw == newValue {
				return op, true
			}
			continue
		}
		if op.NewValue == newValue {
			return op, true
		}
	}
	return WriteOperation{}, false
}

// InWindow reports whether t falls inside the approved maintenance window.
func (p WritePlan) InWindow(t time.Time) bool {
	if t.IsZero() || p.WindowStart.IsZero() || p.WindowEnd.IsZero() {
		return false
	}
	return !t.Before(p.WindowStart) && t.Before(p.WindowEnd)
}
