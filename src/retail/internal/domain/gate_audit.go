package domain

import (
	"encoding/hex"
	"fmt"
	"time"
)

// DeviceBinding pins one client certificate to a gate identity. Only the SHA-256
// of the DER certificate is stored; the certificate itself is never persisted.
type DeviceBinding struct {
	BindingID   string     `json:"binding_id"`
	UserID      GateUserID `json:"user_id"`
	Fingerprint string     `json:"fingerprint"` // SHA-256 hex of the client cert DER
	Label       string     `json:"label,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	Revoked     bool       `json:"revoked"`
	RevokedAt   time.Time  `json:"revoked_at,omitempty"`
}

// Validate checks the binding contract.
func (b DeviceBinding) Validate() error {
	if b.BindingID == "" || b.UserID == "" || len(b.Fingerprint) != 64 {
		return fmt.Errorf("device binding: id, user and sha256 fingerprint are required")
	}
	if _, err := hex.DecodeString(b.Fingerprint); err != nil {
		return fmt.Errorf("device binding %q: fingerprint is not hex: %w", b.BindingID, err)
	}
	return nil
}

// GateConfigVersion records one immutable version of the gate policy/configuration
// so that every approval can reference the rules under which it was granted.
type GateConfigVersion struct {
	Version  int       `json:"version"`
	Hash     string    `json:"hash"`
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
	Reason   string    `json:"reason,omitempty"`
	PrevHash string    `json:"prev_hash,omitempty"`
}

// Validate checks the config version entry.
func (v GateConfigVersion) Validate() error {
	if v.Version < 1 || len(v.Hash) != 64 || v.At.IsZero() || v.Actor == "" {
		return fmt.Errorf("gate config version: version, hash, time and actor are required")
	}
	return nil
}

// Deny reasons are stable identifiers used by API, audit, alerts and UI. They
// must not be reworded without a version bump because operators build runbooks
// and incident playbooks on them.
const (
	DenyNoSession            = "no_session"
	DenySessionExpired       = "session_expired"
	DenySessionRevoked       = "session_revoked"
	DenyWrongSource          = "wrong_source"
	DenyWrongTarget          = "wrong_target"
	DenyNotApproved          = "not_approved"
	DenyOperationNotApproved = "operation_not_approved"
	DenyValueMismatch        = "value_mismatch"
	DenyAddressMismatch      = "address_mismatch"
	// Read-before-write verification (security principle from write-surface.json):
	// the live device value must match the approved CurrentValue before a write
	// is forwarded. Stable identifiers for API/audit/UI.
	DenyCurrentValueMissing    = "current_value_missing"
	DenyCurrentValueMismatch   = "current_value_mismatch"
	DenyCurrentValueUnreadable = "current_value_unreadable"
	DenyOutsideWindow          = "outside_window"
	DenyTokenInvalid           = "token_invalid"
	DenyTokenExpired           = "token_expired"
	DenyTokenUsed              = "token_used"
	DenyMFARequired            = "mfa_required"
	DenyPolicyMissing          = "policy_missing"
	DenyFailsafeClock          = "failsafe_clock"
	DenyFailsafeStore          = "failsafe_store"
)
