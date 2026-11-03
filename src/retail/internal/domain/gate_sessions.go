package domain

import (
	"fmt"
	"time"
)

// WriteSession is the runtime authorisation checked by the protocol proxies for
// every write attempt. It is bound to one plan, one target and one source IP.
type WriteSession struct {
	SessionID SessionID  `json:"session_id"`
	PlanID    PlanID     `json:"plan_id"`
	TargetID  TargetID   `json:"target_id"`
	UserID    GateUserID `json:"user_id"`
	SourceIP  string     `json:"source_ip"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	MaxUses   int        `json:"max_uses"`
	Uses      int        `json:"uses"`
	Revoked   bool       `json:"revoked"`
	RevokedAt time.Time  `json:"revoked_at,omitempty"`
	RevokedBy GateUserID `json:"revoked_by,omitempty"`
}

// Validate checks the session contract.
func (s WriteSession) Validate() error {
	if err := s.SessionID.Validate(); err != nil {
		return fmt.Errorf("write session: %w", err)
	}
	if err := s.PlanID.Validate(); err != nil {
		return fmt.Errorf("write session %q: %w", s.SessionID, err)
	}
	if err := s.TargetID.Validate(); err != nil {
		return fmt.Errorf("write session %q: %w", s.SessionID, err)
	}
	if s.UserID == "" {
		return fmt.Errorf("write session %q: user is required", s.SessionID)
	}
	if s.SourceIP == "" {
		return fmt.Errorf("write session %q: source ip is required", s.SessionID)
	}
	if s.ExpiresAt.IsZero() || !s.ExpiresAt.After(s.CreatedAt) {
		return fmt.Errorf("write session %q: invalid expiry", s.SessionID)
	}
	return nil
}

// Usable reports whether the session can authorise a write at time now.
func (s WriteSession) Usable(now time.Time) bool {
	return !s.Revoked && now.Before(s.ExpiresAt) && s.Uses < s.MaxUses
}

// DeniedWriteAttempt is the evidence record for every write that was refused by
// the gate. It is a security signal, not a log line: it feeds alerts and audit.
type DeniedWriteAttempt struct {
	DenyID    DenyID     `json:"deny_id"`
	At        time.Time  `json:"at"`
	SessionID SessionID  `json:"session_id,omitempty"`
	PlanID    PlanID     `json:"plan_id,omitempty"`
	UserID    GateUserID `json:"user_id,omitempty"`
	SourceIP  string     `json:"source_ip"`
	TargetID  TargetID   `json:"target_id"`
	Protocol  string     `json:"protocol"`
	Function  string     `json:"function"`
	Address   string     `json:"address,omitempty"`
	ValueHint string     `json:"value_hint,omitempty"`
	Reason    string     `json:"reason"`
	Severity  Severity   `json:"severity"`
	ViaBypass bool       `json:"via_bypass,omitempty"`
}

// Validate checks the denial evidence record.
func (d DeniedWriteAttempt) Validate() error {
	if err := d.DenyID.Validate(); err != nil {
		return fmt.Errorf("denied write: %w", err)
	}
	if d.At.IsZero() {
		return fmt.Errorf("denied write %q: at is required", d.DenyID)
	}
	if d.SourceIP == "" || d.TargetID == "" || d.Protocol == "" || d.Function == "" {
		return fmt.Errorf("denied write %q: source, target, protocol and function are required", d.DenyID)
	}
	if !d.Severity.Valid() {
		return fmt.Errorf("denied write %q: invalid severity %q", d.DenyID, d.Severity)
	}
	return nil
}
