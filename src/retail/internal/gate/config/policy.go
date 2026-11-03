package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/identity"
)

const (
	maxPolicyBytes = 1 << 20
	maxTokenUses   = 10
)

// ErrInvalidPolicy is the sentinel wrapper for every policy problem.
var ErrInvalidPolicy = errors.New("gate policy: invalid policy")

// ErrPolicyMissing reports a missing policy document (fail-closed at start).
var ErrPolicyMissing = errors.New("gate policy: policy file does not exist or was deleted")

// ModbusWriteAllow is one writable register/function/value range.
type ModbusWriteAllow struct {
	TargetID domain.TargetID `json:"target_id"`
	FC       int             `json:"fc"`
	Register int             `json:"register"`
	Value    string          `json:"value,omitempty"`
	MaxDelta float64         `json:"max_delta,omitempty"`
	Note     string          `json:"note,omitempty"`
}

// HTTPWriteAllow is one writable method/path prefix pair.
type HTTPWriteAllow struct {
	TargetID   domain.TargetID `json:"target_id"`
	Method     string          `json:"method"`
	PathPrefix string          `json:"path_prefix"`
	Note       string          `json:"note,omitempty"`
}

// TokenPolicy configures one-time write tokens.
type TokenPolicy struct {
	MaxUses      int  `json:"max_uses"`
	BindSourceIP bool `json:"bind_source_ip"`
}

// NotifyPolicy configures the deny severity floor.
type NotifyPolicy struct {
	DenyMinSeverity domain.Severity `json:"deny_min_severity"`
}

// Policy is the versioned, operator-owned write policy of the gate.
type Policy struct {
	PolicyID             string             `json:"policy_id"`
	Version              int                `json:"version"`
	UpdatedAt            time.Time          `json:"updated_at"`
	UpdatedBy            string             `json:"updated_by"`
	DefaultDeny          bool               `json:"default_deny"`
	CriticalAssets       []domain.AssetID   `json:"critical_assets,omitempty"`
	FourEyesAssets       []domain.AssetID   `json:"four_eyes_assets,omitempty"`
	ModbusWriteAllowlist []ModbusWriteAllow `json:"modbus_write_allowlist,omitempty"`
	HTTPWriteAllowlist   []HTTPWriteAllow   `json:"http_write_allowlist,omitempty"`
	Token                TokenPolicy        `json:"token"`
	Notify               NotifyPolicy       `json:"notify"`
}

// LoadPolicy reads the versioned policy document (strict JSON, fail-closed).
func LoadPolicy(path string) (Policy, error) {
	raw, err := readStrictFile(path, maxPolicyBytes)
	if err != nil {
		if errors.Is(err, errFileMissing) {
			return Policy{}, ErrPolicyMissing
		}
		return Policy{}, fmt.Errorf("gate policy: %q: %w", filepath.Base(path), err)
	}
	return ParsePolicy(bytes.NewReader(raw))
}

// ParsePolicy strictly decodes one policy document.
func ParsePolicy(r io.Reader) (Policy, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxPolicyBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("read: %w", err)
	}
	if len(raw) > maxPolicyBytes {
		return Policy{}, fmt.Errorf("%w: policy exceeds %d bytes", ErrInvalidPolicy, maxPolicyBytes)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return Policy{}, fmt.Errorf("%w: policy must be a JSON object", ErrInvalidPolicy)
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var policy Policy
	if derr := decoder.Decode(&policy); derr != nil {
		if strings.Contains(derr.Error(), "unknown field") {
			return Policy{}, fmt.Errorf("%w: %v", ErrUnknownField, derr)
		}
		return Policy{}, fmt.Errorf("decode: %w", derr)
	}
	var extra json.RawMessage
	if derr := decoder.Decode(&extra); derr != io.EOF {
		return Policy{}, fmt.Errorf("%w: trailing content after the policy object", ErrInvalidPolicy)
	}
	return policy, nil
}

// Validate enforces the policy invariants. default_deny must be true: a policy
// that does not default-deny is a fail-safe violation.
func (p Policy) Validate() error {
	if strings.TrimSpace(p.PolicyID) == "" || len(p.PolicyID) > 128 {
		return fmt.Errorf("%w: policy_id is required", ErrInvalidPolicy)
	}
	if p.Version < 1 {
		return fmt.Errorf("%w: version must be >= 1", ErrInvalidPolicy)
	}
	if p.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: updated_at is required", ErrInvalidPolicy)
	}
	if strings.TrimSpace(p.UpdatedBy) == "" {
		return fmt.Errorf("%w: updated_by is required", ErrInvalidPolicy)
	}
	if !p.DefaultDeny {
		return fmt.Errorf("%w: default_deny must be true", ErrInvalidPolicy)
	}
	for _, asset := range p.CriticalAssets {
		if err := asset.Validate(); err != nil {
			return fmt.Errorf("%w: critical_assets: %w", ErrInvalidPolicy, err)
		}
	}
	for _, asset := range p.FourEyesAssets {
		if err := asset.Validate(); err != nil {
			return fmt.Errorf("%w: four_eyes_assets: %w", ErrInvalidPolicy, err)
		}
	}
	seenModbus := make(map[string]struct{}, len(p.ModbusWriteAllowlist))
	for i, allow := range p.ModbusWriteAllowlist {
		if err := allow.TargetID.Validate(); err != nil {
			return fmt.Errorf("%w: modbus_write_allowlist[%d]: %w", ErrInvalidPolicy, i, err)
		}
		if _, ok := modbusWriteFCs[allow.FC]; !ok {
			return fmt.Errorf("%w: modbus_write_allowlist[%d]: fc %d is not a write function code", ErrInvalidPolicy, i, allow.FC)
		}
		if allow.Register < 0 || allow.Register > 65535 {
			return fmt.Errorf("%w: modbus_write_allowlist[%d]: register outside 0..65535", ErrInvalidPolicy, i)
		}
		if allow.MaxDelta < 0 {
			return fmt.Errorf("%w: modbus_write_allowlist[%d]: max_delta must not be negative", ErrInvalidPolicy, i)
		}
		if len(allow.Value) > 256 || len(allow.Note) > 256 {
			return fmt.Errorf("%w: modbus_write_allowlist[%d]: value/note too long", ErrInvalidPolicy, i)
		}
		key := fmt.Sprintf("%s|%d|%d", allow.TargetID, allow.FC, allow.Register)
		if _, dup := seenModbus[key]; dup {
			return fmt.Errorf("%w: duplicate modbus allowlist entry for %s", ErrInvalidPolicy, key)
		}
		seenModbus[key] = struct{}{}
	}
	seenHTTP := make(map[string]struct{}, len(p.HTTPWriteAllowlist))
	for i, allow := range p.HTTPWriteAllowlist {
		if err := allow.TargetID.Validate(); err != nil {
			return fmt.Errorf("%w: http_write_allowlist[%d]: %w", ErrInvalidPolicy, i, err)
		}
		switch allow.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			return fmt.Errorf("%w: http_write_allowlist[%d]: method %q is not a write method", ErrInvalidPolicy, i, allow.Method)
		}
		if !strings.HasPrefix(allow.PathPrefix, "/") || len(allow.PathPrefix) > 256 || strings.Contains(allow.PathPrefix, "..") {
			return fmt.Errorf("%w: http_write_allowlist[%d]: path_prefix is invalid", ErrInvalidPolicy, i)
		}
		key := string(allow.TargetID) + "|" + allow.Method + "|" + allow.PathPrefix
		if _, dup := seenHTTP[key]; dup {
			return fmt.Errorf("%w: duplicate http allowlist entry for %s", ErrInvalidPolicy, key)
		}
		seenHTTP[key] = struct{}{}
	}
	if p.Token.MaxUses < 1 || p.Token.MaxUses > maxTokenUses {
		return fmt.Errorf("%w: token.max_uses must be between 1 and %d", ErrInvalidPolicy, maxTokenUses)
	}
	if p.Notify.DenyMinSeverity != "" && !p.Notify.DenyMinSeverity.Valid() {
		return fmt.Errorf("%w: notify.deny_min_severity is invalid", ErrInvalidPolicy)
	}
	return nil
}

// DenySeverity returns the configured severity floor for denied writes.
func (p Policy) DenySeverity() domain.Severity {
	if p.Notify.DenyMinSeverity.Valid() {
		return p.Notify.DenyMinSeverity
	}
	return domain.SeverityHigh
}

// IsCritical reports whether the asset is operator-declared critical.
func (p Policy) IsCritical(assetID domain.AssetID) bool {
	return containsAsset(p.CriticalAssets, assetID)
}

// NeedsFourEyes reports whether the asset requires two independent approvals.
func (p Policy) NeedsFourEyes(assetID domain.AssetID) bool {
	return containsAsset(p.FourEyesAssets, assetID) || p.IsCritical(assetID)
}

// ModbusOperationAllowed reports whether the policy allowlists the exact writable
// register/function. The allowlist is necessary but never sufficient: an approved
// plan with the exact value is still required.
func (p Policy) ModbusOperationAllowed(targetID domain.TargetID, fc, register int) bool {
	for _, allow := range p.ModbusWriteAllowlist {
		if allow.TargetID == targetID && allow.FC == fc && allow.Register == register {
			return true
		}
	}
	return false
}

// HTTPOperationAllowed reports whether the policy allowlists the method/path pair.
func (p Policy) HTTPOperationAllowed(targetID domain.TargetID, method, path string) bool {
	for _, allow := range p.HTTPWriteAllowlist {
		if allow.TargetID != targetID || allow.Method != method {
			continue
		}
		if strings.HasPrefix(path, allow.PathPrefix) {
			return true
		}
	}
	return false
}

// containsAsset reports membership in an asset allowlist.
func containsAsset(list []domain.AssetID, assetID domain.AssetID) bool {
	for _, candidate := range list {
		if candidate == assetID {
			return true
		}
	}
	return false
}

// placeholderCache memoises the expensive placeholder-hash probe per digest.
var placeholderCache sync.Map

// isPlaceholderHash rejects copied example digests for the classic onboarding
// dictionaries. The probe is memoised; real digests are only checked once.
func isPlaceholderHash(encoded string) bool {
	if cached, ok := placeholderCache.Load(encoded); ok {
		matched, _ := cached.(bool)
		return matched
	}
	matched := false
	for _, placeholder := range []string{"changeme", "password", "admin"} {
		if ok, err := identity.VerifyPassword(encoded, placeholder); err == nil && ok {
			matched = true
			break
		}
	}
	placeholderCache.Store(encoded, matched)
	return matched
}
