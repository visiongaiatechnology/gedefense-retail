// Package config loads and validates the Access Gate configuration and its
// versioned write policy.
//
// Both documents are decoded strictly (unknown fields are a configuration error)
// and validated fail-closed: a gate with an unreadable policy, a missing source
// CIDR or a user without MFA must not start.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// ErrInvalidConfig is the sentinel wrapper for every configuration problem.
var ErrInvalidConfig = errors.New("gate config: invalid configuration")

// ErrUnknownField reports an unknown JSON field.
var ErrUnknownField = errors.New("gate config: unknown field")

// Limits of the configuration documents.
const (
	DefaultAPIPort   = 8540
	MaxConfigBytes   = 4 << 20
	maxTargets       = 64
	maxUsers         = 128
	maxOperationsNum = 32
)

// Listen is the HTTP API listener configuration (TLS/mTLS optional).
type Listen struct {
	API               string `json:"api"`
	TLSCertFile       string `json:"tls_cert_file,omitempty"`
	TLSKeyFile        string `json:"tls_key_file,omitempty"`
	ClientCAFile      string `json:"client_ca_file,omitempty"`
	RequireClientCert bool   `json:"require_client_cert,omitempty"`
}

// Timeouts are the gate-wide TTLs in seconds as configured.
type Timeouts struct {
	SessionTTLS         int `json:"session_ttl_s"`
	TokenTTLS           int `json:"token_ttl_s"`
	ApprovalTTLS        int `json:"approval_ttl_s"`
	PlanTTLS            int `json:"plan_ttl_s"`
	WriteSessionMaxUses int `json:"write_session_max_uses"`
}

// SessionTTL returns the API/write session lifetime.
func (t Timeouts) SessionTTL() time.Duration { return time.Duration(t.SessionTTLS) * time.Second }

// TokenTTL returns the one-time token lifetime.
func (t Timeouts) TokenTTL() time.Duration { return time.Duration(t.TokenTTLS) * time.Second }

// ApprovalTTL returns the lifetime of a plan waiting for approval.
func (t Timeouts) ApprovalTTL() time.Duration {
	return time.Duration(t.ApprovalTTLS) * time.Second
}

// PlanTTL returns the maximum plan lifetime.
func (t Timeouts) PlanTTL() time.Duration { return time.Duration(t.PlanTTLS) * time.Second }

// RegisterSpec is the read-only register window used by the Modbus proxy.
type RegisterSpec struct {
	FC    int `json:"fc"`
	Start int `json:"start"`
	Count int `json:"count"`
}

// Target is one protected OT device reachable only through the gate.
type Target struct {
	TargetID           domain.TargetID `json:"target_id"`
	AssetID            domain.AssetID  `json:"asset_id"`
	Protocol           string          `json:"protocol"`
	Listen             string          `json:"listen"`
	Upstream           string          `json:"upstream"`
	UnitID             int             `json:"unit_id,omitempty"`
	TimeoutS           int             `json:"timeout_s,omitempty"`
	ReadRegisters      *RegisterSpec   `json:"read_registers,omitempty"`
	CAFile             string          `json:"ca_file,omitempty"`
	InsecureSkipVerify bool            `json:"insecure_skip_verify,omitempty"`
	URLAllowlist       []string        `json:"url_allowlist,omitempty"`
}

// EscalationStep is one rung of the notify escalation chain.
type EscalationStep struct {
	AfterMinutes int             `json:"after_minutes"`
	Role         domain.GateRole `json:"role"`
}

// Notify is the webhook notifier configuration.
type Notify struct {
	WebhookURL string           `json:"webhook_url,omitempty"`
	HMACSecret string           `json:"hmac_secret,omitempty"`
	TimeoutS   int              `json:"timeout_s,omitempty"`
	Escalation []EscalationStep `json:"escalation,omitempty"`
}

// Config is the complete gate configuration.
type Config struct {
	Listen         Listen            `json:"listen"`
	DataDir        string            `json:"data_dir"`
	SiteID         domain.SiteID     `json:"site_id"`
	GatewayAssetID domain.AssetID    `json:"gateway_asset_id"`
	PolicyFile     string            `json:"policy_file"`
	Timeouts       Timeouts          `json:"timeouts"`
	Targets        []Target          `json:"targets"`
	SourceCIDRs    []string          `json:"source_cidrs"`
	Users          []domain.GateUser `json:"users"`
	Notify         Notify            `json:"notify"`
}

// Load reads, strictly decodes, defaults and validates the gate configuration.
func Load(path string) (cfg Config, err error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, fmt.Errorf("%w: configuration path is empty", ErrInvalidConfig)
	}
	raw, err := readStrictFile(path, MaxConfigBytes)
	if err != nil {
		return Config{}, fmt.Errorf("gate config: %q: %w", filepath.Base(path), err)
	}
	cfg, err = Parse(bytes.NewReader(raw))
	if err != nil {
		return Config{}, fmt.Errorf("gate config: %q: %w", filepath.Base(path), err)
	}
	cfg = cfg.WithDefaults()
	if verr := cfg.Validate(); verr != nil {
		return Config{}, fmt.Errorf("gate config: %q: %w", filepath.Base(path), verr)
	}
	return cfg, nil
}

// Parse strictly decodes one JSON configuration object.
func Parse(r io.Reader) (Config, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read: %w", err)
	}
	if len(raw) > MaxConfigBytes {
		return Config{}, fmt.Errorf("%w: configuration exceeds %d bytes", ErrInvalidConfig, MaxConfigBytes)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return Config{}, fmt.Errorf("%w: configuration must be a JSON object", ErrInvalidConfig)
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var cfg Config
	if derr := decoder.Decode(&cfg); derr != nil {
		if strings.Contains(derr.Error(), "unknown field") {
			return Config{}, fmt.Errorf("%w: %v", ErrUnknownField, derr)
		}
		return Config{}, fmt.Errorf("decode: %w", derr)
	}
	var extra json.RawMessage
	if derr := decoder.Decode(&extra); derr != io.EOF {
		return Config{}, fmt.Errorf("%w: trailing content after the configuration object", ErrInvalidConfig)
	}
	return cfg, nil
}

// WithDefaults fills the documented defaults.
func (c Config) WithDefaults() Config {
	if strings.TrimSpace(c.Listen.API) == "" {
		c.Listen.API = fmt.Sprintf("127.0.0.1:%d", DefaultAPIPort)
	}
	if strings.TrimSpace(c.DataDir) == "" {
		c.DataDir = "./var/lib/gedefense-gate"
	}
	if strings.TrimSpace(c.PolicyFile) == "" {
		c.PolicyFile = "gate-policy.json"
	}
	if c.Timeouts.SessionTTLS == 0 {
		c.Timeouts.SessionTTLS = 900
	}
	if c.Timeouts.TokenTTLS == 0 {
		c.Timeouts.TokenTTLS = 300
	}
	if c.Timeouts.ApprovalTTLS == 0 {
		c.Timeouts.ApprovalTTLS = 86400
	}
	if c.Timeouts.PlanTTLS == 0 {
		c.Timeouts.PlanTTLS = 604800
	}
	if c.Timeouts.WriteSessionMaxUses == 0 {
		c.Timeouts.WriteSessionMaxUses = 1
	}
	for i := range c.Targets {
		if c.Targets[i].TimeoutS == 0 {
			c.Targets[i].TimeoutS = 5
		}
	}
	if c.Notify.TimeoutS == 0 {
		c.Notify.TimeoutS = 5
	}
	if c.Targets == nil {
		c.Targets = []Target{}
	}
	if c.Users == nil {
		c.Users = []domain.GateUser{}
	}
	if c.SourceCIDRs == nil {
		c.SourceCIDRs = []string{}
	}
	return c
}

// EffectiveDataDir returns the cleaned data directory.
func (c Config) EffectiveDataDir() string {
	dir := strings.TrimSpace(c.DataDir)
	if dir == "" {
		dir = "./var/lib/gedefense-gate"
	}
	return filepath.Clean(dir)
}

// PolicyPath resolves the policy file name against baseDir. The policy file must
// be a plain file name: a path would let the configuration escape the data
// directory.
func (c Config) PolicyPath(baseDir string) string {
	name := strings.TrimSpace(c.PolicyFile)
	if name == "" {
		name = "gate-policy.json"
	}
	return filepath.Join(baseDir, name)
}

// Target looks up a configured target.
func (c Config) Target(id domain.TargetID) (Target, bool) {
	for _, target := range c.Targets {
		if target.TargetID == id {
			return target, true
		}
	}
	return Target{}, false
}

// TargetStatus is the listener health surfaced by the API. The targets package of
// the collectors provides the data; the platform defines the shape.
type TargetStatus struct {
	TargetID domain.TargetID `json:"target_id"`
	Protocol string          `json:"protocol"`
	State    string          `json:"state"`
}
