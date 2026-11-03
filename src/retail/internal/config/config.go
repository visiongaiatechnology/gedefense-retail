// Package config loads, validates and defaults the JSON configuration of a
// GeDefense Retail gateway.
//
// The loader is deliberately strict: unknown JSON fields are rejected, exactly
// one JSON document is accepted, and every value that ends up in the running
// process passes through Validate. Secrets are never accepted in plain text –
// API tokens are configured exclusively as SHA-256 hex digests (see
// cmd/retaild gen-token).
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// ErrInvalidConfig is the single sentinel wrapper for every configuration
// problem. Callers use errors.Is to distinguish a bad configuration file from
// an I/O failure while still getting the precise detail in the message.
var ErrInvalidConfig = errors.New("invalid configuration")

// ErrUnknownField is returned when the JSON document contains a field that this
// build does not know. Accepting unknown fields would silently ignore security
// relevant settings after a downgrade.
var ErrUnknownField = errors.New("unknown configuration field")

// Role is the operator role of a configured user. It maps 1:1 onto the HTTP
// API authorisation model (viewer < operator < admin).
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleViewer, RoleOperator, RoleAdmin:
		return true
	}
	return false
}

// Rank returns the monotonic privilege value used for "at least this role"
// checks. Unknown roles rank below viewer so that a broken configuration can
// never grant access.
func (r Role) Rank() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	}
	return 0
}

// Allows reports whether r grants at least the required role.
func (r Role) Allows(required Role) bool { return r.Rank() >= required.Rank() }

// User is one local operator account. TokenSHA256 is the lowercase hex SHA-256
// digest of the bearer token; the token itself is never stored.
type User struct {
	UserID      domain.UserID `json:"user_id"`
	Name        string        `json:"name"`
	Role        Role          `json:"role"`
	TokenSHA256 string        `json:"token_sha256"`
}

// AdapterConfig selects and configures one collector adapter. Options are
// adapter specific and intentionally not validated here: the adapter owns its
// option contract.
type AdapterConfig struct {
	AdapterID string            `json:"adapter_id"`
	Enabled   bool              `json:"enabled"`
	ZoneID    domain.ZoneID     `json:"zone_id,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
}

// CentralConfig configures the optional outbound connection to the central
// management plane. The MVP only ever connects outbound (no inbound WAN path).
type CentralConfig struct {
	URL            string `json:"url,omitempty"`
	TimeoutS       int    `json:"timeout_s,omitempty"`
	ClientCertFile string `json:"client_cert_file,omitempty"`
	ClientKeyFile  string `json:"client_key_file,omitempty"`
	CAFile         string `json:"ca_file,omitempty"`
	BatchSize      int    `json:"batch_size,omitempty"`
	SpoolMaxMB     int64  `json:"spool_max_mb,omitempty"`
}

// SimulationConfig enables the simulator/development ingest path. It is only
// accepted together with a loopback listen address.
type SimulationConfig struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen,omitempty"`
}

// SecurityConfig hardens dashboard access: source-IP whitelist and optional
// proxy-header trust. require_whitelist is a pointer so that an omitted field
// means the fail-closed default (true) while an explicit false stays possible.
// TrustedProxyCIDRs is the allowlist of reverse proxies whose X-Forwarded-For
// header may be trusted (F-SW-02); it is mandatory when trust_proxy_headers=true.
type SecurityConfig struct {
	RequireWhitelist        *bool    `json:"require_whitelist,omitempty"`
	DashboardWhitelistCIDRs []string `json:"dashboard_whitelist_cidrs"`
	TrustProxyHeaders       bool     `json:"trust_proxy_headers"`
	TrustedProxyCIDRs       []string `json:"trusted_proxy_cidrs,omitempty"`
	SetupTokenTTLS          int      `json:"setup_token_ttl_s,omitempty"`
}

// SetupState is the persisted first-run setup progress.
type SetupState struct {
	Completed   bool   `json:"completed"`
	CompletedAt string `json:"completed_at,omitempty"`
	Language    string `json:"language"`
}

// Config is the complete runtime configuration of one gateway.
type Config struct {
	Listen     string            `json:"listen"`
	DataDir    string            `json:"data_dir"`
	LogLevel   string            `json:"log_level"`
	Site       domain.Site       `json:"site"`
	Users      []User            `json:"users"`
	Collectors []AdapterConfig   `json:"collectors"`
	Central    *CentralConfig    `json:"central,omitempty"`
	Simulation *SimulationConfig `json:"simulation,omitempty"`
	Policy     *domain.Policy    `json:"policy,omitempty"`
	WebDir     string            `json:"web_dir,omitempty"`
	Security   *SecurityConfig   `json:"security,omitempty"`
	Setup      *SetupState       `json:"setup,omitempty"`
}

// SetupLanguages is the allowlist of wizard languages (contract �2/�5).
var SetupLanguages = []string{"en", "de", "fr", "it", "es", "ja", "zh", "ru"}

// EffectiveSecurity resolves the security defaults (require_whitelist=true,
// setup_token_ttl_s=3600) for an omitted or partial security object.
func (c Config) EffectiveSecurity() SecurityConfig {
	out := SecurityConfig{RequireWhitelist: boolPtr(true), SetupTokenTTLS: 3600}
	if c.Security == nil {
		return out
	}
	if c.Security.RequireWhitelist != nil {
		out.RequireWhitelist = boolPtr(*c.Security.RequireWhitelist)
	}
	out.DashboardWhitelistCIDRs = append([]string(nil), c.Security.DashboardWhitelistCIDRs...)
	out.TrustProxyHeaders = c.Security.TrustProxyHeaders
	out.TrustedProxyCIDRs = append([]string(nil), c.Security.TrustedProxyCIDRs...)
	if c.Security.SetupTokenTTLS > 0 {
		out.SetupTokenTTLS = c.Security.SetupTokenTTLS
	}
	return out
}

// SetupCompleted reports whether the first-run wizard finished.
func (c Config) SetupCompleted() bool { return c.Setup != nil && c.Setup.Completed }

// SetupLanguage returns the configured wizard/dashboard language (default en).
func (c Config) SetupLanguage() string {
	if c.Setup != nil && c.Setup.Language != "" {
		return c.Setup.Language
	}
	return "en"
}

// SetupMode reports whether the gateway must run in first-run mode: the wizard is
// incomplete or the whitelist is empty (contract �3).
func (c Config) SetupMode() bool {
	return !c.SetupCompleted() || len(c.EffectiveSecurity().DashboardWhitelistCIDRs) == 0
}

// Warnings returns operator-facing warnings for `retaild check` (contract �2).
func (c Config) Warnings() []string {
	security := c.EffectiveSecurity()
	var warnings []string
	if security.RequireWhitelist != nil && *security.RequireWhitelist && len(security.DashboardWhitelistCIDRs) == 0 {
		warnings = append(warnings, "security.require_whitelist=true but dashboard_whitelist_cidrs is empty: the gateway will start in loopback-only setup mode")
	}
	if security.TrustProxyHeaders {
		warnings = append(warnings, "security.trust_proxy_headers=true: only enable behind a trusted reverse proxy that overwrites X-Forwarded-For; the last hop is used for the whitelist check")
	}
	return warnings
}

// boolPtr returns a pointer to value.
func boolPtr(value bool) *bool { return &value }

// Defaults used when a field is omitted. They are exported so the composition
// root and the self-check report the exact same values.
const (
	DefaultListen   = "127.0.0.1:8080"
	DefaultDataDir  = "./var/lib/gedefense-retail"
	DefaultLogLevel = "info"
	MaxConfigBytes  = 1 << 20 // 1 MiB: a configuration file is not a data store
)

// Log levels accepted by LogLevel.
var logLevels = map[string]struct{}{
	"debug": {}, "info": {}, "warn": {}, "error": {},
}

// Load reads, strictly decodes, defaults and validates the configuration file
// at path.
func Load(path string) (cfg Config, err error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, fmt.Errorf("%w: configuration path is empty", ErrInvalidConfig)
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: open %q: %w", filepath.Base(path), err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("config: close %q: %w", filepath.Base(path), cerr)
		}
	}()

	cfg, err = Parse(io.LimitReader(file, MaxConfigBytes))
	if err != nil {
		return Config{}, fmt.Errorf("config: %q: %w", filepath.Base(path), err)
	}
	cfg = cfg.WithDefaults()
	if verr := cfg.Validate(); verr != nil {
		return Config{}, fmt.Errorf("config: %q: %w", filepath.Base(path), verr)
	}
	return cfg, nil
}

// Parse strictly decodes one JSON configuration document.
func Parse(r io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return Config{}, fmt.Errorf("%w: configuration exceeds %d bytes", ErrInvalidConfig, MaxConfigBytes)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return Config{}, fmt.Errorf("%w: configuration must be a JSON object", ErrInvalidConfig)
	}

	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return Config{}, fmt.Errorf("%w: %v", ErrUnknownField, err)
		}
		return Config{}, fmt.Errorf("decode: %w", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return Config{}, fmt.Errorf("%w: trailing content after the configuration object", ErrInvalidConfig)
	}
	return cfg, nil
}

// WithDefaults returns a copy of cfg with every optional field resolved. It is
// applied by Load and can be called directly by embedders that build a Config
// in code (tests, self-check).
func (c Config) WithDefaults() Config {
	if strings.TrimSpace(c.Listen) == "" {
		c.Listen = DefaultListen
	}
	if strings.TrimSpace(c.DataDir) == "" {
		c.DataDir = DefaultDataDir
	}
	if strings.TrimSpace(c.LogLevel) == "" {
		c.LogLevel = DefaultLogLevel
	}
	if c.Site.Status == "" {
		c.Site.Status = domain.SiteUnknown
	}
	if c.Site.Tags == nil {
		c.Site.Tags = []string{}
	}
	if c.Site.Zones == nil {
		c.Site.Zones = []domain.Zone{}
	}
	for i := range c.Users {
		if strings.TrimSpace(c.Users[i].Name) == "" {
			c.Users[i].Name = string(c.Users[i].UserID)
		}
		c.Users[i].TokenSHA256 = strings.ToLower(strings.TrimSpace(c.Users[i].TokenSHA256))
	}
	if c.Central != nil {
		if c.Central.TimeoutS == 0 {
			c.Central.TimeoutS = 10
		}
		if c.Central.BatchSize == 0 {
			c.Central.BatchSize = 100
		}
		if c.Central.SpoolMaxMB == 0 {
			c.Central.SpoolMaxMB = 512
		}
	}
	if c.Simulation != nil && c.Simulation.Enabled && c.Simulation.Listen == "" {
		c.Simulation.Listen = c.Listen
	}
	if c.Collectors == nil {
		c.Collectors = []AdapterConfig{}
	}
	return c
}

// EffectiveDataDir returns the cleaned data directory that the stores use.
func (c Config) EffectiveDataDir() string {
	dir := strings.TrimSpace(c.DataDir)
	if dir == "" {
		dir = DefaultDataDir
	}
	return filepath.Clean(dir)
}

// EffectiveListen returns the listen address that the HTTP server uses.
func (c Config) EffectiveListen() string {
	if strings.TrimSpace(c.Listen) == "" {
		return DefaultListen
	}
	return strings.TrimSpace(c.Listen)
}

// SimulationEnabled reports whether the simulation/dev path is active.
func (c Config) SimulationEnabled() bool { return c.Simulation != nil && c.Simulation.Enabled }

// User looks up a configured user by identifier.
func (c Config) User(id domain.UserID) (User, bool) {
	for _, u := range c.Users {
		if u.UserID == id {
			return u, true
		}
	}
	return User{}, false
}
