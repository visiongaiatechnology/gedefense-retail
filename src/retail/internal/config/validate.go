package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

const (
	// Token hash shape: SHA-256 hex digest, exactly 64 lowercase hex characters.
	tokenHashHexLen = 64
	// maxAdapterIDLen mirrors the identifier limit of internal/domain.
	maxAdapterIDLen = 96
)

// Validate checks the effective configuration (after WithDefaults). Every
// failure wraps ErrInvalidConfig so callers can classify it.
func (c Config) Validate() error {
	if err := c.validateListen(); err != nil {
		return err
	}
	if err := c.validateDataDir(); err != nil {
		return err
	}
	if _, ok := logLevels[strings.ToLower(strings.TrimSpace(c.LogLevel))]; !ok && c.LogLevel != "" {
		return fmt.Errorf("%w: log_level %q is not one of debug, info, warn, error", ErrInvalidConfig, c.LogLevel)
	}
	if err := c.Site.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	if err := c.validateUsers(); err != nil {
		return err
	}
	if err := c.validateCollectors(); err != nil {
		return err
	}
	if err := c.validateSimulation(); err != nil {
		return err
	}
	if err := c.validateCentral(); err != nil {
		return err
	}
	if err := c.validatePolicy(); err != nil {
		return err
	}
	if wd := strings.TrimSpace(c.WebDir); wd != "" {
		if strings.ContainsRune(wd, 0) {
			return fmt.Errorf("%w: web_dir contains a NUL byte", ErrInvalidConfig)
		}
		if filepath.Clean(wd) == "." {
			return fmt.Errorf("%w: web_dir must not resolve to the working directory", ErrInvalidConfig)
		}
	}
	if err := c.validateSecurity(); err != nil {
		return err
	}
	return nil
}

func (c Config) validateListen() error {
	host, port, err := splitListen(c.EffectiveListen())
	if err != nil {
		return err
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("%w: listen must name an explicit host (for example 127.0.0.1:%d)", ErrInvalidConfig, port)
	}
	if err := validateHost(host); err != nil {
		return err
	}
	return nil
}

func (c Config) validateDataDir() error {
	dir := c.EffectiveDataDir()
	if strings.ContainsRune(dir, 0) {
		return fmt.Errorf("%w: data_dir contains a NUL byte", ErrInvalidConfig)
	}
	if dir == "." || dir == string(filepath.Separator) {
		return fmt.Errorf("%w: data_dir must be a dedicated directory, not %q", ErrInvalidConfig, dir)
	}
	return nil
}

func (c Config) validateUsers() error {
	if len(c.Users) == 0 {
		return fmt.Errorf("%w: at least one user (admin) is required", ErrInvalidConfig)
	}
	ids := make(map[domain.UserID]struct{}, len(c.Users))
	hashes := make(map[string]struct{}, len(c.Users))
	admins := 0
	for i, u := range c.Users {
		if err := u.UserID.Validate(); err != nil {
			return fmt.Errorf("%w: users[%d]: %w", ErrInvalidConfig, i, err)
		}
		if _, dup := ids[u.UserID]; dup {
			return fmt.Errorf("%w: users[%d]: duplicate user_id %q", ErrInvalidConfig, i, u.UserID)
		}
		ids[u.UserID] = struct{}{}
		if !u.Role.Valid() {
			return fmt.Errorf("%w: users[%d] %q: role %q is not one of viewer, operator, admin", ErrInvalidConfig, i, u.UserID, u.Role)
		}
		if u.Role == RoleAdmin {
			admins++
		}
		if err := validateTokenHash(u.TokenSHA256); err != nil {
			return fmt.Errorf("%w: users[%d] %q: %w", ErrInvalidConfig, i, u.UserID, err)
		}
		if _, dup := hashes[u.TokenSHA256]; dup {
			return fmt.Errorf("%w: users[%d] %q: token_sha256 is configured for more than one user", ErrInvalidConfig, i, u.UserID)
		}
		hashes[u.TokenSHA256] = struct{}{}
	}
	if admins == 0 {
		return fmt.Errorf("%w: at least one user with role admin is required", ErrInvalidConfig)
	}
	return nil
}

// validateTokenHash rejects malformed digests and well-known placeholder
// digests: a configuration that still carries a default token must never start.
func validateTokenHash(hash string) error {
	if len(hash) != tokenHashHexLen {
		return fmt.Errorf("token_sha256 must be %d hex characters (sha256 of the token), got %d characters", tokenHashHexLen, len(hash))
	}
	raw, err := hex.DecodeString(hash)
	if err != nil || len(raw) != sha256.Size {
		return fmt.Errorf("token_sha256 is not a valid SHA-256 hex digest")
	}
	if isPlaceholderHash(hash) {
		return fmt.Errorf("token_sha256 is a well-known placeholder; generate a real token with retaild gen-token")
	}
	return nil
}

func isPlaceholderHash(hash string) bool {
	if hash == strings.Repeat("0", tokenHashHexLen) || hash == strings.Repeat("f", tokenHashHexLen) {
		return true
	}
	for _, word := range []string{
		"changeme", "change-me", "admin", "administrator", "token", "password",
		"secret", "test", "demo", "gedefense", "retail", "default", "example",
	} {
		sum := sha256.Sum256([]byte(word))
		if hex.EncodeToString(sum[:]) == hash {
			return true
		}
	}
	return false
}

func (c Config) validateCollectors() error {
	seen := make(map[string]struct{}, len(c.Collectors))
	zones := make(map[domain.ZoneID]struct{}, len(c.Site.Zones))
	for _, z := range c.Site.Zones {
		zones[z.ZoneID] = struct{}{}
	}
	for i, a := range c.Collectors {
		if strings.TrimSpace(a.AdapterID) == "" {
			return fmt.Errorf("%w: collectors[%d]: adapter_id is required", ErrInvalidConfig, i)
		}
		if len(a.AdapterID) > maxAdapterIDLen {
			return fmt.Errorf("%w: collectors[%d]: adapter_id is too long", ErrInvalidConfig, i)
		}
		if _, dup := seen[a.AdapterID]; dup {
			return fmt.Errorf("%w: collectors[%d]: duplicate adapter_id %q", ErrInvalidConfig, i, a.AdapterID)
		}
		seen[a.AdapterID] = struct{}{}
		if a.ZoneID != "" {
			if err := a.ZoneID.Validate(); err != nil {
				return fmt.Errorf("%w: collectors[%d] %q: %w", ErrInvalidConfig, i, a.AdapterID, err)
			}
			if _, ok := zones[a.ZoneID]; !ok {
				return fmt.Errorf("%w: collectors[%d] %q: zone_id %q is not declared in site.zones", ErrInvalidConfig, i, a.AdapterID, a.ZoneID)
			}
		}
		if len(a.Options) > 64 {
			return fmt.Errorf("%w: collectors[%d] %q: too many options", ErrInvalidConfig, i, a.AdapterID)
		}
		for k, v := range a.Options {
			if strings.TrimSpace(k) == "" || len(k) > 64 || len(v) > 1024 {
				return fmt.Errorf("%w: collectors[%d] %q: invalid option %q", ErrInvalidConfig, i, a.AdapterID, k)
			}
		}
	}
	return nil
}

func (c Config) validateSimulation() error {
	if c.Simulation == nil {
		return nil
	}
	if !c.Simulation.Enabled {
		return nil
	}
	host, _, err := splitListen(c.EffectiveListen())
	if err != nil {
		return err
	}
	if !IsLoopbackHost(host) {
		return fmt.Errorf("%w: simulation is only allowed with a loopback listen address, got host %q", ErrInvalidConfig, host)
	}
	if strings.TrimSpace(c.Simulation.Listen) != "" {
		simHost, _, lerr := splitListen(c.Simulation.Listen)
		if lerr != nil {
			return fmt.Errorf("simulation: %w", lerr)
		}
		if !IsLoopbackHost(simHost) {
			return fmt.Errorf("%w: simulation.listen %q is not a loopback address", ErrInvalidConfig, c.Simulation.Listen)
		}
	}
	return nil
}

func (c Config) validateCentral() error {
	if c.Central == nil {
		return nil
	}
	raw := strings.TrimSpace(c.Central.URL)
	if raw == "" {
		return fmt.Errorf("%w: central.url is required when central is configured", ErrInvalidConfig)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: central.url: %w", ErrInvalidConfig, err)
	}
	if u.Host == "" || u.User != nil {
		return fmt.Errorf("%w: central.url must contain a host and must not embed credentials", ErrInvalidConfig)
	}
	host := u.Hostname()
	if u.Scheme != "https" {
		// Plain HTTP is only tolerated for a loopback test endpoint; production
		// forwarding is mTLS-only.
		if u.Scheme != "http" || !IsLoopbackHost(host) {
			return fmt.Errorf("%w: central.url must use https (http is only allowed for loopback)", ErrInvalidConfig)
		}
	}
	if c.Central.TimeoutS < 1 || c.Central.TimeoutS > 300 {
		return fmt.Errorf("%w: central.timeout_s must be between 1 and 300", ErrInvalidConfig)
	}
	if c.Central.BatchSize < 1 || c.Central.BatchSize > 1000 {
		return fmt.Errorf("%w: central.batch_size must be between 1 and 1000", ErrInvalidConfig)
	}
	if c.Central.SpoolMaxMB < 1 || c.Central.SpoolMaxMB > 1_000_000 {
		return fmt.Errorf("%w: central.spool_max_mb must be between 1 and 1000000", ErrInvalidConfig)
	}
	certSet := strings.TrimSpace(c.Central.ClientCertFile) != ""
	keySet := strings.TrimSpace(c.Central.ClientKeyFile) != ""
	if certSet != keySet {
		return fmt.Errorf("%w: central.client_cert_file and central.client_key_file must be configured together", ErrInvalidConfig)
	}
	for _, p := range []string{c.Central.ClientCertFile, c.Central.ClientKeyFile, c.Central.CAFile} {
		if p != "" && strings.ContainsRune(p, 0) {
			return fmt.Errorf("%w: central certificate path contains a NUL byte", ErrInvalidConfig)
		}
	}
	// FIND-008: mTLS is mandatory for a real (non-loopback) central endpoint.
	// require_mtls defaults to true; an explicit false is an audited opt-out.
	if c.CentralRequiresMTLS() && u.Scheme == "https" {
		if !certSet || !keySet {
			return fmt.Errorf("%w: central mTLS requires central.client_cert_file and central.client_key_file (or explicit require_mtls=false)", ErrInvalidConfig)
		}
		if strings.TrimSpace(c.Central.CAFile) == "" {
			return fmt.Errorf("%w: central mTLS requires central.ca_file for server authentication", ErrInvalidConfig)
		}
	}
	return nil
}

// CentralRequiresMTLS reports the effective mTLS requirement (default true).
func (c Config) CentralRequiresMTLS() bool {
	if c.Central == nil {
		return false
	}
	if c.Central.RequireMTLS != nil {
		return *c.Central.RequireMTLS
	}
	return true
}

func (c Config) validatePolicy() error {
	if c.Policy == nil {
		return nil
	}
	if err := c.Policy.Validate(); err != nil {
		return fmt.Errorf("%w: policy: %w", ErrInvalidConfig, err)
	}
	if c.Policy.SiteID != c.Site.SiteID {
		return fmt.Errorf("%w: policy.site_id %q does not match site.site_id %q", ErrInvalidConfig, c.Policy.SiteID, c.Site.SiteID)
	}
	return nil
}

// splitListen validates a host:port listen address and returns its parts.
func splitListen(addr string) (host string, port int, err error) {
	host, portStr, serr := net.SplitHostPort(strings.TrimSpace(addr))
	if serr != nil {
		return "", 0, fmt.Errorf("%w: listen %q is not a valid host:port address: %w", ErrInvalidConfig, addr, serr)
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("%w: listen %q has an invalid port", ErrInvalidConfig, addr)
	}
	return host, port, nil
}

// validateHost accepts IP literals, "localhost" and DNS-style host names.
func validateHost(host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}
	if host == "localhost" {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("%w: listen host is too long", ErrInvalidConfig)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%w: listen host %q is not a valid host name or IP address", ErrInvalidConfig, host)
		}
		for i := 0; i < len(label); i++ {
			switch ch := label[i]; {
			case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
			case ch == '-', ch == '_':
			default:
				return fmt.Errorf("%w: listen host %q contains an invalid character", ErrInvalidConfig, host)
			}
		}
	}
	return nil
}

// IsLoopbackHost reports whether host denotes the loopback interface. It is used
// by the configuration validator and by the API's dev-ingest guard.
func IsLoopbackHost(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// validateSecurity enforces the whitelist/proxy/setup hardening rules. An empty
// whitelist with require_whitelist=true is allowed only in first-run (setup) mode,
// where the gateway binds loopback exclusively.
func (c Config) validateSecurity() error {
	security := c.EffectiveSecurity()
	if len(security.DashboardWhitelistCIDRs) > 64 {
		return fmt.Errorf("%w: security.dashboard_whitelist_cidrs allows at most 64 entries", ErrInvalidConfig)
	}
	for i, raw := range security.DashboardWhitelistCIDRs {
		if _, _, err := parseWhitelistEntry(raw); err != nil {
			return fmt.Errorf("%w: security.dashboard_whitelist_cidrs[%d]: %v", ErrInvalidConfig, i, err)
		}
	}
	if security.SetupTokenTTLS < 60 || security.SetupTokenTTLS > 86400 {
		return fmt.Errorf("%w: security.setup_token_ttl_s must be between 60 and 86400", ErrInvalidConfig)
	}
	// F-SW-02: trusting X-Forwarded-For without a proxy allowlist lets any direct
	// client spoof its source IP and bypass the whitelist. Fail closed at startup.
	if len(security.TrustedProxyCIDRs) > 64 {
		return fmt.Errorf("%w: security.trusted_proxy_cidrs allows at most 64 entries", ErrInvalidConfig)
	}
	for i, raw := range security.TrustedProxyCIDRs {
		if _, _, err := parseWhitelistEntry(raw); err != nil {
			return fmt.Errorf("%w: security.trusted_proxy_cidrs[%d]: %v", ErrInvalidConfig, i, err)
		}
	}
	if security.TrustProxyHeaders && len(security.TrustedProxyCIDRs) == 0 {
		return fmt.Errorf("%w: security.trust_proxy_headers=true requires a non-empty security.trusted_proxy_cidrs list", ErrInvalidConfig)
	}
	if c.Setup != nil {
		if c.Setup.Language != "" && !containsString(SetupLanguages, c.Setup.Language) {
			return fmt.Errorf("%w: setup.language %q is not supported", ErrInvalidConfig, c.Setup.Language)
		}
		if c.Setup.CompletedAt != "" {
			if _, err := time.Parse(time.RFC3339, c.Setup.CompletedAt); err != nil {
				return fmt.Errorf("%w: setup.completed_at must be RFC 3339", ErrInvalidConfig)
			}
		}
		if c.Setup.Completed && security.RequireWhitelist != nil && *security.RequireWhitelist &&
			len(security.DashboardWhitelistCIDRs) == 0 {
			return fmt.Errorf("%w: setup is completed but the whitelist is empty while require_whitelist=true", ErrInvalidConfig)
		}
	}
	return nil
}

// parseWhitelistEntry accepts a CIDR prefix or a single IP address (implicit /32
// or /128) and returns the normalized prefix.
func parseWhitelistEntry(raw string) (netip.Prefix, netip.Addr, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("empty entry")
	}
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return prefix.Masked(), prefix.Addr(), nil
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("%q is neither a CIDR nor an IP address", raw)
	}
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), addr, nil
}

// containsString reports membership in a string slice.
func containsString(list []string, value string) bool {
	for _, candidate := range list {
		if candidate == value {
			return true
		}
	}
	return false
}
