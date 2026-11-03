package config

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/identity"
)

// Modbus function codes that may ever be written through the gate. Anything else
// is a configuration error, not a runtime decision.
var modbusWriteFCs = map[int]struct{}{5: {}, 6: {}, 15: {}, 16: {}, 22: {}, 23: {}}

// Modbus read function codes allowed for the read window.
var modbusReadFCs = map[int]struct{}{1: {}, 2: {}, 3: {}, 4: {}, 7: {}, 17: {}}

// Validate checks the effective configuration (after WithDefaults).
func (c Config) Validate() error {
	if err := validateListen(c.Listen); err != nil {
		return err
	}
	if dir := strings.TrimSpace(c.DataDir); dir == "" || dir == "." || dir == "/" || strings.ContainsRune(dir, 0) {
		return fmt.Errorf("%w: data_dir must be a dedicated directory", ErrInvalidConfig)
	}
	if err := c.SiteID.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	if err := c.GatewayAssetID.Validate(); err != nil {
		return fmt.Errorf("%w: gateway_asset_id: %w", ErrInvalidConfig, err)
	}
	if err := validatePolicyFileName(c.PolicyFile); err != nil {
		return err
	}
	if err := c.validateTimeouts(); err != nil {
		return err
	}
	if err := c.validateTargets(); err != nil {
		return err
	}
	if err := c.validateSourceCIDRs(); err != nil {
		return err
	}
	if err := c.validateUsers(); err != nil {
		return err
	}
	if err := c.validateNotify(); err != nil {
		return err
	}
	return nil
}

func validateListen(listen Listen) error {
	if strings.TrimSpace(listen.API) == "" {
		return fmt.Errorf("%w: listen.api is required", ErrInvalidConfig)
	}
	if err := validateHostPort(listen.API); err != nil {
		return fmt.Errorf("%w: listen.api: %w", ErrInvalidConfig, err)
	}
	certSet := strings.TrimSpace(listen.TLSCertFile) != ""
	keySet := strings.TrimSpace(listen.TLSKeyFile) != ""
	if certSet != keySet {
		return fmt.Errorf("%w: listen.tls_cert_file and listen.tls_key_file must be configured together", ErrInvalidConfig)
	}
	if listen.RequireClientCert {
		if !certSet {
			return fmt.Errorf("%w: listen.require_client_cert requires a TLS certificate", ErrInvalidConfig)
		}
		if strings.TrimSpace(listen.ClientCAFile) == "" {
			return fmt.Errorf("%w: listen.require_client_cert requires client_ca_file", ErrInvalidConfig)
		}
	}
	return nil
}

func validatePolicyFileName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("%w: policy_file is required", ErrInvalidConfig)
	}
	if strings.ContainsAny(trimmed, `/\:`) || trimmed == "." || trimmed == ".." {
		return fmt.Errorf("%w: policy_file must be a plain file name, got %q", ErrInvalidConfig, name)
	}
	return nil
}

func (c Config) validateTimeouts() error {
	checks := []struct {
		name  string
		value int
		low   int
		high  int
	}{
		{"session_ttl_s", c.Timeouts.SessionTTLS, 60, 86400},
		{"token_ttl_s", c.Timeouts.TokenTTLS, 30, 3600},
		{"approval_ttl_s", c.Timeouts.ApprovalTTLS, 60, 604800},
		{"plan_ttl_s", c.Timeouts.PlanTTLS, 60, 2592000},
		{"write_session_max_uses", c.Timeouts.WriteSessionMaxUses, 1, 10},
	}
	for _, check := range checks {
		if check.value < check.low || check.value > check.high {
			return fmt.Errorf("%w: timeouts.%s must be between %d and %d", ErrInvalidConfig, check.name, check.low, check.high)
		}
	}
	if c.Timeouts.PlanTTLS < c.Timeouts.ApprovalTTLS {
		return fmt.Errorf("%w: plan_ttl_s must be >= approval_ttl_s", ErrInvalidConfig)
	}
	if c.Timeouts.SessionTTLS > c.Timeouts.PlanTTLS {
		return fmt.Errorf("%w: session_ttl_s must not exceed plan_ttl_s", ErrInvalidConfig)
	}
	return nil
}

func (c Config) validateTargets() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("%w: at least one target is required", ErrInvalidConfig)
	}
	if len(c.Targets) > maxTargets {
		return fmt.Errorf("%w: at most %d targets are supported", ErrInvalidConfig, maxTargets)
	}
	seenIDs := make(map[domain.TargetID]struct{}, len(c.Targets))
	seenListen := make(map[string]struct{}, len(c.Targets))
	for i, target := range c.Targets {
		if err := target.TargetID.Validate(); err != nil {
			return fmt.Errorf("%w: targets[%d]: %w", ErrInvalidConfig, i, err)
		}
		if _, dup := seenIDs[target.TargetID]; dup {
			return fmt.Errorf("%w: duplicate target_id %q", ErrInvalidConfig, target.TargetID)
		}
		seenIDs[target.TargetID] = struct{}{}
		if err := target.AssetID.Validate(); err != nil {
			return fmt.Errorf("%w: target %q: %w", ErrInvalidConfig, target.TargetID, err)
		}
		if err := validateHostPort(target.Listen); err != nil {
			return fmt.Errorf("%w: target %q listen: %w", ErrInvalidConfig, target.TargetID, err)
		}
		if _, dup := seenListen[target.Listen]; dup {
			return fmt.Errorf("%w: duplicate target listen address %q", ErrInvalidConfig, target.Listen)
		}
		seenListen[target.Listen] = struct{}{}
		if strings.TrimSpace(target.Upstream) == "" {
			return fmt.Errorf("%w: target %q upstream is required", ErrInvalidConfig, target.TargetID)
		}
		if target.TimeoutS < 1 || target.TimeoutS > 60 {
			return fmt.Errorf("%w: target %q timeout_s must be between 1 and 60", ErrInvalidConfig, target.TargetID)
		}
		switch target.Protocol {
		case "modbus_tcp":
			if err := validateModbusTarget(target); err != nil {
				return err
			}
		case "http":
			if err := validateHTTPTarget(target); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: target %q protocol %q is not supported in 0.2 (modbus_tcp, http)", ErrInvalidConfig, target.TargetID, target.Protocol)
		}
	}
	return nil
}

func validateModbusTarget(target Target) error {
	if err := validateHostPort(target.Upstream); err != nil {
		return fmt.Errorf("%w: target %q upstream: %w", ErrInvalidConfig, target.TargetID, err)
	}
	if target.UnitID < 0 || target.UnitID > 255 {
		return fmt.Errorf("%w: target %q unit_id must be 0..255", ErrInvalidConfig, target.TargetID)
	}
	if target.ReadRegisters == nil {
		return fmt.Errorf("%w: target %q requires read_registers", ErrInvalidConfig, target.TargetID)
	}
	spec := *target.ReadRegisters
	if _, ok := modbusReadFCs[spec.FC]; !ok {
		return fmt.Errorf("%w: target %q read_registers.fc must be a read function code", ErrInvalidConfig, target.TargetID)
	}
	if spec.Start < 0 || spec.Start > 65535 || spec.Count < 1 || spec.Count > 125 {
		return fmt.Errorf("%w: target %q read_registers window is invalid", ErrInvalidConfig, target.TargetID)
	}
	if len(target.URLAllowlist) != 0 {
		return fmt.Errorf("%w: target %q is modbus_tcp but has a url_allowlist", ErrInvalidConfig, target.TargetID)
	}
	return nil
}

func validateHTTPTarget(target Target) error {
	parsed, err := url.Parse(strings.TrimSpace(target.Upstream))
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("%w: target %q upstream is not a valid URL", ErrInvalidConfig, target.TargetID)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("%w: target %q upstream must use http or https", ErrInvalidConfig, target.TargetID)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: target %q upstream must not embed credentials", ErrInvalidConfig, target.TargetID)
	}
	if target.InsecureSkipVerify && parsed.Scheme != "https" {
		return fmt.Errorf("%w: target %q insecure_skip_verify requires https", ErrInvalidConfig, target.TargetID)
	}
	if len(target.URLAllowlist) == 0 {
		return fmt.Errorf("%w: target %q requires a non-empty url_allowlist", ErrInvalidConfig, target.TargetID)
	}
	for _, allowed := range target.URLAllowlist {
		if !strings.HasPrefix(allowed, "/") || len(allowed) < 1 || len(allowed) > 256 || strings.Contains(allowed, "..") {
			return fmt.Errorf("%w: target %q url_allowlist entry %q is invalid", ErrInvalidConfig, target.TargetID, allowed)
		}
	}
	if target.ReadRegisters != nil {
		return fmt.Errorf("%w: target %q is http but has read_registers", ErrInvalidConfig, target.TargetID)
	}
	return nil
}

func (c Config) validateSourceCIDRs() error {
	if len(c.SourceCIDRs) == 0 {
		return fmt.Errorf("%w: source_cidrs must not be empty (default-deny needs an explicit management network)", ErrInvalidConfig)
	}
	for _, cidr := range c.SourceCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			return fmt.Errorf("%w: source_cidrs entry %q is not a CIDR", ErrInvalidConfig, cidr)
		}
	}
	return nil
}

func (c Config) validateUsers() error {
	if len(c.Users) == 0 {
		return fmt.Errorf("%w: at least one user is required", ErrInvalidConfig)
	}
	if len(c.Users) > maxUsers {
		return fmt.Errorf("%w: at most %d users are supported", ErrInvalidConfig, maxUsers)
	}
	seen := make(map[domain.GateUserID]struct{}, len(c.Users))
	hasMaster := false
	needsMTLS := false
	for i, user := range c.Users {
		if err := user.Validate(); err != nil {
			return fmt.Errorf("%w: users[%d]: %w", ErrInvalidConfig, i, err)
		}
		if _, dup := seen[user.UserID]; dup {
			return fmt.Errorf("%w: duplicate user_id %q", ErrInvalidConfig, user.UserID)
		}
		seen[user.UserID] = struct{}{}
		if err := identity.ValidatePasswordHash(user.PasswordHash); err != nil {
			return fmt.Errorf("%w: users[%d] %q: %w", ErrInvalidConfig, i, user.UserID, err)
		}
		if isPlaceholderHash(user.PasswordHash) {
			return fmt.Errorf("%w: users[%d] %q: password hash is a placeholder; rotate it", ErrInvalidConfig, i, user.UserID)
		}
		if len(user.DeviceFingerprints) > 0 {
			needsMTLS = true
			for _, fingerprint := range user.DeviceFingerprints {
				if err := identity.ValidateFingerprint(fingerprint); err != nil {
					return fmt.Errorf("%w: users[%d] %q: %w", ErrInvalidConfig, i, user.UserID, err)
				}
			}
		}
		requiresMFA := false
		for _, role := range user.Roles {
			switch role {
			case domain.GateRoleVendorRead, domain.GateRoleVendorWriteRequester:
				if user.Kind != domain.GateUserVendor {
					return fmt.Errorf("%w: users[%d] %q: vendor role %q requires kind vendor", ErrInvalidConfig, i, user.UserID, role)
				}
			case domain.GateRoleApprover, domain.GateRoleMasterAdmin, domain.GateRoleAuditor:
				if user.Kind == domain.GateUserVendor {
					return fmt.Errorf("%w: users[%d] %q: role %q is not allowed for kind vendor", ErrInvalidConfig, i, user.UserID, role)
				}
				requiresMFA = true
			}
			if role == domain.GateRoleMasterAdmin {
				hasMaster = true
			}
		}
		if requiresMFA && !user.TOTPEnabled {
			return fmt.Errorf("%w: users[%d] %q: approver/master_admin/auditor accounts require TOTP", ErrInvalidConfig, i, user.UserID)
		}
		if user.TOTPEnabled {
			if err := identity.ValidateTOTPSecret(user.TOTPSecret); err != nil {
				return fmt.Errorf("%w: users[%d] %q: %w", ErrInvalidConfig, i, user.UserID, err)
			}
		}
	}
	if !hasMaster {
		return fmt.Errorf("%w: at least one master_admin user is required", ErrInvalidConfig)
	}
	if needsMTLS {
		if !c.Listen.RequireClientCert {
			return fmt.Errorf("%w: device-bound users require listen.require_client_cert", ErrInvalidConfig)
		}
	}
	return nil
}

func (c Config) validateNotify() error {
	raw := strings.TrimSpace(c.Notify.WebhookURL)
	if raw != "" {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			return fmt.Errorf("%w: notify.webhook_url is not a valid URL", ErrInvalidConfig)
		}
		if parsed.Scheme != "https" {
			if parsed.Scheme != "http" || !isLoopbackHost(parsed.Hostname()) {
				return fmt.Errorf("%w: notify.webhook_url must use https (http only for loopback)", ErrInvalidConfig)
			}
		}
		if parsed.User != nil {
			return fmt.Errorf("%w: notify.webhook_url must not embed credentials", ErrInvalidConfig)
		}
		if secret := strings.TrimSpace(c.Notify.HMACSecret); secret != "" && len(secret) < 16 {
			return fmt.Errorf("%w: notify.hmac_secret must be at least 16 characters", ErrInvalidConfig)
		}
	}
	if c.Notify.TimeoutS < 1 || c.Notify.TimeoutS > 30 {
		return fmt.Errorf("%w: notify.timeout_s must be between 1 and 30", ErrInvalidConfig)
	}
	last := 0
	for _, step := range c.Notify.Escalation {
		if !step.Role.Valid() {
			return fmt.Errorf("%w: notify.escalation role %q is invalid", ErrInvalidConfig, step.Role)
		}
		if step.AfterMinutes <= last {
			return fmt.Errorf("%w: notify.escalation after_minutes must increase", ErrInvalidConfig)
		}
		last = step.AfterMinutes
	}
	return nil
}

// validateHostPort accepts host:port with a numeric port.
func validateHostPort(address string) error {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return fmt.Errorf("not a host:port address")
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("host must be explicit")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port")
	}
	return nil
}

// isLoopbackHost reports whether host is the loopback interface.
func isLoopbackHost(host string) bool {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(host), "["), "]")
	if trimmed == "localhost" {
		return true
	}
	ip := net.ParseIP(trimmed)
	return ip != nil && ip.IsLoopback()
}

// RandomSecret generates a URL-safe secret for CLI onboarding helpers.
func RandomSecret(bytesCount int) (string, error) {
	if bytesCount < 16 || bytesCount > 64 {
		return "", fmt.Errorf("%w: secret length must be between 16 and 64 bytes", ErrInvalidConfig)
	}
	raw := make([]byte, bytesCount)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("gate config: generate secret: %w", err)
	}
	return fmt.Sprintf("%x", raw), nil
}
