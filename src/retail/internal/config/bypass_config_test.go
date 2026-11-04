package config

import (
	"strings"
	"testing"
)

func TestBypassConfigDefaultsAndValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		bypass  *BypassConfig
		wantErr string
	}{
		{"absent block stays disabled", nil, ""},
		{"disabled without sources", &BypassConfig{}, ""},
		{"enabled requires sources", &BypassConfig{Enabled: true}, "bypass.enabled=true requires at least one"},
		{"enabled with single ip", &BypassConfig{Enabled: true, GateSourceCIDRs: []string{"10.20.30.10"}}, ""},
		{"enabled with ipv4 cidr", &BypassConfig{Enabled: true, GateSourceCIDRs: []string{"10.20.30.0/24"}}, ""},
		{"enabled with ipv6 cidr", &BypassConfig{Enabled: true, GateSourceCIDRs: []string{"fd00::/64"}}, ""},
		{"enabled mixed v4 v6", &BypassConfig{Enabled: true, GateSourceCIDRs: []string{"10.20.30.10", "fd00::1"}}, ""},
		{"invalid entry", &BypassConfig{Enabled: true, GateSourceCIDRs: []string{"not-an-ip"}}, "bypass.gate_source_cidrs[0]"},
		{"invalid prefix", &BypassConfig{Enabled: true, GateSourceCIDRs: []string{"10.0.0.0/33"}}, "bypass.gate_source_cidrs[0]"},
		{"duplicate normalized cidr", &BypassConfig{Enabled: true, GateSourceCIDRs: []string{"10.0.0.0/24", "10.0.0.1/24"}}, "duplicate entry"},
		{"duplicate ip", &BypassConfig{Enabled: true, GateSourceCIDRs: []string{"10.20.30.10", "10.20.30.10"}}, "duplicate entry"},
		{"disabled but invalid stays fail-closed", &BypassConfig{GateSourceCIDRs: []string{"bad"}}, "bypass.gate_source_cidrs[0]"},
		{"ipv6 zone rejected", &BypassConfig{Enabled: true, GateSourceCIDRs: []string{"fe80::1%eth0"}}, "zone identifiers"},
		{"too many entries", &BypassConfig{Enabled: true, GateSourceCIDRs: make([]string, 65)}, "at most 64"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.Bypass = tc.bypass
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestBypassConfigRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	raw := `{
	  "site": {"site_id": "filiale-001", "name": "Markt", "status": "online"},
	  "users": [{"user_id": "admin", "name": "Admin", "role": "admin", "token_sha256": "` + tokenHash("admin-token") + `"}],
	  "bypass": {"enabled": true, "gate_source_cidrs": ["10.20.30.10"], "unknown_field": true}
	}`
	if _, err := Parse(strings.NewReader(raw)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want unknown-field rejection", err)
	}
}

func TestBypassConfigParsesRuntimeExample(t *testing.T) {
	t.Parallel()
	cfg := baseConfig()
	cfg.Bypass = &BypassConfig{Enabled: true, GateSourceCIDRs: []string{"10.20.30.10/32"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid bypass config rejected: %v", err)
	}
}
