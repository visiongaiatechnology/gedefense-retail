package config

import (
	"errors"
	"testing"
)

// TestTrustedProxyConfigValidation: trusting XFF without a proxy allowlist must
// fail closed at startup (F-SW-02).
func TestTrustedProxyConfigValidation(t *testing.T) {
	base := Config{Security: &SecurityConfig{TrustProxyHeaders: true}}
	if err := base.validateSecurity(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("trust without allowlist error = %v", err)
	}
	withList := Config{Security: &SecurityConfig{
		TrustProxyHeaders: true,
		TrustedProxyCIDRs: []string{"10.10.0.0/16", "192.168.1.10"},
	}}
	if err := withList.validateSecurity(); err != nil {
		t.Fatalf("valid trusted proxies rejected: %v", err)
	}
	badCIDR := Config{Security: &SecurityConfig{
		TrustProxyHeaders: true, TrustedProxyCIDRs: []string{"not-a-cidr"},
	}}
	if err := badCIDR.validateSecurity(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid trusted proxy CIDR error = %v", err)
	}
	// trust=false ignores the list entirely.
	untrusted := Config{Security: &SecurityConfig{
		TrustProxyHeaders: false, TrustedProxyCIDRs: []string{"not-a-cidr"},
	}}
	if err := untrusted.validateSecurity(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("malformed list must still be rejected: %v", err)
	}
}
