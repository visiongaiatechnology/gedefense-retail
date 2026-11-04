package config

import (
	"errors"
	"testing"
)

func integrityEnabledConfig(t *testing.T) Config {
	t.Helper()
	cfg := baseConfig(t)
	required := true
	cfg.Integrity = &IntegrityConfig{
		Enabled:       true,
		PollIntervalS: 60,
		ConfirmReads:  2,
		StaleAfterS:   180,
		References: []IntegrityReference{{
			TargetID: "t1", FC: 3, Register: 40002, UnitID: 1, Value: "4.0", Scale: 0.1, Unit: "celsius", Recovery: true,
		}},
		Recovery: RecoveryConfig{
			Enabled: true, MaxActionsPerHour: 3, MaxActionsPerDay: 10, CooldownS: 600,
			RequireNoActiveWindow: &required,
		},
	}
	return cfg
}

func TestIntegrityConfigValid(t *testing.T) {
	cfg := integrityEnabledConfig(t).WithDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid integrity config rejected: %v", err)
	}
	eff := cfg.EffectiveIntegrity()
	if eff.PollIntervalS != 60 || eff.ConfirmReads != 2 || eff.References[0].Scale != 0.1 {
		t.Fatalf("effective config = %+v", eff)
	}
}

func TestIntegrityConfigInvalid(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no references", func(c *Config) { c.Integrity.References = nil }},
		{"bad interval", func(c *Config) { c.Integrity.PollIntervalS = 1 }},
		{"bad confirm", func(c *Config) { c.Integrity.ConfirmReads = 9 }},
		{"stale not larger", func(c *Config) { c.Integrity.StaleAfterS = 30 }},
		{"unknown target", func(c *Config) { c.Integrity.References[0].TargetID = "missing" }},
		{"http target", func(c *Config) {
			c.Integrity.References[0].TargetID = "web"
		}},
		{"fc not 3", func(c *Config) { c.Integrity.References[0].FC = 4 }},
		{"register out of range", func(c *Config) { c.Integrity.References[0].Register = 40000 }},
		{"register outside read window", func(c *Config) { c.Integrity.References[0].Register = 40100 }},
		{"non numeric value", func(c *Config) { c.Integrity.References[0].Value = "warm" }},
		{"value overflow", func(c *Config) { c.Integrity.References[0].Value = "70000" }},
		{"bad cooldown", func(c *Config) { c.Integrity.Recovery.CooldownS = 10 }},
		{"hour exceeds day", func(c *Config) { c.Integrity.Recovery.MaxActionsPerHour = 20 }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := integrityEnabledConfig(t)
			if tc.name == "http target" {
				cfg.Targets = append(cfg.Targets, Target{
					TargetID: "web", AssetID: "a2", Protocol: "http", Listen: "127.0.0.1:18080",
					Upstream: "http://127.0.0.1:18081", URLAllowlist: []string{"/"},
				})
			}
			tc.mutate(&cfg)
			cfg = cfg.WithDefaults()
			err := cfg.Validate()
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected ErrInvalidConfig, got %v", err)
			}
		})
	}
}

func TestIntegrityRecoveryDefaultDisabled(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Integrity = &IntegrityConfig{Enabled: true, References: []IntegrityReference{{
		TargetID: "t1", FC: 3, Register: 40002, Value: "40",
	}}}
	eff := cfg.WithDefaults().EffectiveIntegrity()
	if eff.Recovery.Enabled {
		t.Fatal("recovery must default to disabled")
	}
	if err := cfg.WithDefaults().Validate(); err != nil {
		t.Fatalf("integrity without recovery rejected: %v", err)
	}
}

func TestIntegrityRecoveryRequiresNoActiveWindow(t *testing.T) {
	cfg := integrityEnabledConfig(t)
	disabled := false
	cfg.Integrity.Recovery.RequireNoActiveWindow = &disabled
	err := cfg.WithDefaults().Validate()
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("require_no_active_window=false must be rejected, got %v", err)
	}
}
