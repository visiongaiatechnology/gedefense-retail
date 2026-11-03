package config

import (
	"errors"
	"strings"
	"testing"
)

// baseCentral builds a syntactically valid central config for validator tests.
func baseCentral() *CentralConfig {
	return &CentralConfig{
		URL: "https://central.example.test/ingest", TimeoutS: 10,
		BatchSize: 100, SpoolMaxMB: 64,
	}
}

// TestCentralMTLSRequired covers FIND-008: mTLS is mandatory by default.
func TestCentralMTLSRequired(t *testing.T) {
	cfg := Config{Central: baseCentral()}
	if !cfg.CentralRequiresMTLS() {
		t.Fatal("mTLS must default to required")
	}
	if err := cfg.validateCentral(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("https central without client cert must fail: %v", err)
	}
	if !strings.Contains(errString(cfg.validateCentral()), "client_cert_file") {
		t.Fatalf("error should name the missing client certificate: %s", errString(cfg.validateCentral()))
	}

	withCerts := Config{Central: baseCentral()}
	withCerts.Central.ClientCertFile = "/etc/gedefense-retail/client.crt"
	withCerts.Central.ClientKeyFile = "/etc/gedefense-retail/client.key"
	if err := withCerts.validateCentral(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("mTLS without ca_file must fail: %v", err)
	}
	withCerts.Central.CAFile = "/etc/gedefense-retail/ca.crt"
	if err := withCerts.validateCentral(); err != nil {
		t.Fatalf("complete mTLS config rejected: %v", err)
	}

	// Explicit opt-out is allowed (audited exception, e.g. test endpoint).
	optOut := baseCentral()
	disabled := false
	optOut.RequireMTLS = &disabled
	if err := (Config{Central: optOut}).validateCentral(); err != nil {
		t.Fatalf("explicit require_mtls=false rejected: %v", err)
	}
	// Loopback http test endpoints do not need mTLS.
	loopback := &CentralConfig{URL: "http://127.0.0.1:9443/ingest", TimeoutS: 10, BatchSize: 100, SpoolMaxMB: 64}
	if err := (Config{Central: loopback}).validateCentral(); err != nil {
		t.Fatalf("loopback http endpoint rejected: %v", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
