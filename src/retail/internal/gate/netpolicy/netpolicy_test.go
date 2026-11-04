package netpolicy

import (
	"errors"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
)

var updateGolden = flag.Bool("update", false, "update golden files")

// fixtureTargets covers IPv4 Modbus, IPv6 HTTPS and a duplicate endpoint.
func fixtureTargets() []config.Target {
	return []config.Target{
		{TargetID: domain.TargetID("regler-1"), Protocol: "modbus_tcp", Upstream: "10.0.0.5:502"},
		{TargetID: domain.TargetID("regler-2"), Protocol: "modbus_tcp", Upstream: "10.0.0.6:502"},
		{TargetID: domain.TargetID("hmi-1"), Protocol: "https", Upstream: "https://[2001:db8::10]:8443/"},
		{TargetID: domain.TargetID("regler-1-dup"), Protocol: "modbus_tcp", Upstream: "10.0.0.5:502"},
	}
}

func fixtureSources() []string {
	return []string{"10.20.30.40/32", "2001:db8:100::/64", "10.20.30.40/32"}
}

func fixturePlan(t *testing.T) Plan {
	t.Helper()
	plan, err := Build(fixtureTargets(), fixtureSources())
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	return plan
}

func TestBuildValidatesFailClosed(t *testing.T) {
	cases := []struct {
		name    string
		targets []config.Target
		sources []string
		wantErr bool
	}{
		{name: "no targets", targets: nil, sources: []string{"10.0.0.0/8"}, wantErr: true},
		{name: "no gate source", targets: fixtureTargets(), sources: nil, wantErr: true},
		{name: "hostname modbus", targets: []config.Target{{TargetID: "x", Protocol: "modbus_tcp", Upstream: "plc.local:502"}}, sources: []string{"10.0.0.0/8"}, wantErr: true},
		{name: "hostname http", targets: []config.Target{{TargetID: "x", Protocol: "http", Upstream: "http://plc.local/"}}, sources: []string{"10.0.0.0/8"}, wantErr: true},
		{name: "modbus without port", targets: []config.Target{{TargetID: "x", Protocol: "modbus_tcp", Upstream: "10.0.0.5"}}, sources: []string{"10.0.0.0/8"}, wantErr: true},
		{name: "port out of range", targets: []config.Target{{TargetID: "x", Protocol: "modbus_tcp", Upstream: "10.0.0.5:70000"}}, sources: []string{"10.0.0.0/8"}, wantErr: true},
		{name: "unsupported protocol", targets: []config.Target{{TargetID: "x", Protocol: "bacnet", Upstream: "10.0.0.5:47808"}}, sources: []string{"10.0.0.0/8"}, wantErr: true},
		{name: "bad gate source", targets: fixtureTargets(), sources: []string{"not-a-cidr"}, wantErr: true},
		{name: "IPv4 target with only IPv6 source", targets: []config.Target{{TargetID: "x", Protocol: "modbus_tcp", Upstream: "10.0.0.5:502"}}, sources: []string{"2001:db8::/64"}, wantErr: true},
		{name: "IPv6 target with only IPv4 source", targets: []config.Target{{TargetID: "x", Protocol: "https", Upstream: "https://[2001:db8::10]:8443/"}}, sources: []string{"10.20.30.0/24"}, wantErr: true},
		{name: "mixed targets with only IPv4 source", targets: fixtureTargets(), sources: []string{"10.20.30.0/24"}, wantErr: true},
		{name: "mixed targets with only IPv6 source", targets: fixtureTargets(), sources: []string{"2001:db8:100::/64"}, wantErr: true},
		{name: "both families with matching sources", targets: fixtureTargets(), sources: fixtureSources(), wantErr: false},
		{name: "valid", targets: fixtureTargets(), sources: fixtureSources(), wantErr: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Build(testCase.targets, testCase.sources)
			if testCase.wantErr && !errors.Is(err, ErrConfig) {
				t.Fatalf("expected ErrConfig, got %v", err)
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBuildNormalizesEndpointsAndSources(t *testing.T) {
	plan := fixturePlan(t)
	if len(plan.Endpoints) != 3 {
		t.Fatalf("deduplicated endpoints = %d, want 3", len(plan.Endpoints))
	}
	if len(plan.SourcesV4) != 1 || len(plan.SourcesV6) != 1 {
		t.Fatalf("sources v4=%v v6=%v", plan.SourcesV4, plan.SourcesV6)
	}
	if plan.Endpoints[0].IP.String() != "10.0.0.5" || plan.Endpoints[0].Port != 502 {
		t.Fatalf("first endpoint = %+v", plan.Endpoints[0])
	}
	last := plan.Endpoints[len(plan.Endpoints)-1]
	if !last.IP.Is6() || last.Port != 8443 || last.Protocol != "https" {
		t.Fatalf("IPv6 endpoint = %+v", last)
	}
}

func TestGoldenNFTables(t *testing.T) {
	plan := fixturePlan(t)
	got, err := Render(plan, FormatNFTables)
	if err != nil {
		t.Fatalf("render nftables: %v", err)
	}
	checkGolden(t, "gedefense-gate.nft.golden", got)
	for _, want := range []string{
		"table inet gedefense_gate {",
		"chain forward {",
		"type filter hook forward priority -5; policy accept;",
		"ct state established,related accept",
		"set gate_sources_v4 {",
		"set gate_sources_v6 {",
		"set protected_v4 {",
		"set protected_v6 {",
		"ip daddr . tcp dport @protected_v4 log prefix \"gedefense-gate-drop \" flags all counter drop",
		"ip6 daddr . tcp dport @protected_v6 log prefix \"gedefense-gate-drop \" flags all counter drop",
		"10.0.0.5 . 502",
		"2001:db8::10 . 8443",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("nftables output misses %q", want)
		}
	}
	if strings.Contains(got, "policy drop") && !strings.Contains(got, "policy accept") {
		t.Error("generated table must not change default policies")
	}
}

func TestGoldenIPTables(t *testing.T) {
	plan := fixturePlan(t)
	got, err := Render(plan, FormatIPTables)
	if err != nil {
		t.Fatalf("render iptables: %v", err)
	}
	checkGolden(t, "gedefense-gate.iptables.golden", got)
	for _, want := range []string{
		"#!/bin/sh",
		"GEDEFENSE_GATE",
		"iptables -w -N GEDEFENSE_GATE 2>/dev/null || true",
		"while iptables -w -C FORWARD -j GEDEFENSE_GATE 2>/dev/null; do iptables -w -D FORWARD -j GEDEFENSE_GATE; done",
		"iptables -w -I FORWARD 1 -j GEDEFENSE_GATE",
		"iptables -w -F GEDEFENSE_GATE",
		"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-s 10.20.30.40/32 -p tcp -d 10.0.0.5 --dport 502",
		"--log-prefix \"gedefense-gate-drop \"",
		"ip6tables -w -A GEDEFENSE_GATE",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("iptables output misses %q", want)
		}
	}
}

func TestRollbackRenders(t *testing.T) {
	nft, err := RollbackScript(FormatNFTables)
	if err != nil || !strings.Contains(nft, "nft delete table inet gedefense_gate") {
		t.Fatalf("nft rollback = %q err=%v", nft, err)
	}
	ipt, err := RollbackScript(FormatIPTables)
	if err != nil {
		t.Fatalf("iptables rollback: %v", err)
	}
	for _, want := range []string{"while iptables -w -C FORWARD -j GEDEFENSE_GATE", "iptables -w -F GEDEFENSE_GATE", "iptables -w -X GEDEFENSE_GATE", "ip6tables -w -F GEDEFENSE_GATE"} {
		if !strings.Contains(ipt, want) {
			t.Errorf("iptables rollback misses %q", want)
		}
	}
	if _, err := RollbackScript("pf"); !errors.Is(err, ErrConfig) {
		t.Fatalf("unknown format rollback error = %v", err)
	}
}

func TestDefaultPathsAndTopology(t *testing.T) {
	if DefaultPath(FormatNFTables) != "/etc/nftables.d/gedefense-gate.nft" {
		t.Fatalf("nft default path = %q", DefaultPath(FormatNFTables))
	}
	if DefaultPath(FormatIPTables) != "/etc/gedefense-gate.iptables" {
		t.Fatalf("iptables default path = %q", DefaultPath(FormatIPTables))
	}
	plan := fixturePlan(t)
	notes := TopologyNotes(&plan)
	for _, want := range []string{
		"traffic that actually traverses this host",
		"NOT a router/NAT implementation",
		"IP forwarding",
		"Protected controller endpoints:",
		"10.0.0.5:502",
		"Allowed gate sources:",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("topology notes miss %q", want)
		}
	}
	if !strings.Contains(TopologyNotes(nil), "netpolicy --config") {
		t.Error("guidance without plan misses the example invocation")
	}
}

// checkGolden compares got with testdata/name, writing it with -update.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("create testdata: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run go test -update): %v", name, err)
	}
	if string(want) != got {
		t.Fatalf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

// TestRenderRejectsFamilyWithoutSource proves the renderer itself never emits a
// family without a matching gate source (defense in depth for F-A3-05).
func TestRenderRejectsFamilyWithoutSource(t *testing.T) {
	v6Prefix := netip.MustParsePrefix("2001:db8:100::/64")
	plan := Plan{
		Endpoints: []Endpoint{{TargetID: "v4-only", IP: netip.MustParseAddr("10.0.0.5"), Port: 502, Protocol: "modbus_tcp"}},
		SourcesV6: []netip.Prefix{v6Prefix},
	}
	if _, err := Render(plan, FormatNFTables); !errors.Is(err, ErrConfig) {
		t.Fatalf("renderer accepted IPv4 endpoints without IPv4 source: %v", err)
	}
	if _, err := Render(plan, FormatIPTables); !errors.Is(err, ErrConfig) {
		t.Fatalf("iptables renderer accepted IPv4 endpoints without IPv4 source: %v", err)
	}
	v4Prefix := netip.MustParsePrefix("10.20.30.0/24")
	v6Plan := Plan{
		Endpoints: []Endpoint{{TargetID: "v6-only", IP: netip.MustParseAddr("2001:db8::10"), Port: 443, Protocol: "https"}},
		SourcesV4: []netip.Prefix{v4Prefix},
	}
	if _, err := Render(v6Plan, FormatNFTables); !errors.Is(err, ErrConfig) {
		t.Fatalf("renderer accepted IPv6 endpoints without IPv6 source: %v", err)
	}
}
