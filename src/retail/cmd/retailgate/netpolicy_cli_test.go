package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/netpolicy"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns printed text.
func captureStdout(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	original := os.Stdout
	os.Stdout = writer
	code := fn()
	os.Stdout = original
	if err := writer.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	buffer := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for {
		n, rerr := reader.Read(chunk)
		if n > 0 {
			buffer = append(buffer, chunk[:n]...)
			if len(buffer) > 1<<20 {
				t.Fatal("command output too large")
			}
		}
		if rerr != nil {
			break
		}
	}
	_ = reader.Close()
	return code, string(buffer)
}

// writeGateConfig writes a minimal gate.json with only targets[].
func writeGateConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gate.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const cliGateConfig = `{
  "targets": [
    {"target_id": "regler-1", "protocol": "modbus_tcp", "upstream": "10.0.0.5:502"},
    {"target_id": "hmi-1", "protocol": "https", "upstream": "https://10.0.0.6:8443/"}
  ]
}`

func TestNetPolicyCLIValidationExitCodes(t *testing.T) {
	if code, _ := captureStdout(t, func() int { return run([]string{"netpolicy", "--format", "pf"}) }); code != 2 {
		t.Fatalf("bad format exit = %d, want 2", code)
	}
	if code, _ := captureStdout(t, func() int { return run([]string{"netpolicy", "--gate-source", "10.0.0.0/8"}) }); code != 2 {
		t.Fatalf("missing config exit = %d, want 2", code)
	}
	hostNameConfig := writeGateConfig(t, `{"targets":[{"target_id":"x","protocol":"modbus_tcp","upstream":"plc.local:502"}]}`)
	if code, _ := captureStdout(t, func() int {
		return run([]string{"netpolicy", "--config", hostNameConfig, "--format", "nftables", "--gate-source", "10.0.0.0/8"})
	}); code != 2 {
		t.Fatalf("hostname upstream exit = %d, want 2", code)
	}
	validConfig := writeGateConfig(t, cliGateConfig)
	if code, _ := captureStdout(t, func() int {
		return run([]string{"netpolicy", "--config", validConfig, "--format", "nftables"})
	}); code != 2 {
		t.Fatalf("missing gate-source exit = %d, want 2", code)
	}
	// F-A3-05: a family mismatch (IPv4/IPv6 targets vs. sources) is a config error.
	if code, _ := captureStdout(t, func() int {
		return run([]string{"netpolicy", "--config", validConfig, "--format", "nftables", "--gate-source", "2001:db8:100::/64"})
	}); code != 2 {
		t.Fatalf("family mismatch exit = %d, want 2", code)
	}
}

func TestNetPolicyCLIRendersToStdout(t *testing.T) {
	configPath := writeGateConfig(t, cliGateConfig)
	code, output := captureStdout(t, func() int {
		return run([]string{"netpolicy", "--config", configPath, "--format", "nftables",
			"--gate-source", "10.20.30.40/32", "--gate-source", "10.20.30.41/32"})
	})
	if code != 0 {
		t.Fatalf("render exit = %d", code)
	}
	for _, want := range []string{"table inet gedefense_gate", "10.0.0.5 . 502", "10.20.30.41/32"} {
		if !strings.Contains(output, want) {
			t.Errorf("stdout misses %q", want)
		}
	}
	code, output = captureStdout(t, func() int {
		return run([]string{"netpolicy", "--config", configPath, "--format", "iptables", "--gate-source", "10.20.30.40/32"})
	})
	if code != 0 || !strings.Contains(output, "GEDEFENSE_GATE") {
		t.Fatalf("iptables render exit=%d output=%s", code, output)
	}
}

func TestNetPolicyCLIWritesOutputFile(t *testing.T) {
	configPath := writeGateConfig(t, cliGateConfig)
	target := filepath.Join(t.TempDir(), "rules.nft")
	code, output := captureStdout(t, func() int {
		return run([]string{"netpolicy", "--config", configPath, "--format", "nftables",
			"--gate-source", "10.20.30.40/32", "--out", target})
	})
	if code != 0 {
		t.Fatalf("write exit = %d (%s)", code, output)
	}
	var response struct {
		Written string `json:"written"`
	}
	if err := json.Unmarshal([]byte(output), &response); err != nil || response.Written != target {
		t.Fatalf("output = %s err=%v", output, err)
	}
	raw, err := os.ReadFile(target)
	if err != nil || !strings.Contains(string(raw), "table inet gedefense_gate") {
		t.Fatalf("written ruleset: %v", err)
	}
}

func TestNetPolicyCLICheck(t *testing.T) {
	configPath := writeGateConfig(t, cliGateConfig)
	code, output := captureStdout(t, func() int {
		return run([]string{"netpolicy", "--config", configPath, "--format", "nftables",
			"--gate-source", "10.20.30.40/32", "--check"})
	})
	var report netpolicy.CheckReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("check report: %v (%s)", err, output)
	}
	if report.Format != "nftables" || report.SyntaxCheck == "" {
		t.Fatalf("report = %+v", report)
	}
	if report.Status == "" {
		t.Fatalf("empty check status (CI regression): code=%d report=%+v", code, report)
	}
	switch report.Status {
	case "ok":
		if code != 0 {
			t.Fatalf("status ok but exit = %d", code)
		}
	case "not_tested":
		if code == 0 {
			t.Fatalf("status not_tested but exit = 0 (must fail closed)")
		}
		if !strings.Contains(report.SyntaxCheck, "NOT_TESTED") {
			t.Fatalf("not_tested without NOT_TESTED explanation: %q", report.SyntaxCheck)
		}
		if !strings.Contains(report.SyntaxCheck, "nft") && !strings.Contains(report.SyntaxCheck, "sh") {
			t.Fatalf("NOT_TESTED without a reason: %q", report.SyntaxCheck)
		}
	default:
		t.Fatalf("unexpected check status %q", report.Status)
	}
}

func TestNetPolicyCLIPrintTopology(t *testing.T) {
	code, output := captureStdout(t, func() int {
		return run([]string{"netpolicy", "--print-topology"})
	})
	if code != 0 {
		t.Fatalf("topology exit = %d", code)
	}
	for _, want := range []string{"NOT a router/NAT implementation", "IP forwarding", "Honest limits"} {
		if !strings.Contains(output, want) {
			t.Errorf("topology misses %q", want)
		}
	}
}

func TestNetPolicyCLIRollbackRequiresRoot(t *testing.T) {
	if (netpolicy.ExecRunner{}).Root() {
		t.Skip("test runs as root: rollback would modify the host firewall")
	}
	if code, _ := captureStdout(t, func() int { return run([]string{"netpolicy", "--rollback", "--format", "nftables"}) }); code != 3 {
		t.Fatalf("unprivileged rollback exit = %d, want 3", code)
	}
}
