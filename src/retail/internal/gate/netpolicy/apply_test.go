package netpolicy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeRunner records commands and simulates tool availability/privileges.
type fakeRunner struct {
	root     bool
	tools    map[string]bool
	runs     []string
	failOn   map[string]error
	lookPath map[string]string
	failWhen func(line string) error
	runCount int
}

func newFakeRunner(root bool, tools ...string) *fakeRunner {
	runner := &fakeRunner{root: root, tools: map[string]bool{}, runs: nil, failOn: map[string]error{}, lookPath: map[string]string{}}
	for _, tool := range tools {
		runner.tools[tool] = true
		runner.lookPath[tool] = "/usr/bin/" + tool
	}
	return runner
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	if f.tools[name] {
		return f.lookPath[name], nil
	}
	return "", os.ErrNotExist
}

func (f *fakeRunner) Run(name string, args ...string) error {
	line := name + " " + strings.Join(args, " ")
	f.runs = append(f.runs, line)
	f.runCount++
	if f.failWhen != nil {
		if err := f.failWhen(line); err != nil {
			return err
		}
	}
	if err, ok := f.failOn[name]; ok {
		return err
	}
	return nil
}

func (f *fakeRunner) Root() bool { return f.root }

// hasRun reports whether one executed command starts with prefix.
func (f *fakeRunner) hasRun(prefix string) bool {
	for _, line := range f.runs {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func TestCheckReportsNotTestedWithoutTools(t *testing.T) {
	plan := fixturePlan(t)
	report, err := Check(plan, FormatNFTables, newFakeRunner(false))
	if !errors.Is(err, ErrNotTested) {
		t.Fatalf("check without nft error = %v, want ErrNotTested", err)
	}
	if report.Status != "not_tested" || !strings.Contains(report.SyntaxCheck, "NOT_TESTED") {
		t.Fatalf("report = %+v", report)
	}
	report, err = Check(plan, FormatIPTables, newFakeRunner(false))
	if !errors.Is(err, ErrNotTested) {
		t.Fatalf("iptables check without tools error = %v, want ErrNotTested", err)
	}
	if report.Status != "not_tested" {
		t.Fatalf("iptables report = %+v", report)
	}
	// sh present but iptables missing must also be fail-closed.
	report, err = Check(plan, FormatIPTables, newFakeRunner(false, "sh"))
	if !errors.Is(err, ErrNotTested) || report.Status != "not_tested" {
		t.Fatalf("check without iptables error=%v report=%+v", err, report)
	}
}

func TestCheckRunsToolSyntaxCheck(t *testing.T) {
	plan := fixturePlan(t)
	runner := newFakeRunner(false, "nft")
	report, err := Check(plan, FormatNFTables, runner)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !strings.Contains(report.SyntaxCheck, "ok") || !runner.hasRun("nft -c -f ") {
		t.Fatalf("report=%+v runs=%v", report, runner.runs)
	}
	shellRunner := newFakeRunner(false, "sh", "iptables")
	report, err = Check(plan, FormatIPTables, shellRunner)
	if err != nil || !shellRunner.hasRun("sh -n ") {
		t.Fatalf("shell report=%+v runs=%v err=%v", report, shellRunner.runs, err)
	}
	// A failing syntax check is an apply error, never "ok".
	failing := newFakeRunner(false, "nft")
	failing.failOn["nft"] = errors.New("syntax error")
	if _, err := Check(plan, FormatNFTables, failing); !errors.Is(err, ErrApply) {
		t.Fatalf("failing syntax check error = %v", err)
	}
}

func TestApplyRequiresRoot(t *testing.T) {
	plan := fixturePlan(t)
	target := filepath.Join(t.TempDir(), "gedefense-gate.nft")
	if _, err := Apply(ApplyOptions{Plan: plan, Format: FormatNFTables, OutPath: target, Runner: newFakeRunner(false, "nft")}); !errors.Is(err, ErrPermission) {
		t.Fatalf("unprivileged apply error = %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("unprivileged apply wrote the ruleset")
	}
}

func TestApplyNFTablesChecksThenInstalls(t *testing.T) {
	plan := fixturePlan(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "gedefense-gate.nft")
	runner := newFakeRunner(true, "nft")
	artifactExistedAtLoad := false
	runner.failWhen = func(line string) error {
		if strings.HasPrefix(line, "nft -f ") {
			if _, statErr := os.Stat(target); statErr == nil {
				artifactExistedAtLoad = true
			}
		}
		return nil
	}
	installed, err := Apply(ApplyOptions{Plan: plan, Format: FormatNFTables, OutPath: target, Runner: runner})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if installed != target {
		t.Fatalf("installed path = %q, want %q", installed, target)
	}
	if !runner.hasRun("nft -c -f ") {
		t.Fatalf("syntax check missing: %v", runner.runs)
	}
	if !runner.hasRun("nft -f ") {
		t.Fatalf("load command missing: %v", runner.runs)
	}
	if artifactExistedAtLoad {
		t.Fatalf("artifact was installed before a successful load: %v", runner.runs)
	}
	raw, err := os.ReadFile(target)
	if err != nil || !strings.Contains(string(raw), "table inet gedefense_gate") {
		t.Fatalf("installed ruleset invalid: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, serr := os.Stat(target)
		if serr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("nft ruleset mode = %v %v", info, serr)
		}
	}
}

func TestApplyIPTablesInstallsExecutableRuleset(t *testing.T) {
	plan := fixturePlan(t)
	target := filepath.Join(t.TempDir(), "gedefense-gate.iptables")
	runner := newFakeRunner(true, "sh", "iptables", "ip6tables")
	installed, err := Apply(ApplyOptions{Plan: plan, Format: FormatIPTables, OutPath: target, Runner: runner})
	if err != nil {
		t.Fatalf("apply iptables: %v", err)
	}
	if installed != target || !runner.hasRun("sh -n ") || len(runner.runs) < 2 {
		t.Fatalf("installed=%q runs=%v", installed, runner.runs)
	}
	if strings.HasSuffix(runner.runs[1], target) {
		t.Fatalf("iptables ruleset was loaded from the installed path instead of the temp file: %v", runner.runs)
	}
	if _, statErr := os.Stat(target); statErr != nil {
		t.Fatalf("installed ruleset missing after successful load: %v", statErr)
	}
}

func TestApplyRefusesFailingSyntaxCheckBeforeRename(t *testing.T) {
	plan := fixturePlan(t)
	target := filepath.Join(t.TempDir(), "gedefense-gate.nft")
	runner := newFakeRunner(true, "nft")
	runner.failOn["nft"] = errors.New("bad rule")
	if _, err := Apply(ApplyOptions{Plan: plan, Format: FormatNFTables, OutPath: target, Runner: runner}); !errors.Is(err, ErrApply) {
		t.Fatalf("failing apply error = %v", err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatal("ruleset was installed despite a failing syntax check")
	}
}

func TestApplyLoadFailureLeavesNoArtifact(t *testing.T) {
	plan := fixturePlan(t)
	target := filepath.Join(t.TempDir(), "gedefense-gate.nft")
	runner := newFakeRunner(true, "nft")
	runner.failWhen = func(line string) error {
		if strings.HasPrefix(line, "nft -f ") {
			return errors.New("kernel rejected ruleset")
		}
		return nil
	}
	if _, err := Apply(ApplyOptions{Plan: plan, Format: FormatNFTables, OutPath: target, Runner: runner}); !errors.Is(err, ErrApply) {
		t.Fatalf("load failure error = %v", err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatal("artifact exists although the firewall load failed")
	}
}

func TestApplyIPTablesLoadFailureCleansUp(t *testing.T) {
	plan := fixturePlan(t)
	target := filepath.Join(t.TempDir(), "gedefense-gate.iptables")
	runner := newFakeRunner(true, "sh", "iptables")
	runner.failWhen = func(line string) error {
		if strings.HasPrefix(line, "sh ") && !strings.Contains(line, " -n ") {
			return errors.New("iptables rejected ruleset")
		}
		return nil
	}
	if _, err := Apply(ApplyOptions{Plan: plan, Format: FormatIPTables, OutPath: target, Runner: runner}); !errors.Is(err, ErrApply) {
		t.Fatalf("iptables load failure error = %v", err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatal("iptables artifact exists although the load failed")
	}
	// The best-effort cleanup executes the rollback ruleset (third sh invocation).
	if len(runner.runs) < 3 {
		t.Fatalf("no cleanup/rollback after failed load: %v", runner.runs)
	}
}

func TestApplyRequiresTool(t *testing.T) {
	plan := fixturePlan(t)
	target := filepath.Join(t.TempDir(), "gedefense-gate.nft")
	if _, err := Apply(ApplyOptions{Plan: plan, Format: FormatNFTables, OutPath: target, Runner: newFakeRunner(true)}); !errors.Is(err, ErrToolUnavailable) {
		t.Fatalf("missing nft error = %v", err)
	}
}

func TestRollbackSemantics(t *testing.T) {
	if err := Rollback(FormatNFTables, newFakeRunner(false, "nft")); !errors.Is(err, ErrPermission) {
		t.Fatalf("unprivileged rollback error = %v", err)
	}
	runner := newFakeRunner(true, "nft")
	if err := Rollback(FormatNFTables, runner); err != nil {
		t.Fatalf("nft rollback: %v", err)
	}
	if !runner.hasRun("nft delete table inet gedefense_gate") {
		t.Fatalf("rollback runs = %v", runner.runs)
	}
	shellRunner := newFakeRunner(true, "sh")
	if err := Rollback(FormatIPTables, shellRunner); err != nil {
		t.Fatalf("iptables rollback: %v", err)
	}
	if !shellRunner.hasRun("sh /") && !strings.Contains(strings.Join(shellRunner.runs, " "), "sh ") {
		t.Fatalf("iptables rollback did not execute the script: %v", shellRunner.runs)
	}
	if err := Rollback("pf", runner); !errors.Is(err, ErrConfig) {
		t.Fatalf("unknown rollback format error = %v", err)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "rules.nft")
	if err := WriteFileAtomic(target, []byte("rules\n"), 0o600); err != nil {
		t.Fatalf("write atomic: %v", err)
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "rules\n" {
		t.Fatalf("read atomic file: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, serr := os.Stat(target)
		if serr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v %v", info, serr)
		}
	}
	entries, derr := os.ReadDir(filepath.Dir(target))
	if derr != nil {
		t.Fatalf("read dir: %v", derr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".gedefense-netpolicy-") {
			t.Fatalf("temporary file was not cleaned up: %s", entry.Name())
		}
	}
	if err := WriteFileAtomic("", []byte("x"), 0o600); !errors.Is(err, ErrApply) {
		t.Fatalf("empty path error = %v", err)
	}
}
