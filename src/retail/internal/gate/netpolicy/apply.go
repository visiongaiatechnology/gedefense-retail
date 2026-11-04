package netpolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CheckReport is the machine-readable result of --check.
type CheckReport struct {
	Format      string   `json:"format"`
	Endpoints   int      `json:"endpoints"`
	GateSources []string `json:"gate_sources"`
	SyntaxCheck string   `json:"syntax_check"`
	Status      string   `json:"status"`
	CheckedAt   string   `json:"checked_at"`
}

// Check validates the rendered ruleset without touching the host. The firewall
// syntax check is performed with nft -c -f (nftables) or sh -n (iptables shell
// ruleset) when the corresponding tool is available; otherwise the report clearly
// states NOT_TESTED instead of pretending the syntax was verified.
func Check(plan Plan, format Format, runner Runner) (CheckReport, error) {
	rules, err := Render(plan, format)
	if err != nil {
		return CheckReport{}, err
	}
	report := CheckReport{
		Format: string(format), Endpoints: len(plan.Endpoints), GateSources: plan.sourceSummary(),
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
	checkFile, err := os.CreateTemp("", "gedefense-netpolicy-check-*")
	if err != nil {
		return CheckReport{}, fmt.Errorf("%w: temporary check file: %v", ErrConfig, err)
	}
	name := checkFile.Name()
	defer func() { _ = os.Remove(name) }()
	if _, werr := checkFile.WriteString(rules); werr != nil {
		_ = checkFile.Close()
		return CheckReport{}, fmt.Errorf("%w: write check file: %v", ErrConfig, werr)
	}
	if cerr := checkFile.Close(); cerr != nil {
		return CheckReport{}, fmt.Errorf("%w: close check file: %v", ErrConfig, cerr)
	}
	switch format {
	case FormatNFTables:
		if _, lerr := runner.LookPath("nft"); lerr != nil {
			report.SyntaxCheck = "NOT_TESTED (nft not installed; syntax not verified)"
			report.Status = "not_tested"
			return report, fmt.Errorf("%w: nft not installed", ErrNotTested)
		}
		if rerr := runner.Run("nft", "-c", "-f", name); rerr != nil {
			return classifyCheckFailure(report, "nft -c", rerr)
		}
		report.SyntaxCheck = "ok (nft -c -f)"
	case FormatIPTables:
		if _, lerr := runner.LookPath("sh"); lerr != nil {
			report.SyntaxCheck = "NOT_TESTED (sh not installed; syntax not verified)"
			report.Status = "not_tested"
			return report, fmt.Errorf("%w: sh not installed", ErrNotTested)
		}
		if rerr := runner.Run("sh", "-n", name); rerr != nil {
			return classifyCheckFailure(report, "sh -n", rerr)
		}
		report.SyntaxCheck = "ok (sh -n)"
		if _, lerr := runner.LookPath("iptables"); lerr != nil {
			report.SyntaxCheck = "ok (sh -n); iptables NOT_TESTED (binary not installed)"
			report.Status = "not_tested"
			return report, fmt.Errorf("%w: iptables not installed", ErrNotTested)
		}
	default:
		return CheckReport{}, fmt.Errorf("%w: unknown format %q", ErrConfig, format)
	}
	report.Status = "ok"
	return report, nil
}

// classifyCheckFailure turns a failed tool syntax check into a non-empty report
// and the right error class. A missing privilege (e.g. nft -c without
// CAP_NET_ADMIN/root on Linux: "netlink: cache initialization failed: Operation
// not permitted") is NOT a syntax error and must be reported as not_tested, never
// as a broken ruleset. Genuine syntax errors are reported as error.
func classifyCheckFailure(report CheckReport, tool string, cause error) (CheckReport, error) {
	report.SyntaxCheck = ""
	reason := sanitizeCheckReason(cause)
	if isPrivilegeFailure(cause) {
		report.Status = "not_tested"
		report.SyntaxCheck = "NOT_TESTED (" + tool + " requires CAP_NET_ADMIN/root: " + reason + ")"
		return report, fmt.Errorf("%w: %s: %s", ErrNotTested, tool, reason)
	}
	report.Status = "error"
	report.SyntaxCheck = "error (" + tool + "): " + reason
	return report, fmt.Errorf("%w: %s syntax check: %v", ErrApply, tool, cause)
}

// isPrivilegeFailure detects missing CAP_NET_ADMIN/root or a sandboxed netlink
// socket in the tool output. Fail-closed: only explicit markers classify as
// not_tested, everything else stays a genuine error.
func isPrivilegeFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	text := strings.ToLower(err.Error())
	for _, marker := range []string{
		"operation not permitted",
		"cache initialization failed",
		"permission denied",
		"eperm",
		"cap_net_admin",
		"requires root",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// sanitizeCheckReason keeps the report single-line and bounded (no log injection,
// no multi-kilobyte kernel dumps in JSON).
func sanitizeCheckReason(err error) string {
	text := strings.Join(strings.Fields(err.Error()), " ")
	text = strings.ReplaceAll(text, "\n", " ")
	if len(text) > 240 {
		text = text[:240] + "..."
	}
	return text
}

// ApplyOptions controls Apply.
type ApplyOptions struct {
	Plan    Plan
	Format  Format
	OutPath string
	Runner  Runner
}

// Apply validates privileges, checks the syntax, installs the ruleset atomically
// and loads it into the running firewall. It returns the installed path.
func Apply(opts ApplyOptions) (string, error) {
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	if !opts.Runner.Root() {
		return "", ErrPermission
	}
	rules, err := Render(opts.Plan, opts.Format)
	if err != nil {
		return "", err
	}
	target := strings.TrimSpace(opts.OutPath)
	if target == "" {
		target = DefaultPath(opts.Format)
	}
	// Temporary ruleset in the target directory to keep rename atomic, with the
	// final mode already set.
	temp, err := os.CreateTemp(filepath.Dir(target), ".gedefense-netpolicy-apply-*")
	if err != nil {
		return "", fmt.Errorf("%w: create temporary ruleset: %v", ErrApply, err)
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	mode := os.FileMode(0o600)
	if opts.Format == FormatIPTables {
		mode = 0o700
	}
	if cerr := temp.Chmod(mode); cerr != nil {
		_ = temp.Close()
		return "", fmt.Errorf("%w: chmod temporary ruleset: %v", ErrApply, cerr)
	}
	if _, werr := temp.WriteString(rules); werr != nil {
		_ = temp.Close()
		return "", fmt.Errorf("%w: write temporary ruleset: %v", ErrApply, werr)
	}
	if serr := temp.Sync(); serr != nil {
		_ = temp.Close()
		return "", fmt.Errorf("%w: sync temporary ruleset: %v", ErrApply, serr)
	}
	if cerr := temp.Close(); cerr != nil {
		return "", fmt.Errorf("%w: close temporary ruleset: %v", ErrApply, cerr)
	}
	// Syntax check BEFORE loading anything.
	if err := checkSyntax(opts.Runner, opts.Format, tempName); err != nil {
		return "", err
	}
	// F-A3-06: load the ruleset into the running firewall FIRST. Only a successful
	// load allows the artifact to be installed; a load failure leaves no file.
	switch opts.Format {
	case FormatNFTables:
		if _, lerr := opts.Runner.LookPath("nft"); lerr != nil {
			return "", fmt.Errorf("%w: nft not installed: %v", ErrToolUnavailable, lerr)
		}
		if rerr := opts.Runner.Run("nft", "-f", tempName); rerr != nil {
			return "", fmt.Errorf("%w: load nftables ruleset (no artifact installed): %v", ErrApply, rerr)
		}
	case FormatIPTables:
		if rerr := opts.Runner.Run("sh", tempName); rerr != nil {
			// Best effort: remove a partially inserted own chain/jump.
			_ = cleanupIPTables(opts.Runner)
			return "", fmt.Errorf("%w: execute iptables ruleset (no artifact installed): %v", ErrApply, rerr)
		}
	default:
		return "", fmt.Errorf("%w: unknown format %q", ErrConfig, opts.Format)
	}
	if err := os.Rename(tempName, target); err != nil {
		return "", fmt.Errorf("%w: install ruleset %s after successful load: %v", ErrApply, target, err)
	}
	return target, nil
}

// cleanupIPTables runs the rollback ruleset as a best effort after a failed
// iptables load so that a partial chain/jump does not stay active.
func cleanupIPTables(runner Runner) error {
	script, err := RollbackScript(FormatIPTables)
	if err != nil {
		return err
	}
	path, werr := writeTempScript(script)
	if werr != nil {
		return werr
	}
	defer func() { _ = os.Remove(path) }()
	return runner.Run("sh", path)
}

// checkSyntax runs the backend-specific syntax check on the temporary ruleset.
func checkSyntax(runner Runner, format Format, path string) error {
	switch format {
	case FormatNFTables:
		if _, err := runner.LookPath("nft"); err != nil {
			return fmt.Errorf("%w: nft not installed: %v", ErrToolUnavailable, err)
		}
		if err := runner.Run("nft", "-c", "-f", path); err != nil {
			return fmt.Errorf("%w: nft syntax check: %v", ErrApply, err)
		}
		return nil
	case FormatIPTables:
		if _, err := runner.LookPath("sh"); err != nil {
			return fmt.Errorf("%w: sh not installed: %v", ErrToolUnavailable, err)
		}
		if err := runner.Run("sh", "-n", path); err != nil {
			return fmt.Errorf("%w: shell syntax check: %v", ErrApply, err)
		}
		if _, err := runner.LookPath("iptables"); err != nil {
			return fmt.Errorf("%w: iptables not installed: %v", ErrToolUnavailable, err)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown format %q", ErrConfig, format)
	}
}

// Rollback removes the dedicated table/chain and the installed ruleset file.
// It is idempotent: a missing table/chain/file is not an error.
func Rollback(format Format, runner Runner) error {
	if runner == nil {
		runner = ExecRunner{}
	}
	if !runner.Root() {
		return ErrPermission
	}
	switch format {
	case FormatNFTables:
		if _, err := runner.LookPath("nft"); err != nil {
			return fmt.Errorf("%w: nft not installed: %v", ErrToolUnavailable, err)
		}
		// Best effort: the table may not exist on a fresh host.
		_ = runner.Run("nft", "delete", "table", "inet", NFTTable)
		_ = os.Remove(NFTDefaultPath)
		return nil
	case FormatIPTables:
		script, err := RollbackScript(FormatIPTables)
		if err != nil {
			return err
		}
		path, werr := writeTempScript(script)
		if werr != nil {
			return werr
		}
		defer func() { _ = os.Remove(path) }()
		if _, lerr := runner.LookPath("sh"); lerr != nil {
			return fmt.Errorf("%w: sh not installed: %v", ErrToolUnavailable, lerr)
		}
		if rerr := runner.Run("sh", path); rerr != nil {
			return fmt.Errorf("%w: rollback iptables ruleset: %v", ErrApply, rerr)
		}
		_ = os.Remove(IPTablesDefaultPath)
		return nil
	default:
		return fmt.Errorf("%w: unknown format %q", ErrConfig, format)
	}
}

// writeTempScript writes an executable temporary shell script.
func writeTempScript(script string) (string, error) {
	temp, err := os.CreateTemp("", "gedefense-netpolicy-rollback-*.sh")
	if err != nil {
		return "", fmt.Errorf("%w: temporary rollback script: %v", ErrApply, err)
	}
	path := temp.Name()
	if cerr := temp.Chmod(0o700); cerr != nil {
		_ = temp.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("%w: chmod rollback script: %v", ErrApply, cerr)
	}
	if _, werr := temp.WriteString(script); werr != nil {
		_ = temp.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("%w: write rollback script: %v", ErrApply, werr)
	}
	if cerr := temp.Close(); cerr != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("%w: close rollback script: %v", ErrApply, cerr)
	}
	return path, nil
}

// IsConfigError and friends map sentinel errors for the CLI exit codes.
func IsConfigError(err error) bool { return errors.Is(err, ErrConfig) }

// IsPermissionError reports missing privileges.
func IsPermissionError(err error) bool { return errors.Is(err, ErrPermission) }

// IsApplyError reports a failed install/load/syntax check.
func IsApplyError(err error) bool {
	return errors.Is(err, ErrApply) || errors.Is(err, ErrToolUnavailable) || errors.Is(err, ErrNotTested)
}
