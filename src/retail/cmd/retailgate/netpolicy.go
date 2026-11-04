package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/netpolicy"
)

// cmdNetPolicy implements the netpolicy subcommand: render, check, install or
// roll back the host firewall rules that force management traffic through the gate.
func cmdNetPolicy(args []string) int {
	fs := flag.NewFlagSet("netpolicy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", "", "path to gate.json (required unless --rollback/--print-topology)")
	formatText := fs.String("format", string(netpolicy.FormatNFTables), "firewall format: nftables|iptables")
	var sources gateSources
	fs.Var(&sources, "gate-source", "CIDR of a retailgate source address (repeatable)")
	outPath := fs.String("out", "", "write the ruleset to this file instead of stdout")
	applyRules := fs.Bool("apply", false, "install the ruleset and load it into the running firewall (root required)")
	rollbackRules := fs.Bool("rollback", false, "remove the generated table/chain and installed ruleset")
	check := fs.Bool("check", false, "validate configuration and rules without changing the host")
	printTopology := fs.Bool("print-topology", false, "print routing/NAT/bridge prerequisites and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	format := netpolicy.Format(strings.TrimSpace(*formatText))
	if format != netpolicy.FormatNFTables && format != netpolicy.FormatIPTables {
		fmt.Fprintf(os.Stderr, "retailgate netpolicy: --format must be nftables or iptables\n")
		return 2
	}
	if *rollbackRules {
		if err := netpolicy.Rollback(format, netpolicy.ExecRunner{}); err != nil {
			return netPolicyExit(err, "rollback")
		}
		return printJSON(map[string]any{"rolled_back": true, "format": string(format)})
	}
	var plan netpolicy.Plan
	havePlan := false
	if strings.TrimSpace(*cfgPath) != "" {
		targets, err := netpolicy.LoadTargets(*cfgPath)
		if err != nil {
			return netPolicyExit(err, "config")
		}
		built, err := netpolicy.Build(targets, sources)
		if err != nil {
			return netPolicyExit(err, "config")
		}
		plan, havePlan = built, true
	}
	if *printTopology {
		if havePlan {
			fmt.Print(netpolicy.TopologyNotes(&plan))
		} else {
			fmt.Print(netpolicy.TopologyNotes(nil))
		}
		return 0
	}
	if !havePlan {
		fmt.Fprintf(os.Stderr, "retailgate netpolicy: --config is required for --check/--apply/output\n")
		return 2
	}
	runner := netpolicy.ExecRunner{}
	if *check {
		report, checkErr := netpolicy.Check(plan, format, runner)
		if code := printJSON(report); code != 0 {
			return code
		}
		if checkErr != nil {
			return netPolicyExit(checkErr, "check")
		}
		return 0
	}
	if *applyRules {
		installed, err := netpolicy.Apply(netpolicy.ApplyOptions{
			Plan: plan, Format: format, OutPath: *outPath, Runner: runner,
		})
		if err != nil {
			return netPolicyExit(err, "apply")
		}
		return printJSON(map[string]any{
			"applied": true, "format": string(format), "path": installed,
			"restart_note": "re-run this command after reboot (or include the file in the firewall service)",
		})
	}
	rules, err := netpolicy.Render(plan, format)
	if err != nil {
		return netPolicyExit(err, "render")
	}
	if strings.TrimSpace(*outPath) != "" {
		mode := os.FileMode(0o600)
		if format == netpolicy.FormatIPTables {
			mode = 0o700
		}
		if werr := netpolicy.WriteFileAtomic(*outPath, []byte(rules), mode); werr != nil {
			return netPolicyExit(werr, "write")
		}
		return printJSON(map[string]any{"written": *outPath, "format": string(format), "bytes": len(rules)})
	}
	fmt.Print(rules)
	return 0
}

// gateSources collects repeated --gate-source flags.
type gateSources []string

// String renders the collected sources.
func (g *gateSources) String() string { return strings.Join(*g, ",") }

// Set appends one source value (flag.Value).
func (g *gateSources) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("empty --gate-source")
	}
	*g = append(*g, value)
	return nil
}

// netPolicyExit maps a netpolicy error onto the documented exit codes:
// 2 = configuration, 3 = permission, 4 = apply.
func netPolicyExit(err error, phase string) int {
	fmt.Fprintf(os.Stderr, "retailgate netpolicy (%s): %v\n", phase, err)
	switch {
	case netpolicy.IsConfigError(err):
		return 2
	case netpolicy.IsPermissionError(err):
		return 3
	case netpolicy.IsApplyError(err):
		return 4
	default:
		return 1
	}
}
