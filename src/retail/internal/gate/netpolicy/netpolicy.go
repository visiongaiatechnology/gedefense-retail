// Package netpolicy renders and applies host-based network enforcement rules so
// that management connections to protected OT controllers only originate from the
// retailgate source addresses.
//
// Honest scope: the firewall can only enforce what actually traverses the gate
// host. It is NOT a router/NAT implementation; the operator must place the gate as
// the L3 path (routing/NAT/bridge, see --print-topology) before these rules have
// any effect. The package never changes default chains/policies, only its own
// table/chain.
package netpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
)

// Format is the firewall backend of the generated ruleset.
type Format string

const (
	FormatNFTables Format = "nftables"
	FormatIPTables Format = "iptables"

	// NFTTable is the dedicated nftables table (never a default chain).
	NFTTable = "gedefense_gate"
	// ChainName is the dedicated iptables chain in the FORWARD table.
	ChainName = "GEDEFENSE_GATE"
	// LogPrefix marks every dropped packet in the kernel log.
	LogPrefix = "gedefense-gate-drop "
	// NFTDefaultPath is the installed nftables include fragment.
	NFTDefaultPath = "/etc/nftables.d/gedefense-gate.nft"
	// IPTablesDefaultPath is the installed idempotent iptables ruleset script.
	IPTablesDefaultPath = "/etc/gedefense-gate.iptables"
)

// Validation and operation errors. The CLI maps them onto documented exit codes.
var (
	// ErrConfig reports invalid input (exit 2).
	ErrConfig = errors.New("netpolicy: invalid configuration")
	// ErrPermission reports missing privileges (exit 3).
	ErrPermission = errors.New("netpolicy: insufficient privileges (root required)")
	// ErrApply reports a failed installation/syntax check (exit 4).
	ErrApply = errors.New("netpolicy: apply failed")
	// ErrToolUnavailable reports a missing firewall tool for an applying action.
	ErrToolUnavailable = errors.New("netpolicy: firewall tool not available")
	// ErrNotTested reports that --check could not verify the ruleset syntax
	// because the required firewall tooling is not installed (fail-closed).
	ErrNotTested = errors.New("netpolicy: syntax NOT_TESTED (required tool not installed)")
)

// Endpoint is one protected controller address (management path).
type Endpoint struct {
	TargetID string
	IP       netip.Addr
	Port     uint16
	Protocol string // modbus_tcp, http, https
}

// Plan is the validated rule input.
type Plan struct {
	Endpoints []Endpoint
	SourcesV4 []netip.Prefix
	SourcesV6 []netip.Prefix
}

// GateSource is one source CIDR/address of the gate host.
func (p Plan) sourceSummary() []string {
	out := make([]string, 0, len(p.SourcesV4)+len(p.SourcesV6))
	for _, prefix := range append(append([]netip.Prefix{}, p.SourcesV4...), p.SourcesV6...) {
		out = append(out, prefix.String())
	}
	return out
}

// LoadTargets reads the targets[] section of a gate.json. Only the endpoint
// information is used; the netpolicy command deliberately does not require the
// full gate configuration (users/policy) to render firewall rules.
func LoadTargets(path string) ([]config.Target, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: --config is required", ErrConfig)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: config %q: %v", ErrConfig, filepath.Base(path), err)
	}
	if info.Size() > 4<<20 {
		return nil, fmt.Errorf("%w: config exceeds 4 MiB", ErrConfig)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read config: %v", ErrConfig, err)
	}
	var document struct {
		Targets []config.Target `json:"targets"`
	}
	if derr := json.Unmarshal(raw, &document); derr != nil {
		return nil, fmt.Errorf("%w: decode config: %v", ErrConfig, derr)
	}
	if len(document.Targets) == 0 {
		return nil, fmt.Errorf("%w: targets[] is empty", ErrConfig)
	}
	return document.Targets, nil
}

// Build validates targets and gate sources and produces a deterministic plan.
// Fail-closed: only IP literals are accepted as upstream endpoints (never host
// names), and at least one gate source is required.
func Build(targets []config.Target, gateSources []string) (Plan, error) {
	if len(targets) == 0 {
		return Plan{}, fmt.Errorf("%w: no targets configured", ErrConfig)
	}
	if len(gateSources) == 0 {
		return Plan{}, fmt.Errorf("%w: at least one --gate-source is required", ErrConfig)
	}
	plan := Plan{}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		endpoint, err := endpointFor(target)
		if err != nil {
			return Plan{}, err
		}
		key := endpoint.IP.String() + "|" + endpoint.Protocol + "|" + strconv.Itoa(int(endpoint.Port))
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		plan.Endpoints = append(plan.Endpoints, endpoint)
	}
	sort.Slice(plan.Endpoints, func(i, j int) bool {
		if plan.Endpoints[i].IP.Compare(plan.Endpoints[j].IP) != 0 {
			return plan.Endpoints[i].IP.Compare(plan.Endpoints[j].IP) < 0
		}
		if plan.Endpoints[i].Port != plan.Endpoints[j].Port {
			return plan.Endpoints[i].Port < plan.Endpoints[j].Port
		}
		return plan.Endpoints[i].TargetID < plan.Endpoints[j].TargetID
	})
	if len(plan.Endpoints) == 0 {
		return Plan{}, fmt.Errorf("%w: no usable target endpoints", ErrConfig)
	}
	for _, raw := range gateSources {
		prefix, err := parseSourcePrefix(raw)
		if err != nil {
			return Plan{}, err
		}
		if prefix.Addr().Is4() {
			plan.SourcesV4 = append(plan.SourcesV4, prefix)
		} else {
			plan.SourcesV6 = append(plan.SourcesV6, prefix)
		}
	}
	plan.SourcesV4 = dedupePrefixes(plan.SourcesV4)
	plan.SourcesV6 = dedupePrefixes(plan.SourcesV6)
	if len(plan.SourcesV4)+len(plan.SourcesV6) == 0 {
		return Plan{}, fmt.Errorf("%w: no usable --gate-source", ErrConfig)
	}
	// F-A3-05: fail-closed per address family.
	if err := validateFamilyCoverage(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// validateFamilyCoverage enforces F-A3-05: every address family that occurs in
// the protected endpoints must have at least one gate source of the same family.
// Without this check a family without a source would silently fall through the
// generated rules (fail-open). The renderer calls it again as defense in depth.
func validateFamilyCoverage(plan Plan) error {
	hasV4Target, hasV6Target := false, false
	for _, endpoint := range plan.Endpoints {
		if endpoint.IP.Is4() {
			hasV4Target = true
		} else {
			hasV6Target = true
		}
	}
	if hasV4Target && len(plan.SourcesV4) == 0 {
		return fmt.Errorf("%w: targets contain IPv4 endpoints but no IPv4 --gate-source was supplied (fail-closed per address family)", ErrConfig)
	}
	if hasV6Target && len(plan.SourcesV6) == 0 {
		return fmt.Errorf("%w: targets contain IPv6 endpoints but no IPv6 --gate-source was supplied (fail-closed per address family)", ErrConfig)
	}
	return nil
}

// endpointFor extracts the protected IP:port of one configured target.
func endpointFor(target config.Target) (Endpoint, error) {
	protocol := strings.ToLower(strings.TrimSpace(target.Protocol))
	upstream := strings.TrimSpace(target.Upstream)
	if upstream == "" {
		return Endpoint{}, fmt.Errorf("%w: target %q has no upstream", ErrConfig, target.TargetID)
	}
	var host, portText string
	var defaultPort int
	switch protocol {
	case "modbus_tcp":
		defaultPort = 0 // the Modbus port must be explicit in the configuration
		var err error
		host, portText, err = net.SplitHostPort(upstream)
		if err != nil {
			return Endpoint{}, fmt.Errorf("%w: target %q upstream %q must be an IP:port literal", ErrConfig, target.TargetID, upstream)
		}
	case "http":
		parsed, err := url.Parse(upstream)
		if err != nil || parsed.Host == "" || parsed.User != nil {
			return Endpoint{}, fmt.Errorf("%w: target %q upstream is not a valid URL", ErrConfig, target.TargetID)
		}
		host = parsed.Hostname()
		portText = parsed.Port()
		if portText == "" {
			if parsed.Scheme == "https" {
				defaultPort = 443
			} else {
				defaultPort = 80
			}
		}
	case "https":
		parsed, err := url.Parse(upstream)
		if err != nil || parsed.Host == "" {
			return Endpoint{}, fmt.Errorf("%w: target %q upstream is not a valid URL", ErrConfig, target.TargetID)
		}
		host = parsed.Hostname()
		portText = parsed.Port()
		if portText == "" {
			defaultPort = 443
		}
	default:
		return Endpoint{}, fmt.Errorf("%w: target %q protocol %q is not supported (modbus_tcp, http, https)", ErrConfig, target.TargetID, target.Protocol)
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: target %q upstream host %q is not an IP literal (DNS names are rejected fail-closed)", ErrConfig, target.TargetID, host)
	}
	port := defaultPort
	if portText != "" {
		parsedPort, perr := strconv.Atoi(portText)
		if perr != nil || parsedPort < 1 || parsedPort > 65535 {
			return Endpoint{}, fmt.Errorf("%w: target %q has an invalid port %q", ErrConfig, target.TargetID, portText)
		}
		port = parsedPort
	}
	if port < 1 || port > 65535 {
		return Endpoint{}, fmt.Errorf("%w: target %q has no valid port", ErrConfig, target.TargetID)
	}
	return Endpoint{TargetID: string(target.TargetID), IP: ip.Unmap(), Port: uint16(port), Protocol: protocol}, nil
}

// parseSourcePrefix accepts a CIDR or a single IP (implicit host prefix).
func parseSourcePrefix(raw string) (netip.Prefix, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return netip.Prefix{}, fmt.Errorf("%w: empty --gate-source", ErrConfig)
	}
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: --gate-source %q is neither a CIDR nor an IP address", ErrConfig, raw)
	}
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

// dedupePrefixes sorts and deduplicates a prefix list.
func dedupePrefixes(list []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	seen := make(map[string]struct{}, len(list))
	for _, prefix := range list {
		text := prefix.String()
		if _, dup := seen[text]; dup {
			continue
		}
		seen[text] = struct{}{}
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Compare(out[j].Addr()) < 0 })
	return out
}

// Render produces the ruleset text for the requested format.
func Render(plan Plan, format Format) (string, error) {
	// Defense in depth: never render a family without a matching source.
	if err := validateFamilyCoverage(plan); err != nil {
		return "", err
	}
	switch format {
	case FormatNFTables:
		return renderNFTables(plan), nil
	case FormatIPTables:
		return renderIPTables(plan), nil
	default:
		return "", fmt.Errorf("%w: unknown format %q (nftables, iptables)", ErrConfig, format)
	}
}

// RollbackScript renders the removal script for the requested format.
func RollbackScript(format Format) (string, error) {
	switch format {
	case FormatNFTables:
		return rollbackNFTables(), nil
	case FormatIPTables:
		return rollbackIPTables(), nil
	default:
		return "", fmt.Errorf("%w: unknown format %q (nftables, iptables)", ErrConfig, format)
	}
}

// DefaultPath returns the default install path of the rendered rules.
func DefaultPath(format Format) string {
	if format == FormatNFTables {
		return NFTDefaultPath
	}
	return IPTablesDefaultPath
}

// endpointComment renders the audit comment of one endpoint.
func endpointComment(endpoint Endpoint) string {
	return fmt.Sprintf("retailgate target=%s proto=tcp port=%d protocol=%s", endpoint.TargetID, endpoint.Port, endpoint.Protocol)
}

// endpointList renders endpoints for the header comment.
func endpointList(plan Plan) string {
	parts := make([]string, 0, len(plan.Endpoints))
	for _, endpoint := range plan.Endpoints {
		parts = append(parts, cleanupComment(endpoint.IP.String()+":"+strconv.Itoa(int(endpoint.Port))))
	}
	return strings.Join(parts, ", ")
}

// cleanupComment keeps a comment on one line and free of rule-breaking characters.
func cleanupComment(text string) string {
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\"", "'")
	if len(text) > 200 {
		text = text[:200]
	}
	return text
}
