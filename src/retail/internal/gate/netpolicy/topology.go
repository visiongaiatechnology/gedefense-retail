package netpolicy

import (
	"fmt"
	"strings"
)

// TopologyNotes explains the prerequisites that must hold before the generated
// firewall rules enforce anything. It deliberately states the honest limitation:
// a host firewall cannot protect traffic that never traverses the host.
func TopologyNotes(plan *Plan) string {
	var builder strings.Builder
	builder.WriteString("retailgate netpolicy — network enforcement prerequisites\n")
	builder.WriteString("================================================================\n\n")
	builder.WriteString("The generated rules only filter traffic that actually traverses this host.\n")
	builder.WriteString("The firewall is NOT a router/NAT implementation and does not create a\n")
	builder.WriteString("management path by itself. Before enforcement is effective, the operator\n")
	builder.WriteString("must place retailgate as the L3 path between the management network and the\n")
	builder.WriteString("OT/controller network:\n\n")
	builder.WriteString("  1. Gate host has two interfaces (management / OT) or a trunk with VLANs.\n")
	builder.WriteString("  2. IP forwarding is enabled on the gate host (net.ipv4.ip_forward=1,\n")
	builder.WriteString("     net.ipv6.conf.all.forwarding=1 when IPv6 is used).\n")
	builder.WriteString("  3. Controllers use the gate host as their default gateway (or static\n")
	builder.WriteString("     routes point the management network at the gate host).\n")
	builder.WriteString("  4. NAT/masquerade is configured only if the controllers must see the gate\n")
	builder.WriteString("     source address instead of the original client address.\n")
	builder.WriteString("  5. The protected controller IPs/ports are exactly the upstream endpoints\n")
	builder.WriteString("     from gate.json targets[]; hostnames/DNS are rejected fail-closed.\n")
	builder.WriteString("  6. The gate host itself may keep direct access (its own traffic is locally\n")
	builder.WriteString("     generated output, not forwarded); restrict local admin access by other\n")
	builder.WriteString("     means (SSH hardening, local firewall policy).\n\n")
	builder.WriteString("Honest limits:\n")
	builder.WriteString("  * Traffic that never passes through this host (flat L2/L3 network, side\n")
	builder.WriteString("    paths, field service laptops on the OT segment) is NOT enforced.\n")
	builder.WriteString("  * The rules do not stop local processes on the gate host; use OS hardening\n")
	builder.WriteString("    and the gate approval workflow for that.\n")
	builder.WriteString("  * nftables and iptables are alternative backends: install only one of them\n")
	builder.WriteString("    to avoid conflicting hooks.\n")
	builder.WriteString("  * Applying requires root; rollback removes only this tool's own table/chain.\n\n")
	if plan != nil && len(plan.Endpoints) > 0 {
		builder.WriteString("Protected controller endpoints:\n")
		for _, endpoint := range plan.Endpoints {
			builder.WriteString(fmt.Sprintf("  - %s:%d (%s, target=%s)\n", endpoint.IP.String(), endpoint.Port, endpoint.Protocol, endpoint.TargetID))
		}
		builder.WriteString("\nAllowed gate sources:\n")
		for _, source := range plan.sourceSummary() {
			builder.WriteString("  - " + source + "\n")
		}
	} else {
		builder.WriteString("Example: retailgate netpolicy --config gate.json --format nftables \\\n")
		builder.WriteString("           --gate-source 10.20.30.40/32 --print-topology\n")
	}
	return builder.String()
}
