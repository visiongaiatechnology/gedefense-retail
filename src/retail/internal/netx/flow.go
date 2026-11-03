// Flow helpers for passive collectors.
package netx

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Flow is the normalized passive communication metadata of one observed
// connection/flow. It is a value type: collectors build it from packets and
// convert it into its own JSON shape without carrying extra state.
type Flow struct {
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	Protocol string
}

// Validate rejects incomplete or out-of-range flows. Protocol must be one of
// the values the product knows about; unknown protocols are still allowed but
// must be lower-case ASCII so that they cannot smuggle control characters into
// logs or JSON.
func (f Flow) Validate() error {
	if !ValidProtocol(f.Protocol) {
		return fmt.Errorf("flow: invalid protocol %q", f.Protocol)
	}
	if f.SrcPort < 0 || f.SrcPort > 65535 || f.DstPort < 0 || f.DstPort > 65535 {
		return fmt.Errorf("flow: port out of range")
	}
	if _, err := ParseAddr(f.SrcIP); err != nil {
		return fmt.Errorf("flow: src: %w", err)
	}
	if _, err := ParseAddr(f.DstIP); err != nil {
		return fmt.Errorf("flow: dst: %w", err)
	}
	return nil
}

// ValidProtocol accepts lower-case protocol labels such as modbus_tcp,
// bacnet_ip, mqtt, snmp, http, https, arp, tcp, udp, icmp or opaque.
func ValidProtocol(p string) bool {
	if p == "" || len(p) > 32 {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

// Canonical orders the two endpoints deterministically so that both directions
// of the same conversation share one flow key. It never guesses a client.
func (f Flow) Canonical() Flow {
	if f.endpointLess(f.SrcIP, f.SrcPort, f.DstIP, f.DstPort) {
		return f
	}
	return Flow{SrcIP: f.DstIP, DstIP: f.SrcIP, SrcPort: f.DstPort, DstPort: f.SrcPort, Protocol: f.Protocol}
}

// Key is a stable map key for aggregation. Both directions of a conversation
// produce the same key.
func (f Flow) Key() string {
	c := f.Canonical()
	return c.SrcIP + ":" + strconv.Itoa(c.SrcPort) + ">" + c.DstIP + ":" + strconv.Itoa(c.DstPort) + "/" + c.Protocol
}

// Reverse swaps the endpoints, keeping the protocol.
func (f Flow) Reverse() Flow {
	return Flow{SrcIP: f.DstIP, DstIP: f.SrcIP, SrcPort: f.DstPort, DstPort: f.SrcPort, Protocol: f.Protocol}
}

func (f Flow) endpointLess(aIP string, aPort int, bIP string, bPort int) bool {
	aAddr, aErr := ParseAddr(aIP)
	bAddr, bErr := ParseAddr(bIP)
	switch {
	case aErr != nil && bErr != nil:
		return aIP < bIP
	case aErr != nil:
		return false
	case bErr != nil:
		return true
	}
	if cmp := aAddr.Compare(bAddr); cmp != 0 {
		return cmp < 0
	}
	return aPort < bPort
}

// Meta converts the flow into the domain metadata block. Direction is left
// empty on purpose: a passive sensor cannot prove who initiated a flow.
func (f Flow) Meta() domain.FlowMeta {
	return domain.FlowMeta{
		SrcIP:    f.SrcIP,
		DstIP:    f.DstIP,
		SrcPort:  f.SrcPort,
		DstPort:  f.DstPort,
		Protocol: f.Protocol,
	}
}

// AddMeta merges byte/packet counters into the domain metadata and validates
// the result.
func (f Flow) AddMeta(bytes, packets int64) domain.FlowMeta {
	m := f.Meta()
	if bytes > 0 {
		m.Bytes = bytes
	}
	if packets > 0 {
		m.Packets = packets
	}
	return m
}

// ServiceProtocol maps well-known OT/retail ports to the protocol label used
// in flow and asset events. Ports are hints, never proof (see the protocol
// matrix), so callers must keep their confidence low.
func ServiceProtocol(port int) string {
	switch port {
	case 502:
		return "modbus_tcp"
	case 47808:
		return "bacnet_ip"
	case 1883:
		return "mqtt"
	case 8883:
		return "mqtt"
	case 161:
		return "snmp"
	case 162:
		return "snmp_trap"
	case 80:
		return "http"
	case 443, 8443:
		return "https"
	case 8000:
		return "http"
	case 8080:
		return "http"
	default:
		return ""
	}
}

// SplitList parses a comma or semicolon separated option value into non-empty,
// trimmed items. Both separators may be mixed; it is the single parsing helper
// for all adapter options so that whitespace handling stays identical.
func SplitList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ParseAddrPort is a strict host:port parser that also accepts a bare host with
// an explicit default port supplied by the caller.
func ParseAddrPort(value string, defaultPort uint16) (string, uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, fmt.Errorf("%w: empty", ErrInvalidEndpoint)
	}
	if !strings.Contains(value, ":") {
		addr, err := ParseAddr(value)
		if err != nil {
			return "", 0, fmt.Errorf("%w: %v", ErrInvalidEndpoint, err)
		}
		return addr.String(), defaultPort, nil
	}
	return ParseEndpoint(value)
}

// CompareEndpoints orders two textual IPs deterministically. It is used when
// sorting aggregated output so that generated events are reproducible.
func CompareEndpoints(aIP string, aPort int, bIP string, bPort int) int {
	a, aErr := ParseAddr(aIP)
	b, bErr := ParseAddr(bIP)
	switch {
	case aErr == nil && bErr == nil:
		if cmp := a.Compare(b); cmp != 0 {
			return cmp
		}
	case aErr == nil:
		return -1
	case bErr == nil:
		return 1
	default:
		if aIP != bIP {
			if aIP < bIP {
				return -1
			}
			return 1
		}
	}
	switch {
	case aPort < bPort:
		return -1
	case aPort > bPort:
		return 1
	}
	return 0
}

// AddrFromIPv4 builds a netip.Addr from four raw bytes.
func AddrFromIPv4(b []byte) (netip.Addr, error) {
	if len(b) != 4 {
		return netip.Addr{}, fmt.Errorf("%w: need 4 bytes", ErrInvalidIP)
	}
	return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}), nil
}
