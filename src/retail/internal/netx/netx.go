// Package netx provides small, dependency-free helpers for the passive
// collectors: IP/MAC normalization, endpoint parsing and flow keys.
//
// The package never opens sockets, never resolves names and never sends any
// traffic. It exists so that the protocol adapters do not duplicate fragile
// parsing code and so that the safety tests have one place to audit for
// network egress (there is none here).
package netx

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// MaxTextLen bounds every textual address/identifier accepted from config or
// from the wire. Anything longer is rejected instead of being allocated.
const MaxTextLen = 512

// Sentinel errors returned by the helpers. Callers use errors.Is for control
// flow, never string comparison.
var (
	ErrInvalidIP       = errors.New("netx: invalid ip address")
	ErrInvalidMAC      = errors.New("netx: invalid mac address")
	ErrInvalidPort     = errors.New("netx: invalid port")
	ErrInvalidEndpoint = errors.New("netx: invalid endpoint")
)

// ParseAddr parses an IP address strictly: no zone, no trailing junk and a
// bounded length. IPv4-mapped IPv6 addresses are unmapped so that one host has
// exactly one textual identity.
func ParseAddr(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxTextLen {
		return netip.Addr{}, fmt.Errorf("%w: empty or too long", ErrInvalidIP)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %v", ErrInvalidIP, err)
	}
	if addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%w: zoned addresses are not supported", ErrInvalidIP)
	}
	return addr.Unmap(), nil
}

// NormalizeIP returns the canonical textual form of an IP address.
func NormalizeIP(s string) (string, error) {
	addr, err := ParseAddr(s)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

// IsLoopback reports whether the textual address is a loopback address.
func IsLoopback(s string) bool {
	addr, err := ParseAddr(s)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// IsPrivate reports whether the address belongs to a non-public range
// (RFC1918, CGNAT, loopback, link-local or multicast). Discovery uses this to
// avoid claiming internet identities for private peers.
func IsPrivate(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified()
}

// AddrClass labels an address range for flow metadata. The labels are stable
// and not user visible; unknown ranges are "public".
func AddrClass(addr netip.Addr) string {
	switch {
	case !addr.IsValid():
		return "invalid"
	case addr.IsLoopback():
		return "loopback"
	case addr.IsLinkLocalUnicast():
		return "link_local"
	case addr.IsPrivate():
		return "private"
	case addr.IsMulticast():
		return "multicast"
	case addr.IsUnspecified():
		return "unspecified"
	default:
		return "public"
	}
}

// ParseMAC accepts the common MAC notations (colon, dash, dot or bare hex) and
// returns the six raw bytes. It rejects multicast/zero MACs because those are
// never a valid per-asset identity for discovery.
func ParseMAC(s string) ([6]byte, error) {
	var out [6]byte
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return out, fmt.Errorf("%w: empty or too long", ErrInvalidMAC)
	}
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', '.', ' ':
			return -1
		}
		return r
	}, s)
	if len(clean) != 12 {
		return out, fmt.Errorf("%w: %q does not contain 12 hex digits", ErrInvalidMAC, s)
	}
	for i := 0; i < 6; i++ {
		v, err := strconv.ParseUint(clean[i*2:i*2+2], 16, 8)
		if err != nil {
			return out, fmt.Errorf("%w: invalid hex byte", ErrInvalidMAC)
		}
		out[i] = byte(v)
	}
	if out[0]&0x01 != 0 {
		return out, fmt.Errorf("%w: multicast/broadcast mac", ErrInvalidMAC)
	}
	if out == [6]byte{} {
		return out, fmt.Errorf("%w: zero mac", ErrInvalidMAC)
	}
	return out, nil
}

// FormatMAC renders a MAC in upper-case colon notation.
func FormatMAC(mac [6]byte) string {
	const hexdigits = "0123456789ABCDEF"
	buf := make([]byte, 0, 17)
	for i, b := range mac {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexdigits[b>>4], hexdigits[b&0x0f])
	}
	return string(buf)
}

// OUI returns the vendor prefix (first three bytes) in upper-case colon
// notation. It is passive evidence only; an OUI match is never an identity.
func OUI(mac [6]byte) string {
	return FormatMAC([6]byte{mac[0], mac[1], mac[2], 0, 0, 0})[:8]
}

// ParsePort parses a TCP/UDP port number and rejects out-of-range values.
func ParsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("%w: empty", ErrInvalidPort)
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %q is not numeric", ErrInvalidPort, s)
	}
	if v > 65535 {
		return 0, fmt.Errorf("%w: %d out of range", ErrInvalidPort, v)
	}
	return uint16(v), nil
}

// FormatEndpoint renders host:port in the canonical net.JoinHostPort form.
func FormatEndpoint(host string, port uint16) string {
	return joinHostPort(host, port)
}

// joinHostPort is equivalent to net.JoinHostPort without importing net for the
// hot path of event construction.
func joinHostPort(host string, port uint16) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(int(port))
	}
	return host + ":" + strconv.Itoa(int(port))
}

// ParseEndpoint splits "host:port" and validates both parts. It never resolves
// names: the host must already be an IP address, because the collectors must
// not trigger DNS lookups to internal devices.
func ParseEndpoint(s string) (string, uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxTextLen {
		return "", 0, fmt.Errorf("%w: empty or too long", ErrInvalidEndpoint)
	}
	host, portText, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, fmt.Errorf("%w: %q has no port", ErrInvalidEndpoint, s)
	}
	host = strings.Trim(host, "[]")
	addr, err := ParseAddr(host)
	if err != nil {
		return "", 0, fmt.Errorf("%w: host: %v", ErrInvalidEndpoint, err)
	}
	port, err := ParsePort(portText)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrInvalidEndpoint, err)
	}
	return addr.String(), port, nil
}
