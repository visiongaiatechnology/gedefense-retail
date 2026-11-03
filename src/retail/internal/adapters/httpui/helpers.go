// Small helpers shared by the HTTP/UI adapter and its decoder.
package httpui

import (
	"fmt"
	"net"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/netx"
)

// ConnMeta is the passive address evidence of one observed connection. For a
// byte-stream feed only the client (feed) side is known; the PCAP dispatcher
// fills both sides from the packet headers.
type ConnMeta struct {
	ClientIP   string
	ClientPort uint16
	ServerIP   string
	ServerPort uint16
}

// Valid reports whether the meta carries enough evidence to build flow/asset
// events. Without a server IP nothing is invented.
func (m ConnMeta) Valid() bool {
	if _, err := netx.ParseAddr(m.ServerIP); err != nil {
		return false
	}
	if m.ClientIP == "" {
		return false
	}
	_, err := netx.ParseAddr(m.ClientIP)
	return err == nil
}

func validateIPv4(value string) error {
	addr, err := netx.ParseAddr(value)
	if err != nil {
		return err
	}
	if !addr.Is4() {
		return fmt.Errorf("only IPv4 feed addresses are supported in the MVP")
	}
	return nil
}

func netxParsePort(value string) (int, error) {
	port, err := netx.ParsePort(value)
	if err != nil {
		return 0, err
	}
	return int(port), nil
}

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return ""
	}
	if _, err := netx.ParseAddr(host); err != nil {
		return ""
	}
	return host
}

func remotePort(conn net.Conn) uint16 {
	_, portText, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return 0
	}
	port, err := netx.ParsePort(portText)
	if err != nil {
		return 0
	}
	return port
}

// sanitizeHost accepts only a conservative DNS label / IPv4 host form and
// removes any port suffix. It returns "" for anything that is not a hostname.
func sanitizeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 255 {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	raw = strings.ToLower(raw)
	if len(raw) == 0 || len(raw) > 253 {
		return ""
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_':
		default:
			return ""
		}
	}
	if strings.HasPrefix(raw, ".") || strings.HasSuffix(raw, ".") {
		return ""
	}
	return raw
}

// sanitizePath keeps the path part of a request target and removes the query
// string and fragment (they can carry credentials or operator data).
func sanitizePath(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if raw == "" || raw[0] != '/' {
		// Absolute-form targets (proxy style) and authority-form targets are not
		// representative for a management UI; keep only bounded printable ASCII.
		raw = "/" + raw
	}
	out := make([]byte, 0, 128)
	for i := 0; i < len(raw) && len(out) < 128; i++ {
		c := raw[i]
		if c < 0x20 || c > 0x7e {
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return "/"
	}
	return string(out)
}

// sanitizeToken returns a bounded, printable ASCII token or "".
func sanitizeToken(raw string, max int) string {
	raw = strings.TrimSpace(raw)
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw) && len(out) < max; i++ {
		c := raw[i]
		if c < 0x20 || c > 0x7e {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// uiHint infers a product family from a Host/Server/User-Agent string. It is a
// WEAK hint and is reported as such (model + confidence), never as a proven
// device identity.
func uiHint(values ...string) (vendor, model string) {
	for _, value := range values {
		lower := strings.ToLower(value)
		switch {
		case strings.Contains(lower, "storeview"):
			return "", "StoreView"
		case strings.Contains(lower, "xweb"):
			return "", "XWEB"
		case strings.Contains(lower, "danfoss"):
			return "Danfoss", ""
		case strings.Contains(lower, "ak-sm"):
			return "Danfoss", "AK-SM"
		case strings.Contains(lower, "ak-sc"):
			return "Danfoss", "AK-SC"
		case strings.Contains(lower, "copeland"):
			return "Copeland", ""
		case strings.Contains(lower, "dixell"):
			return "Dixell", ""
		case strings.Contains(lower, "carel"):
			return "Carel", ""
		}
	}
	return "", ""
}
