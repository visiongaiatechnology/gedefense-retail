package netx

import (
	"strings"
	"testing"
)

func TestParseAddrAndNormalize(t *testing.T) {
	t.Parallel()
	addr, err := ParseAddr(" 172.16.50.10 ")
	if err != nil || addr.String() != "172.16.50.10" {
		t.Fatalf("parse: %v %v", addr, err)
	}
	mapped, err := ParseAddr("::ffff:172.16.50.10")
	if err != nil || mapped.String() != "172.16.50.10" {
		t.Fatalf("mapped address not unmapped: %v %v", mapped, err)
	}
	if _, err := ParseAddr(""); err == nil {
		t.Fatal("empty address accepted")
	}
	if _, err := ParseAddr("172.16.50.10%eth0"); err == nil {
		t.Fatal("zoned address accepted")
	}
	if _, err := ParseAddr(strings.Repeat("9", 1024)); err == nil {
		t.Fatal("oversized address accepted")
	}
	if !IsLoopback("127.0.0.1") || !IsLoopback("::1") || IsLoopback("172.16.50.10") {
		t.Fatal("loopback detection broken")
	}
	for _, private := range []string{"10.0.0.1", "172.16.50.10", "192.168.1.1", "169.254.1.1", "127.0.0.1"} {
		addr, _ := ParseAddr(private)
		if !IsPrivate(addr) {
			t.Fatalf("%s not classified private", private)
		}
	}
	public, _ := ParseAddr("8.8.8.8")
	if IsPrivate(public) || AddrClass(public) != "public" {
		t.Fatal("public address misclassified")
	}
}

func TestMACHelpers(t *testing.T) {
	t.Parallel()
	mac, err := ParseMAC("02:00:00:11:22:33")
	if err != nil {
		t.Fatalf("parse mac: %v", err)
	}
	if FormatMAC(mac) != "02:00:00:11:22:33" {
		t.Fatalf("format = %q", FormatMAC(mac))
	}
	if OUI(mac) != "02:00:00" {
		t.Fatalf("oui = %q", OUI(mac))
	}
	for _, invalid := range []string{"", "02:00:00", "zz:00:00:11:22:33", "ff:ff:ff:ff:ff:ff", "01:00:00:00:00:00"} {
		if _, err := ParseMAC(invalid); err == nil {
			t.Fatalf("invalid mac %q accepted", invalid)
		}
	}
	if _, err := ParseMAC("02-00-00-11-22-33"); err != nil {
		t.Fatalf("dash notation rejected: %v", err)
	}
}

func TestEndpointParsing(t *testing.T) {
	t.Parallel()
	host, port, err := ParseEndpoint("172.16.50.10:502")
	if err != nil || host != "172.16.50.10" || port != 502 {
		t.Fatalf("endpoint: %v %v %v", host, port, err)
	}
	if _, _, err := ParseEndpoint("172.16.50.10"); err == nil {
		t.Fatal("endpoint without port accepted")
	}
	if _, _, err := ParseEndpoint("hostname:502"); err == nil {
		t.Fatal("hostname endpoint accepted (no DNS in collectors)")
	}
	if _, _, err := ParseAddrPort("172.16.50.10", 161); err != nil {
		t.Fatalf("default port: %v", err)
	}
	if _, err := ParsePort("65536"); err == nil {
		t.Fatal("port out of range accepted")
	}
	if _, err := ParsePort(""); err == nil {
		t.Fatal("empty port accepted")
	}
	if got := FormatEndpoint("172.16.50.10", 1883); got != "172.16.50.10:1883" {
		t.Fatalf("format endpoint = %q", got)
	}
}

func TestFlowHelpers(t *testing.T) {
	t.Parallel()
	flow := Flow{SrcIP: "172.16.50.20", DstIP: "172.16.50.10", SrcPort: 50000, DstPort: 502, Protocol: "modbus_tcp"}
	if err := flow.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	reverse := flow.Reverse()
	if reverse.Key() != flow.Key() {
		t.Fatalf("canonical keys differ: %q vs %q", flow.Key(), reverse.Key())
	}
	if flow.Canonical().SrcIP != "172.16.50.10" {
		t.Fatalf("canonical direction = %+v", flow.Canonical())
	}
	meta := flow.AddMeta(120, 2)
	if meta.Bytes != 120 || meta.Packets != 2 || meta.Protocol != "modbus_tcp" {
		t.Fatalf("flow meta = %+v", meta)
	}
	if err := (Flow{SrcIP: "nope", DstIP: "172.16.50.10", Protocol: "tcp"}).Validate(); err == nil {
		t.Fatal("invalid source accepted")
	}
	if err := (Flow{SrcIP: "172.16.50.1", DstIP: "172.16.50.2", Protocol: "BAD PROTO"}).Validate(); err == nil {
		t.Fatal("invalid protocol accepted")
	}
	if got := ServiceProtocol(47808); got != "bacnet_ip" {
		t.Fatalf("service protocol = %q", got)
	}
	if got := ServiceProtocol(12345); got != "" {
		t.Fatalf("unknown port mapped to %q", got)
	}
}

func TestSplitList(t *testing.T) {
	t.Parallel()
	items := SplitList(" a, b ; c ,, d ")
	want := []string{"a", "b", "c", "d"}
	if len(items) != len(want) {
		t.Fatalf("items = %v", items)
	}
	for i := range want {
		if items[i] != want[i] {
			t.Fatalf("items = %v", items)
		}
	}
	if len(SplitList("  ")) != 0 {
		t.Fatal("empty list not empty")
	}
}

func TestCompareEndpoints(t *testing.T) {
	t.Parallel()
	if CompareEndpoints("172.16.50.1", 1, "172.16.50.2", 1) >= 0 {
		t.Fatal("IP ordering wrong")
	}
	if CompareEndpoints("172.16.50.1", 1, "172.16.50.1", 2) >= 0 {
		t.Fatal("port ordering wrong")
	}
	if CompareEndpoints("172.16.50.1", 1, "172.16.50.1", 1) != 0 {
		t.Fatal("equal endpoints not equal")
	}
}
