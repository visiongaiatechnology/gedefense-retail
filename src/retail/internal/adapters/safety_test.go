package adapters

// Safety gate: proves at the source level that the adapter packages contain no
// writable path into an OT device.
//
// The test is deliberately conservative and layered:
//   - static: forbidden imports (net/http, os/exec), forbidden outbound-write
//     calls (WriteTo), forbidden write encoders per protocol;
//   - contract: every adapter reports ReadOnly=true and a valid collection
//     method;
//   - protocol: the wire behavior is proven in the per-adapter tests
//     (fake Modbus server sees FC3/4 only, fake MQTT broker sees no PUBLISH,
//     fake SNMP agent sees GetRequest only, BACnet has no send path at all).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/bacnet"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/httpui"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/modbus"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/mqtt"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/pcap"
	"github.com/visiongaiatechnology/gedefense/retail/internal/adapters/snmp"
	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// adapterPackages are the subpackages audited by this gate.
var adapterPackages = []string{"modbus", "mqtt", "bacnet", "snmp", "httpui", "pcap"}

// forbiddenImports may not appear in adapter production code.
var forbiddenImports = map[string]string{
	"net/http":         "no HTTP client may talk to a management UI",
	"os/exec":          "no process execution from an adapter",
	"plugin":           "no dynamic code loading",
	"unsafe":           "no unsafe code in the passive adapters",
	"golang.org/x/net": "stdlib-only",
	"github.com/":      "no third-party module",
}

// forbiddenFuncPattern matches names that would indicate a write/send capability
// implemented by the adapter itself (only the observation helpers may carry a
// "write" in their name and are allowlisted below).
var forbiddenFuncPattern = regexp.MustCompile(`(?i)^(encodeWrite|buildWrite|sendWrite|doWrite|writePdu|writeFrame|writeProperty|writeRegister|writeCoil|publishMessage|encodePublish|buildSet|sendSet|snmpSet|setRequest)`)

// allowedObserverFuncs are the only functions whose names may contain "write":
// allowedObserverFuncs are the only functions whose names may contain "write".
// They either describe/passively observe a write attempt or write a protocol
// packet that provably cannot carry a write (MQTT CONNECT/SUBSCRIBE/PINGREQ,
// PCAP fixture files in tests/simulator).
var allowedObserverFuncs = map[string]struct{}{
	"isObservedWriteFunction": {},
	"writeFunctionName":       {},
	"writeRegisterAddress":    {},
	"writeRegisterCount":      {},
	"observedRegisterName":    {},
	"handleWrite":             {},
	"writeAttemptEvents":      {},
	"rememberWrite":           {}, // transaction de-duplication of observed writes
	"isWriteMethod":           {}, // HTTP method classification (observation only)
	"writePacket":             {}, // MQTT: CONNECT/SUBSCRIBE/PINGREQ/DISCONNECT only
	"writeUTF8":               {}, // MQTT: length-prefixed STRING encoder (CONNECT/SUBSCRIBE)
	"NewWriter":               {}, // PCAP fixture writer (io.Writer, no socket)
	"NewWriterLinkType":       {}, // PCAP fixture writer (io.Writer, no socket)
	"WritePacket":             {}, // PCAP fixture writer (io.Writer, no socket)
}

// TestSafety_NoForbiddenImportsInAdapters scans every adapter package.
func TestSafety_NoForbiddenImportsInAdapters(t *testing.T) {
	for _, pkg := range adapterPackages {
		pkg := pkg
		t.Run(pkg, func(t *testing.T) {
			imports := productionImports(t, pkg)
			for _, imp := range imports {
				if reason, forbidden := forbiddenImports[imp]; forbidden {
					t.Fatalf("%s imports %q: %s", pkg, imp, reason)
				}
				if strings.HasPrefix(imp, "github.com/") && !strings.HasPrefix(imp, "github.com/visiongaiatechnology/gedefense/retail/") {
					t.Fatalf("%s imports third-party package %q", pkg, imp)
				}
			}
		})
	}
}

// TestSafety_NoOutboundPacketWriteInPassiveAdapters ensures the passive
// adapters never call WriteTo (raw packet send). BACnet/IP, HTTP-UI and PCAP
// must be incapable of emitting a datagram.
func TestSafety_NoOutboundPacketWriteInPassiveAdapters(t *testing.T) {
	passive := []string{"bacnet", "httpui", "pcap"}
	for _, pkg := range passive {
		pkg := pkg
		t.Run(pkg, func(t *testing.T) {
			for _, call := range productionCallNames(t, pkg) {
				switch call {
				case "WriteTo", "WriteMsgUDP", "WriteToUDP", "Dial", "DialUDP", "DialTCP":
					t.Fatalf("%s calls %q: passive adapters must not send traffic", pkg, call)
				}
			}
		})
	}
}

// TestSafety_NoAdapterImplementsWriteFunctionCode checks that no adapter
// production function is a write encoder.
func TestSafety_NoAdapterImplementsWriteFunctionCode(t *testing.T) {
	for _, pkg := range adapterPackages {
		pkg := pkg
		t.Run(pkg, func(t *testing.T) {
			for _, name := range productionFuncNames(t, pkg) {
				if _, allowed := allowedObserverFuncs[name]; allowed {
					continue
				}
				if forbiddenFuncPattern.MatchString(name) {
					t.Fatalf("%s declares %q: write/send capability in an adapter", pkg, name)
				}
				lower := strings.ToLower(name)
				if strings.Contains(lower, "write") && !strings.Contains(lower, "observed") {
					t.Fatalf("%s declares %q: only observed-write helpers may mention write", pkg, name)
				}
			}
		})
	}
}

// TestSafety_ProtocolWriteFramesAreNotEncoded is a source-text guard for the
// exact encoders that would let an adapter mutate a device.
func TestSafety_ProtocolWriteFramesAreNotEncoded(t *testing.T) {
	checks := []struct {
		pkg       string
		forbidden []string
	}{
		{"modbus", []string{"encodeWriteRequest", "writeSingleRegisterPDU", "pktWrite"}},
		{"mqtt", []string{"encodePublish(", "publishToBroker", "pktPublish<<"}},
		{"snmp", []string{"tagSetRequest,", "buildSetRequest", "setRequest"}},
		{"bacnet", []string{"encodeWriteProperty", "sendWriteProperty", "WhoIsRequest"}},
		{"httpui", []string{"http.Post(", "http.Get(", "http.NewRequest("}},
	}
	for _, check := range checks {
		for _, forbidden := range check.forbidden {
			if sourceContains(t, check.pkg, forbidden) {
				t.Fatalf("%s contains forbidden write/send construct %q", check.pkg, forbidden)
			}
		}
	}
}

// TestSafety_AdaptersAreReadOnly builds every adapter with a minimal valid
// configuration and verifies the read-only collector contract.
func TestSafety_AdaptersAreReadOnly(t *testing.T) {
	site := domain.SiteID("filiale-001")
	base := func(id string, opts map[string]string) collect.AdapterConfig {
		return collect.AdapterConfig{AdapterID: id, SiteID: site, Options: opts}
	}
	cases := []struct {
		name string
		cfg  collect.AdapterConfig
	}{
		{"modbus.tap", base("modbus.tap", map[string]string{"mode": "tap", "listen": "127.0.0.1:0"})},
		{"modbus.poll", base("modbus.poll", map[string]string{
			"mode": "poll", "target": "127.0.0.1:1502",
			"registers": "3:0:sensor_01:air_temperature:celsius:0.1",
		})},
		{"mqtt", base("mqtt", map[string]string{"broker": "127.0.0.1:1883", "topics": "store/#", "allow_wildcard": "1"})},
		{"bacnet", base("bacnet", map[string]string{"listen": "127.0.0.1:47808"})},
		{"snmp", base("snmp", map[string]string{
			"targets": "127.0.0.1:161", "community": "public",
			"oids": "1.3.6.1.2.1.1.3.0|sensor_01|sys_uptime|seconds",
		})},
		{"httpui", base("httpui", map[string]string{"listen": "127.0.0.1:0", "device_ip": "172.16.50.10"})},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			col := newAdapter(t, tc.name, tc.cfg)
			info := col.Info()
			if !info.ReadOnly {
				t.Fatalf("%s reports ReadOnly=false", tc.name)
			}
			if !collect.ValidCollection(info.Collection) {
				t.Fatalf("%s reports invalid collection %q", tc.name, info.Collection)
			}
			if len(info.Protocols) == 0 {
				t.Fatalf("%s reports no protocols", tc.name)
			}
			if info.AdapterID != tc.name {
				t.Fatalf("%s reports adapter id %q", tc.name, info.AdapterID)
			}
		})
	}
}

// productionImports returns the import paths of a package's non-test files.
func productionImports(t *testing.T, pkg string) []string {
	t.Helper()
	files := productionFiles(t, pkg)
	seen := make(map[string]struct{})
	var out []string
	for _, file := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, imp := range parsed.Imports {
			if imp.Path == nil {
				continue
			}
			path := strings.Trim(imp.Path.Value, `"`)
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			out = append(out, path)
		}
	}
	return out
}

// productionFuncNames returns all function/method names in non-test files.
func productionFuncNames(t *testing.T, pkg string) []string {
	t.Helper()
	var out []string
	for _, file := range productionFiles(t, pkg) {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil {
				continue
			}
			out = append(out, fn.Name.Name)
		}
	}
	return out
}

// productionCallNames returns all called function/selector names.
func productionCallNames(t *testing.T, pkg string) []string {
	t.Helper()
	var out []string
	for _, file := range productionFiles(t, pkg) {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				out = append(out, fun.Name)
			case *ast.SelectorExpr:
				out = append(out, fun.Sel.Name)
			}
			return true
		})
	}
	return out
}

// productionFiles lists the non-test Go files of an adapter package.
func productionFiles(t *testing.T, pkg string) []string {
	t.Helper()
	dir := filepath.Join(".", pkg)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read adapter dir %q: %v", dir, err)
	}
	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	if len(files) == 0 {
		t.Fatalf("adapter package %q has no production files", pkg)
	}
	return files
}

// sourceContains is a plain source-text search over one adapter package.
func sourceContains(t *testing.T, pkg, needle string) bool {
	t.Helper()
	for _, file := range productionFiles(t, pkg) {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.Contains(string(raw), needle) {
			return true
		}
	}
	return false
}

// newAdapter constructs one adapter through its package constructor.
func newAdapter(t *testing.T, id string, cfg collect.AdapterConfig) ports.Collector {
	t.Helper()
	cfg.AdapterID = id
	col, err := newFromKind(t, cfg)
	if err != nil {
		t.Fatalf("construct %s: %v", id, err)
	}
	return col
}

// newFromKind maps an adapter id ("modbus.tap") to its constructor.
func newFromKind(t *testing.T, cfg collect.AdapterConfig) (ports.Collector, error) {
	t.Helper()
	kind := cfg.AdapterID
	if idx := strings.IndexByte(kind, '.'); idx >= 0 {
		kind = kind[:idx]
	}
	switch kind {
	case "modbus":
		return modbus.New(cfg)
	case "mqtt":
		return mqtt.New(cfg)
	case "bacnet":
		return bacnet.New(cfg)
	case "snmp":
		return snmp.New(cfg)
	case "httpui":
		return httpui.New(cfg)
	case "pcap":
		return pcap.New(cfg)
	default:
		t.Fatalf("unknown adapter kind %q", kind)
		return nil, nil
	}
}
