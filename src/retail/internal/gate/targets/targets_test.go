package targets

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/fakedev"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/modbusproxy"
)

type fakeModbusSessions struct{}

func (fakeModbusSessions) Lookup(domain.TargetID, string, time.Time) (domain.WriteSession, bool) {
	return domain.WriteSession{}, false
}
func (fakeModbusSessions) ConsumeUse(domain.SessionID, time.Time) bool { return false }
func (fakeModbusSessions) PlanFor(domain.SessionID) (domain.WritePlan, bool) {
	return domain.WritePlan{}, false
}
func (fakeModbusSessions) Deny(context.Context, domain.DeniedWriteAttempt) error { return nil }
func (fakeModbusSessions) Allowed(context.Context, domain.SessionID, domain.WriteOperation) error {
	return nil
}

func testOptions() Options {
	return Options{
		ModbusSessions: fakeModbusSessions{},
		SourceCIDRs:    []string{"127.0.0.0/8"},
	}
}

func TestRegistryStartsAndReportsHealth(t *testing.T) {
	t.Parallel()
	device, err := fakedev.NewModbus(fakedev.ModbusConfig{})
	if err != nil {
		t.Fatalf("fake device: %v", err)
	}
	if err := device.Start(); err != nil {
		t.Fatalf("start device: %v", err)
	}
	defer func() { _ = device.Close() }()

	registry, err := New(testOptions())
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	spec := Spec{
		TargetID: "aksm-1", AssetID: "asset-danfoss-aksm800", Protocol: ProtocolModbusTCP,
		Listen: "127.0.0.1:0", Upstream: device.Addr(), UnitID: 1,
		ReadRegisters: &modbusproxy.RegisterRange{FC: 3, Start: 0, Count: 16},
	}
	if err := registry.Add(spec); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := registry.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	health := registry.Health()
	if len(health) != 1 || health[0].State != "running" || health[0].Listen == "" || health[0].Listen == "127.0.0.1:0" {
		t.Fatalf("health = %+v", health)
	}
	registry.Stop()
	registry.Stop()
	if got := registry.Health()[0].State; got != "stopped" {
		t.Fatalf("state after stop = %q", got)
	}
}

func TestRegistryValidation(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{}); err == nil {
		t.Fatal("empty source CIDRs must fail")
	}
	registry, err := New(testOptions())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := registry.Add(Spec{TargetID: "x", Protocol: "opcua", Listen: "127.0.0.1:0", Upstream: "127.0.0.1:1"}); err == nil {
		t.Fatal("unsupported protocol accepted")
	}
	spec := Spec{TargetID: "aksm-1", Protocol: ProtocolModbusTCP, Listen: "127.0.0.1:0", Upstream: "127.0.0.1:502"}
	if err := registry.Add(spec); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := registry.Add(spec); err == nil {
		t.Fatal("duplicate target accepted")
	}
}

func TestRegistryAddAfterStartRejected(t *testing.T) {
	t.Parallel()
	registry, err := New(testOptions())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := registry.Start(context.Background()); err != nil {
		t.Fatalf("start empty registry: %v", err)
	}
	defer registry.Stop()
	err = registry.Add(Spec{TargetID: "aksm-1", Protocol: ProtocolModbusTCP, Listen: "127.0.0.1:0", Upstream: "127.0.0.1:502"})
	if err == nil {
		t.Fatal("Add after Start must fail")
	}
}

func TestSourceCIDRParsing(t *testing.T) {
	t.Parallel()
	registry, err := New(Options{ModbusSessions: fakeModbusSessions{}, SourceCIDRs: []string{"bad-cidr"}})
	if err == nil || registry != nil {
		t.Fatal("invalid CIDR must fail")
	}
	registry, err = New(Options{ModbusSessions: fakeModbusSessions{}, SourceCIDRs: []string{"10.10.40.0/24"}})
	if err != nil || len(registry.cidrs) != 1 || registry.cidrs[0] != netip.MustParsePrefix("10.10.40.0/24") {
		t.Fatalf("cidr parsing failed: %v", err)
	}
}

func TestTimeoutClamp(t *testing.T) {
	t.Parallel()
	if got := timeoutFromSeconds(0); got != 5*time.Second {
		t.Fatalf("default timeout = %v", got)
	}
	if got := timeoutFromSeconds(600); got != 60*time.Second {
		t.Fatalf("clamped timeout = %v", got)
	}
}

var _ = errors.Is
