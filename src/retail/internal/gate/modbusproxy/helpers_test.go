package modbusproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/fakedev"
)

var testNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// fakeAuth is a controllable SessionLookup (plus the optional WriteUnknown seam).
type fakeAuth struct {
	mu            sync.Mutex
	session       domain.WriteSession
	plan          domain.WritePlan
	hasSession    bool
	hasPlan       bool
	consumeOK     bool
	consumeBudget int
	consumeCalls  int
	allowedErr    error
	denies        []domain.DeniedWriteAttempt
	allowedOps    []domain.WriteOperation
	unknown       []string
}

func (f *fakeAuth) Lookup(domain.TargetID, string, time.Time) (domain.WriteSession, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.session, f.hasSession
}

func (f *fakeAuth) ConsumeUse(domain.SessionID, time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consumeCalls++
	if f.consumeBudget > 0 {
		f.consumeBudget--
		return true
	}
	return f.consumeOK
}

func (f *fakeAuth) PlanFor(domain.SessionID) (domain.WritePlan, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.plan, f.hasPlan
}

func (f *fakeAuth) Deny(_ context.Context, attempt domain.DeniedWriteAttempt) error {
	f.mu.Lock()
	f.denies = append(f.denies, attempt)
	f.mu.Unlock()
	return nil
}

func (f *fakeAuth) Allowed(_ context.Context, _ domain.SessionID, op domain.WriteOperation) error {
	f.mu.Lock()
	f.allowedOps = append(f.allowedOps, op)
	f.mu.Unlock()
	return f.allowedErr
}

// WriteUnknown implements WriteUnknownReporter.
func (f *fakeAuth) WriteUnknown(_ context.Context, _ domain.SessionID, _ domain.WriteOperation, detail string) error {
	f.mu.Lock()
	f.unknown = append(f.unknown, detail)
	f.mu.Unlock()
	return nil
}

func (f *fakeAuth) denyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.denies)
}

func (f *fakeAuth) lastDeny(t *testing.T) domain.DeniedWriteAttempt {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.denies) == 0 {
		t.Fatal("no deny recorded")
	}
	return f.denies[len(f.denies)-1]
}

func (f *fakeAuth) allowedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.allowedOps)
}

func (f *fakeAuth) unknownCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.unknown)
}

func (f *fakeAuth) reset() {
	f.mu.Lock()
	f.denies = nil
	f.allowedOps = nil
	f.unknown = nil
	f.mu.Unlock()
}

func sessionFor(target domain.TargetID, sourceIP string, expires time.Time) domain.WriteSession {
	return domain.WriteSession{
		SessionID: "ses_test", PlanID: "pln_test", TargetID: target, UserID: "vendor-acme",
		SourceIP: sourceIP, CreatedAt: testNow.Add(-time.Minute), ExpiresAt: expires, MaxUses: 1,
	}
}

func planFor(target domain.TargetID, ops ...domain.WriteOperation) domain.WritePlan {
	return domain.WritePlan{
		PlanID: "pln_test", SiteID: "filiale-001", TargetID: target,
		AssetID: "asset-danfoss-aksm800", Protocol: Protocol, Operations: ops,
		Reason: "test", RequestedBy: "vendor-acme",
		RequestedAt: testNow.Add(-time.Hour),
		WindowStart: testNow.Add(-time.Hour), WindowEnd: testNow.Add(time.Hour),
		State: domain.PlanApproved,
	}
}

func op(function, address, value string) domain.WriteOperation {
	return domain.WriteOperation{Protocol: Protocol, Function: function, Address: address, CurrentValue: "40", NewValue: value}
}

func newTestProxy(t *testing.T, auth SessionLookup, mutate func(*Config)) (*Proxy, *fakedev.Modbus) {
	return newTestProxyWithDevice(t, auth, mutate, nil)
}

func newTestProxyWithDevice(t *testing.T, auth SessionLookup, mutate func(*Config), mutateDevice func(*fakedev.ModbusConfig)) (*Proxy, *fakedev.Modbus) {
	t.Helper()
	deviceCfg := fakedev.ModbusConfig{}
	if mutateDevice != nil {
		mutateDevice(&deviceCfg)
	}
	device, err := fakedev.NewModbus(deviceCfg)
	if err != nil {
		t.Fatalf("fake device: %v", err)
	}
	if err := device.Start(); err != nil {
		t.Fatalf("fake device start: %v", err)
	}
	t.Cleanup(func() { _ = device.Close() })

	cfg := Config{
		TargetID:      "aksm-1",
		Listen:        "127.0.0.1:0",
		Upstream:      device.Addr(),
		UnitID:        1,
		Timeout:       2 * time.Second,
		IdleTimeout:   time.Minute,
		ReadRegisters: &RegisterRange{FC: FCReadHoldingRegisters, Start: 0, Count: 10},
		SourceCIDRs:   []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Clock:         fixedClock{at: testNow},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	proxy, err := New(cfg, auth)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := proxy.Start(context.Background()); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy, device
}

func dial(t *testing.T, proxy *Proxy) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxy.Addr(), time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// testADU encodes a client request for tests. The production proxy has no
// request encoder: it forwards validated client ADUs byte-identically.
func testADU(txID uint16, unit uint8, pdu []byte) []byte {
	out := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(out[0:2], txID)
	binary.BigEndian.PutUint16(out[4:6], uint16(1+len(pdu)))
	out[6] = unit
	copy(out[7:], pdu)
	return out
}

func sendPDU(t *testing.T, conn net.Conn, txID uint16, unit uint8, pdu []byte) []byte {
	t.Helper()
	adu := testADU(txID, unit, pdu)
	if _, err := conn.Write(adu); err != nil {
		t.Fatalf("write: %v", err)
	}
	return adu
}

func readPDU(t *testing.T, conn net.Conn) (uint16, []byte) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	f, err := readFrame(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return f.TransactionID, f.PDU
}

func fc6(addr, value uint16) []byte {
	return []byte{FCWriteSingleRegister, byte(addr >> 8), byte(addr), byte(value >> 8), byte(value)}
}

func fc3(addr, qty uint16) []byte {
	return []byte{FCReadHoldingRegisters, byte(addr >> 8), byte(addr), byte(qty >> 8), byte(qty)}
}

func fc22(addr, andMask, orMask uint16) []byte {
	return []byte{FCMaskWriteRegister, byte(addr >> 8), byte(addr), byte(andMask >> 8), byte(andMask), byte(orMask >> 8), byte(orMask)}
}

func fc23(readAddr, readQty, writeAddr, writeQty uint16, values []uint16) []byte {
	pdu := []byte{FCReadWriteRegisters,
		byte(readAddr >> 8), byte(readAddr), byte(readQty >> 8), byte(readQty),
		byte(writeAddr >> 8), byte(writeAddr), byte(writeQty >> 8), byte(writeQty),
		byte(2 * len(values)),
	}
	for _, value := range values {
		pdu = append(pdu, byte(value>>8), byte(value))
	}
	return pdu
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met")
}
