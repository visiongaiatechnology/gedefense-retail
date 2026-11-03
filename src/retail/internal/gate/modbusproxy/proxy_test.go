package modbusproxy

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/fakedev"
)

func TestNullWriteNoUpstreamWriteADU(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sendPDU(t, conn, 7, 1, fc6(0, 35))
	txID, pdu := readPDU(t, conn)
	if txID != 7 {
		t.Fatalf("transaction id = %d", txID)
	}
	if len(pdu) != 2 || pdu[0] != 0x86 || pdu[1] != 0x01 {
		t.Fatalf("exception = %v", pdu)
	}
	state := device.State()
	if state.WriteADUs != 0 {
		t.Fatalf("NULL-WRITE VIOLATION: %d write ADU(s) reached the controller", state.WriteADUs)
	}
	if state.Connects != 0 {
		t.Fatalf("deny path opened %d upstream connection(s); authorization must precede dial", state.Connects)
	}
	if auth.denyCount() != 1 {
		t.Fatalf("deny count = %d", auth.denyCount())
	}
	deny := auth.lastDeny(t)
	if deny.Reason != ReasonNoSession || deny.Protocol != Protocol || deny.Function != "fc6" {
		t.Fatalf("deny = %+v", deny)
	}
	if err := deny.Validate(); err != nil {
		t.Fatalf("invalid deny evidence: %v", err)
	}
	if proxy.Stats().WritesDenied != 1 {
		t.Fatalf("stats = %+v", proxy.Stats())
	}
}

func TestManyDeniesNeverContactUpstream(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	for i := 0; i < 50; i++ {
		sendPDU(t, conn, uint16(i+1), 1, fc6(0, 35))
		_, pdu := readPDU(t, conn)
		if pdu[0] != 0x86 || pdu[1] != 0x01 {
			t.Fatalf("deny %d exception = %v", i, pdu)
		}
	}
	state := device.State()
	if state.Connects != 0 || state.WriteADUs != 0 {
		t.Fatalf("deny flood reached the controller: %+v", state)
	}
	if auth.denyCount() != 50 {
		t.Fatalf("deny evidence count = %d", auth.denyCount())
	}
}

func TestByteIdenticalForwarding(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan:    planFor("aksm-1", op("fc6", "40001", "35")),
	}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sent := sendPDU(t, conn, 42, 1, fc6(0, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != FCWriteSingleRegister {
		t.Fatalf("response = %v", pdu)
	}
	state := device.State()
	if !bytes.Equal(state.LastRequestRaw, sent) {
		t.Fatalf("ADU was re-encoded: sent %x got %x", sent, state.LastRequestRaw)
	}
}

func TestAllowedWriteForwardsToUpstream(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan:    planFor("aksm-1", op("fc6", "40001", "35")),
	}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sendPDU(t, conn, 9, 1, fc6(0, 35))
	_, pdu := readPDU(t, conn)
	if len(pdu) != 5 || pdu[0] != FCWriteSingleRegister {
		t.Fatalf("response = %v", pdu)
	}
	if got := device.State(); got.WriteADUs != 1 || got.Holding[0] != 35 {
		t.Fatalf("device state = %+v", got)
	}
	if auth.denyCount() != 0 {
		t.Fatalf("unexpected deny")
	}
	if auth.allowedCount() != 1 || auth.allowedOps[0].NewValue != "35" {
		t.Fatalf("allowed audit = %+v", auth.allowedOps)
	}
}

func TestWrongValueAndRegisterDenied(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan:    planFor("aksm-1", op("fc6", "40001", "35")),
	}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sendPDU(t, conn, 1, 1, fc6(0, 40))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x86 || pdu[1] != 0x02 {
		t.Fatalf("wrong value exception = %v", pdu)
	}
	if auth.lastDeny(t).Reason != ReasonValueMismatch {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	sendPDU(t, conn, 2, 1, fc6(1, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x86 || pdu[1] != 0x02 {
		t.Fatalf("wrong register exception = %v", pdu)
	}
	if auth.lastDeny(t).Reason != ReasonAddressMismatch {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	if got := device.State(); got.WriteADUs != 0 || got.Connects != 0 {
		t.Fatalf("deny reached the controller: %+v", got)
	}
}

func TestPlanNotApprovedDenied(t *testing.T) {
	t.Parallel()
	rejected := planFor("aksm-1", op("fc6", "40001", "35"))
	rejected.State = domain.PlanRejected
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan:    rejected,
	}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sendPDU(t, conn, 1, 1, fc6(0, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x86 || pdu[1] != 0x01 {
		t.Fatalf("rejected plan exception = %v", pdu)
	}
	if auth.lastDeny(t).Reason != ReasonNotApproved {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	if got := device.State(); got.WriteADUs != 0 || got.Connects != 0 {
		t.Fatalf("rejected plan reached the controller: %+v", got)
	}
}

func TestFC22AndFC23DeniedWithoutPlan(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sendPDU(t, conn, 1, 1, fc22(0, 0xff00, 0x00ff))
	if _, pdu := readPDU(t, conn); pdu[0] != FCMaskWriteRegister|0x80 || pdu[1] != 0x01 {
		t.Fatalf("fc22 exception = %v", pdu)
	}
	sendPDU(t, conn, 2, 1, fc23(0, 1, 0, 1, []uint16{35}))
	if _, pdu := readPDU(t, conn); pdu[0] != FCReadWriteRegisters|0x80 || pdu[1] != 0x01 {
		t.Fatalf("fc23 exception = %v", pdu)
	}
	if auth.denyCount() != 2 {
		t.Fatalf("deny count = %d", auth.denyCount())
	}
	if got := device.State(); got.WriteADUs != 0 || got.Connects != 0 {
		t.Fatalf("fc22/fc23 reached the controller: %+v", got)
	}
}

func TestUnitIDNotAllowlistedDeniedBeforeDial(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan:    planFor("aksm-1", op("fc6", "40001", "35")),
	}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sendPDU(t, conn, 1, 2, fc6(0, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x86 || pdu[1] != 0x01 {
		t.Fatalf("unit deny exception = %v", pdu)
	}
	if auth.lastDeny(t).Reason != ReasonWrongTarget {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	sendPDU(t, conn, 2, 2, fc3(0, 1))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x83 || pdu[1] != 0x02 {
		t.Fatalf("unit read exception = %v", pdu)
	}
	if got := device.State(); got.Connects != 0 || got.WriteADUs != 0 {
		t.Fatalf("unit deny reached the controller: %+v", got)
	}
}

func TestSessionExpiredAndWrongSource(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(-time.Minute)),
		plan:    planFor("aksm-1", op("fc6", "40001", "35")),
	}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sendPDU(t, conn, 1, 1, fc6(0, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x86 || pdu[1] != 0x01 {
		t.Fatalf("expired session exception = %v", pdu)
	}
	if auth.lastDeny(t).Reason != ReasonSessionExpired {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	auth.mu.Lock()
	auth.session = sessionFor("aksm-1", "10.9.9.9", testNow.Add(time.Hour))
	auth.mu.Unlock()
	sendPDU(t, conn, 2, 1, fc6(0, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x86 || pdu[1] != 0x01 {
		t.Fatalf("wrong source exception = %v", pdu)
	}
	if auth.lastDeny(t).Reason != ReasonWrongSource {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	if got := device.State(); got.WriteADUs != 0 || got.Connects != 0 {
		t.Fatalf("expired/wrong-source write reached the controller: %+v", got)
	}
}

func TestReadWindowEnforced(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true}
	proxy, _ := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sendPDU(t, conn, 1, 1, fc3(0, 5))
	if _, pdu := readPDU(t, conn); pdu[0] != FCReadHoldingRegisters || pdu[1] != 10 {
		t.Fatalf("read response = %v", pdu)
	}
	sendPDU(t, conn, 2, 1, fc3(50, 1))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x83 || pdu[1] != 0x02 {
		t.Fatalf("out-of-window exception = %v", pdu)
	}
	if proxy.Stats().ReadsDenied != 1 {
		t.Fatalf("stats = %+v", proxy.Stats())
	}
}

func TestCIDRDeniesEverything(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan:    planFor("aksm-1", op("fc6", "40001", "35")),
	}
	proxy, device := newTestProxy(t, auth, func(cfg *Config) {
		cfg.SourceCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	})
	conn := dial(t, proxy)
	sendPDU(t, conn, 1, 1, fc6(0, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x86 || pdu[1] != 0x01 {
		t.Fatalf("write from outside CIDR = %v", pdu)
	}
	if auth.lastDeny(t).Reason != ReasonWrongSource {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	sendPDU(t, conn, 2, 1, fc3(0, 1))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x83 || pdu[1] != 0x02 {
		t.Fatalf("read from outside CIDR = %v", pdu)
	}
	if got := device.State(); got.WriteADUs != 0 || got.Connects != 0 {
		t.Fatalf("outside-CIDR request reached the controller: %+v", got)
	}
}

func TestFragmentedAndPipelinedFrames(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true}
	proxy, _ := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	request := testADU(3, 1, fc3(0, 2))
	if _, err := conn.Write(request[:2]); err != nil {
		t.Fatalf("write fragment: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := conn.Write(request[2:]); err != nil {
		t.Fatalf("write rest: %v", err)
	}
	if txID, pdu := readPDU(t, conn); txID != 3 || pdu[0] != FCReadHoldingRegisters {
		t.Fatalf("fragmented response = %d %v", txID, pdu)
	}
	first := testADU(4, 1, fc3(0, 1))
	second := testADU(5, 1, fc3(1, 1))
	if _, err := conn.Write(append(first, second...)); err != nil {
		t.Fatalf("write pipelined: %v", err)
	}
	if txID, _ := readPDU(t, conn); txID != 4 {
		t.Fatalf("first pipelined tx = %d", txID)
	}
	if txID, _ := readPDU(t, conn); txID != 5 {
		t.Fatalf("second pipelined tx = %d", txID)
	}
}

func TestMalformedFrameClosesConnection(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	bad := []byte{0, 1, 0, 7, 0, 2, 1, 3}
	if _, err := conn.Write(bad); err != nil {
		t.Fatalf("write: %v", err)
	}
	buffer := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(buffer); err == nil {
		t.Fatal("connection was not closed after a malformed frame")
	}
	waitFor(t, time.Second, func() bool { return proxy.Stats().ParserErrors >= 1 })
	if got := device.State(); got.Connects != 0 || got.Requests != 0 {
		t.Fatalf("malformed frame reached the controller: %+v", got)
	}
}

func TestReadOnlyModeDeniesApprovedPlan(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan:    planFor("aksm-1", op("fc6", "40001", "35")),
	}
	proxy, device := newTestProxy(t, auth, func(cfg *Config) { cfg.ReadOnlyMode = true })
	conn := dial(t, proxy)
	sendPDU(t, conn, 1, 1, fc6(0, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x86 || pdu[1] != 0x01 {
		t.Fatalf("read-only exception = %v", pdu)
	}
	if auth.lastDeny(t).Reason != ReasonOperationNotApproved {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	if got := device.State(); got.WriteADUs != 0 || got.Connects != 0 {
		t.Fatalf("write reached the controller in read-only mode")
	}
}

func TestMultiRegisterWriteRequiresEveryOperation(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan: planFor("aksm-1",
			op("fc16", "40001", "35"),
			op("fc16", "40002", "40"),
		),
	}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	writeTwo := []byte{FCWriteMultipleRegisters, 0, 0, 0, 2, 4, 0, 35, 0, 40}
	sendPDU(t, conn, 1, 1, writeTwo)
	_, pdu := readPDU(t, conn)
	if got := device.State(); got.WriteADUs != 1 {
		t.Fatalf("approved multi-write did not reach the device: %+v", got)
	}
	if pdu[0] != FCWriteMultipleRegisters|0x80 {
		t.Fatalf("device response = %v", pdu)
	}
	if auth.allowedCount() != 2 {
		t.Fatalf("allowed ops = %d", auth.allowedCount())
	}
	auth.reset()
	bad := []byte{FCWriteMultipleRegisters, 0, 0, 0, 2, 4, 0, 35, 0, 41}
	sendPDU(t, conn, 2, 1, bad)
	if _, pdu := readPDU(t, conn); pdu[0] != 0x90 || pdu[1] != 0x02 {
		t.Fatalf("multi-write mismatch exception = %v", pdu)
	}
	if auth.lastDeny(t).Reason != ReasonValueMismatch {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	if got := device.State().WriteADUs; got != 1 {
		t.Fatalf("denied multi-write reached the device: %+v", got)
	}
}

func TestAuditFailureFailsClosed(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		allowedErr: errors.New("audit store full"),
		session:    sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan:       planFor("aksm-1", op("fc6", "40001", "35")),
	}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sendPDU(t, conn, 1, 1, fc6(0, 35))
	buffer := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(buffer); err == nil {
		t.Fatal("connection stayed open after the audit failure")
	}
	if auth.lastDeny(t).Reason != ReasonFailsafeStore {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	if got := device.State(); got.WriteADUs != 0 || got.Connects != 0 {
		t.Fatalf("write reached the controller although the audit failed")
	}
}

func TestWriteTimeoutReportsUnknownNoRetry(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan:    planFor("aksm-1", op("fc6", "40001", "35")),
	}
	proxy, device := newTestProxyWithDevice(t, auth,
		func(cfg *Config) { cfg.Timeout = 50 * time.Millisecond },
		func(cfg *fakedev.ModbusConfig) { cfg.ResponseDelay = 300 * time.Millisecond },
	)
	conn := dial(t, proxy)
	sendPDU(t, conn, 1, 1, fc6(0, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x86 || pdu[1] != 0x0b {
		t.Fatalf("upstream timeout exception = %v", pdu)
	}
	waitFor(t, time.Second, func() bool { return auth.unknownCount() >= 1 })
	state := device.State()
	if state.Requests != 1 || len(state.LastRequestRaw) < 8 || state.LastRequestRaw[7] != FCWriteSingleRegister {
		t.Fatalf("write was retried or not forwarded exactly once: %+v", state)
	}
}

func TestConcurrentWritesMaxUsesOne(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{
		consumeOK: false, consumeBudget: 1, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan:    planFor("aksm-1", op("fc6", "40001", "35")),
	}
	proxy, device := newTestProxy(t, auth, nil)
	first := dial(t, proxy)
	second := dial(t, proxy)
	results := make(chan []byte, 2)
	go func() { results <- writeAndRead(first, fc6(0, 35)) }()
	go func() { results <- writeAndRead(second, fc6(0, 35)) }()
	allowed, denied := 0, 0
	for i := 0; i < 2; i++ {
		pdu := <-results
		switch {
		case pdu == nil:
			t.Fatal("no response")
		case pdu[0] == FCWriteSingleRegister:
			allowed++
		case pdu[0] == 0x86 && pdu[1] == 0x01:
			denied++
		}
	}
	if allowed != 1 || denied != 1 {
		t.Fatalf("allowed=%d denied=%d (MaxUses=1 must allow exactly one)", allowed, denied)
	}
	if got := device.State().WriteADUs; got != 1 {
		t.Fatalf("write ADUs = %d, want 1", got)
	}
	if auth.denyCount() != 1 {
		t.Fatalf("deny evidence = %d", auth.denyCount())
	}
}
