package modbusproxy

import (
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/fakedev"
)

// readbackAuth builds an auth fixture with one approved fc6 plan for 40001.
func readbackAuth(current string) *fakeAuth {
	return &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan:    planFor("aksm-1", op("fc6", "40001", "35")),
	}
}

func withCurrent(op domain.WriteOperation, current string) domain.WriteOperation {
	op.CurrentValue = current
	return op
}

// TestReadbackMatchForwardsExactlyOneWrite: read == CurrentValue => the write is
// forwarded exactly once after the verification reads.
func TestReadbackMatchForwardsExactlyOneWrite(t *testing.T) {
	t.Parallel()
	auth := readbackAuth("40")
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sendPDU(t, conn, 21, 1, fc6(0, 35))
	_, pdu := readPDU(t, conn)
	if len(pdu) != 5 || pdu[0] != FCWriteSingleRegister {
		t.Fatalf("write response = %x", pdu)
	}
	state := device.State()
	if state.WriteADUs != 1 || state.Holding[0] != 35 {
		t.Fatalf("device state = %+v", state)
	}
	if auth.denyCount() != 0 {
		t.Fatalf("unexpected deny: %+v", auth.lastDeny(t))
	}
	if auth.allowedCount() != 1 {
		t.Fatalf("allowed audit = %d", auth.allowedCount())
	}
	if auth.consumeCalls != 1 {
		t.Fatalf("consume calls = %d, want 1 (after verification)", auth.consumeCalls)
	}
	if proxy.Stats().WritesAllowed != 1 {
		t.Fatalf("stats = %+v", proxy.Stats())
	}
}

// TestReadbackMismatchDenies: a drifted live value must deny the write with
// current_value_mismatch and never touch the controller with a write ADU.
func TestReadbackMismatchDenies(t *testing.T) {
	t.Parallel()
	auth := readbackAuth("40")
	proxy, device := newTestProxyWithDevice(t, auth, nil, func(cfg *fakedev.ModbusConfig) {
		cfg.Holding = []uint16{41, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	})
	conn := dial(t, proxy)
	sendPDU(t, conn, 22, 1, fc6(0, 35))
	_, pdu := readPDU(t, conn)
	if pdu[0] != 0x86 || pdu[1] != 0x04 {
		t.Fatalf("mismatch exception = %x, want 0x86 0x04", pdu)
	}
	deny := auth.lastDeny(t)
	if deny.Reason != ReasonCurrentValueMismatch {
		t.Fatalf("reason = %q", deny.Reason)
	}
	if deny.Severity != domain.SeverityCritical {
		t.Fatalf("severity = %q, want critical", deny.Severity)
	}
	if got := device.State(); got.WriteADUs != 0 {
		t.Fatalf("mismatch forwarded a write: %+v", got)
	}
	if auth.allowedCount() != 0 || auth.consumeCalls != 0 {
		t.Fatalf("consume/audit happened before verification: consume=%d allowed=%d", auth.consumeCalls, auth.allowedCount())
	}
}

// TestReadbackMissingCurrentValue: an operation without CurrentValue is denied.
func TestReadbackMissingCurrentValue(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan:    planFor("aksm-1", withCurrent(op("fc6", "40001", "35"), "")),
	}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sendPDU(t, conn, 23, 1, fc6(0, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x86 || pdu[1] != 0x04 {
		t.Fatalf("missing current value exception = %x", pdu)
	}
	if auth.lastDeny(t).Reason != ReasonCurrentValueMissing {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	if got := device.State(); got.WriteADUs != 0 {
		t.Fatalf("missing current value forwarded a write: %+v", got)
	}
}

// TestReadbackUnreadableOutsideWindow: an address outside the read window is
// unreadable and therefore denied before any upstream contact.
func TestReadbackUnreadableOutsideWindow(t *testing.T) {
	t.Parallel()
	auth := readbackAuth("40")
	proxy, device := newTestProxy(t, auth, func(cfg *Config) {
		cfg.ReadRegisters = &RegisterRange{FC: FCReadHoldingRegisters, Start: 5, Count: 5}
	})
	conn := dial(t, proxy)
	sendPDU(t, conn, 24, 1, fc6(0, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x86 || pdu[1] != 0x04 {
		t.Fatalf("unreadable exception = %x", pdu)
	}
	if auth.lastDeny(t).Reason != ReasonCurrentValueUnreadable {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	if got := device.State(); got.WriteADUs != 0 || got.Connects != 0 {
		t.Fatalf("unreadable path touched the controller: %+v", got)
	}
}

// TestReadbackCoilMatch: FC5 writes are verified with an FC1 coil read.
func TestReadbackCoilMatch(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan: planFor("aksm-1", domain.WriteOperation{
			Protocol: Protocol, Function: "fc5", Address: "1", CurrentValue: "1", NewValue: "0",
		}),
	}
	proxy, device := newTestProxyWithDevice(t, auth, func(cfg *Config) {
		cfg.ReadCoils = &RegisterRange{FC: FCReadCoils, Start: 0, Count: 8}
	}, func(cfg *fakedev.ModbusConfig) {
		cfg.Coils = []bool{true, false, false, false, false, false, false, false}
	})
	conn := dial(t, proxy)
	sendPDU(t, conn, 25, 1, []byte{FCWriteSingleCoil, 0, 0, 0x00, 0x00})
	if _, pdu := readPDU(t, conn); pdu[0] != FCWriteSingleCoil {
		t.Fatalf("coil write response = %x", pdu)
	}
	if got := device.State(); got.WriteADUs != 1 {
		t.Fatalf("coil write not forwarded: %+v", got)
	}
}
