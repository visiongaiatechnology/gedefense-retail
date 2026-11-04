package modbusproxy

import (
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/fakedev"
)

func fc16(addr uint16, values []uint16) []byte {
	pdu := []byte{FCWriteMultipleRegisters, byte(addr >> 8), byte(addr), byte(len(values) >> 8), byte(len(values)), byte(2 * len(values))}
	for _, value := range values {
		pdu = append(pdu, byte(value>>8), byte(value))
	}
	return pdu
}

// TestReadbackDecimalScale covers F-A8-01: display values 4.0 -> 3.5 with
// value_scale 0.1 map to raw register values 40 -> 35.
func TestReadbackDecimalScale(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan: planFor("aksm-1", domain.WriteOperation{
			Protocol: Protocol, Function: "fc6", Address: "40001",
			CurrentValue: "4.0", NewValue: "3.5", ValueScale: 0.1, Unit: "celsius",
		}),
	}
	proxy, device := newTestProxy(t, auth, nil)
	conn := dial(t, proxy)
	sendPDU(t, conn, 31, 1, fc6(0, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != FCWriteSingleRegister {
		t.Fatalf("decimal write response = %x", pdu)
	}
	if got := device.State(); got.WriteADUs != 1 || got.Holding[0] != 35 {
		t.Fatalf("decimal write state = %+v", got)
	}
}

// TestReadbackDecimalScaleMismatch: a drifted raw value denies the decimal write.
func TestReadbackDecimalScaleMismatch(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan: planFor("aksm-1", domain.WriteOperation{
			Protocol: Protocol, Function: "fc6", Address: "40001",
			CurrentValue: "4.0", NewValue: "3.5", ValueScale: 0.1,
		}),
	}
	proxy, device := newTestProxyWithDevice(t, auth, nil, func(cfg *fakedev.ModbusConfig) {
		cfg.Holding = []uint16{41, 0, 0, 0, 0, 0}
	})
	conn := dial(t, proxy)
	sendPDU(t, conn, 32, 1, fc6(0, 35))
	if _, pdu := readPDU(t, conn); pdu[0] != 0x86 || pdu[1] != 0x04 {
		t.Fatalf("decimal mismatch exception = %x", pdu)
	}
	if auth.lastDeny(t).Reason != ReasonCurrentValueMismatch {
		t.Fatalf("reason = %q", auth.lastDeny(t).Reason)
	}
	if got := device.State(); got.WriteADUs != 0 {
		t.Fatalf("decimal mismatch forwarded a write: %+v", got)
	}
}

// TestReadbackMultiOperationFC16 verifies every operation of a multi-register
// write against the device before forwarding exactly one FC16 ADU.
func TestReadbackMultiOperationFC16(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true, hasSession: true, hasPlan: true,
		session: sessionFor("aksm-1", "127.0.0.1", testNow.Add(time.Hour)),
		plan: planFor("aksm-1",
			domain.WriteOperation{OperationID: "a", Protocol: Protocol, Function: "fc16", Address: "40001",
				CurrentValue: "4.0", NewValue: "4.1", ValueScale: 0.1},
			domain.WriteOperation{OperationID: "b", Protocol: Protocol, Function: "fc16", Address: "40002",
				CurrentValue: "0.0", NewValue: "0.2", ValueScale: 0.1},
		),
	}
	proxy, device := newTestProxyWithDevice(t, auth, nil, func(cfg *fakedev.ModbusConfig) {
		cfg.Holding = []uint16{40, 0, 0, 0, 0, 0}
	})
	conn := dial(t, proxy)
	sendPDU(t, conn, 33, 1, fc16(0, []uint16{41, 2}))
	if _, pdu := readPDU(t, conn); pdu[0] != FCWriteMultipleRegisters {
		t.Fatalf("fc16 response = %x", pdu)
	}
	if got := device.State(); got.WriteADUs != 1 {
		t.Fatalf("fc16 not forwarded exactly once: %+v", got)
	}
	if auth.allowedCount() != 2 {
		t.Fatalf("allowed audit = %d, want 2", auth.allowedCount())
	}
}

// TestParseReadValueNegative covers F-A8-08: exception, short and partial read
// responses fail closed.
func TestParseReadValueNegative(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		pdu  []byte
		fc   uint8
	}{
		{"exception", []byte{0x83, 0x02}, FCReadHoldingRegisters},
		{"too short", []byte{0x03}, FCReadHoldingRegisters},
		{"empty payload", []byte{0x03, 0x00}, FCReadHoldingRegisters},
		{"short register payload", []byte{0x03, 0x02, 0x00}, FCReadHoldingRegisters},
		{"partial coil payload", []byte{0x01, 0x01}, FCReadCoils},
		{"wrong function", []byte{0x04, 0x02, 0x00, 0x28}, FCReadHoldingRegisters},
	}
	for _, tc := range cases {
		if _, err := parseReadValue(frame{PDU: tc.pdu}, tc.fc); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
	// A valid FC3 response parses to the raw register value.
	value, err := parseReadValue(frame{PDU: []byte{0x03, 0x02, 0x00, 0x28}}, FCReadHoldingRegisters)
	if err != nil || value != "40" {
		t.Fatalf("valid FC3 parse = %q err=%v", value, err)
	}
	// A valid FC1 response parses to 0/1.
	value, err = parseReadValue(frame{PDU: []byte{0x01, 0x01, 0x01}}, FCReadCoils)
	if err != nil || value != "1" {
		t.Fatalf("valid FC1 parse = %q err=%v", value, err)
	}
}

// TestRawValueScale covers the domain conversion edge cases.
func TestRawValueScale(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value string
		scale float64
		want  string
		ok    bool
	}{
		{"4.0", 0.1, "40", true},
		{"3.5", 0.1, "35", true},
		{"40", 0, "40", true},
		{"65535", 1, "65535", true},
		{"70000", 1, "", false},
		{"-1", 1, "", false},
		{"abc", 1, "", false},
		{"", 1, "", false},
	}
	for _, tc := range cases {
		got, ok := domain.ScaleToRaw(tc.value, tc.scale)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("ScaleToRaw(%q,%v) = %q,%v want %q,%v", tc.value, tc.scale, got, ok, tc.want, tc.ok)
		}
	}
	// FC22-style literal expression must not be treated as numeric.
	op := domain.WriteOperation{CurrentValue: "40", NewValue: "and=63487,or=32", ValueScale: 0}
	if _, ok := op.RawNewValue(); ok {
		t.Fatal("literal expression must not parse as numeric")
	}
	if raw, ok := op.RawCurrentValue(); !ok || raw != "40" {
		t.Fatalf("current raw = %q,%v", raw, ok)
	}
}
