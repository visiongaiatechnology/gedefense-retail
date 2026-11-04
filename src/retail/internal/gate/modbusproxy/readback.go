// Read-before-write verification for Modbus writes.
//
// Every approved write is checked against the live device value before any byte
// is forwarded: the proxy reads the target register/coil once (FC3/FC1) and
// compares it with domain.WriteOperation.CurrentValue (converted to the wire
// value via value_scale). This reduces the TOCTOU window to the interval between
// the verification read and the forwarded write on the same serialized upstream
// connection; that residual window is documented and cannot be closed by the
// Modbus protocol itself.
package modbusproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// readFunctionFor maps a write function to the register/coil read used for the
// read-before-write check. Unknown functions fail closed.
func readFunctionFor(writeFC uint8) (uint8, bool) {
	switch writeFC {
	case FCWriteSingleRegister, FCWriteMultipleRegisters, FCMaskWriteRegister, FCReadWriteRegisters:
		return FCReadHoldingRegisters, true
	case FCWriteSingleCoil, FCWriteMultipleCoils:
		return FCReadCoils, true
	default:
		return 0, false
	}
}

// rawAddress converts an operator-facing address into the wire address:
// holding registers use 40001+n, coils use n+1 (see frame.go).
func rawAddress(address string, readFC uint8) (uint16, bool) {
	value, err := strconv.Atoi(strings.TrimSpace(address))
	if err != nil {
		return 0, false
	}
	switch readFC {
	case FCReadHoldingRegisters:
		raw := value - 40001
		if raw < 0 || raw > 65535 {
			return 0, false
		}
		return uint16(raw), true
	case FCReadCoils:
		raw := value - 1
		if raw < 0 || raw > 65535 {
			return 0, false
		}
		return uint16(raw), true
	default:
		return 0, false
	}
}

// canonicalCurrentValue normalizes the approved display current value to the
// wire representation via value_scale (plain integer, coils 0/1). An absent,
// unparsable or out-of-range value is a hard deny, never a wildcard.
func canonicalCurrentValue(op domain.WriteOperation, readFC uint8) (string, bool) {
	raw, ok := op.RawCurrentValue()
	if !ok {
		return "", false
	}
	if readFC == FCReadCoils && raw != "0" && raw != "1" {
		return "", false
	}
	return raw, true
}

// readFrame builds a one-register/one-coil read request frame.
func readFrameFor(transactionID uint16, unitID, fc uint8, start uint16) frame {
	pdu := []byte{fc, byte(start >> 8), byte(start), 0, 1}
	raw := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(raw[0:2], transactionID)
	binary.BigEndian.PutUint16(raw[2:4], 0)
	binary.BigEndian.PutUint16(raw[4:6], uint16(1+len(pdu)))
	raw[6] = unitID
	copy(raw[7:], pdu)
	return frame{TransactionID: transactionID, UnitID: unitID, PDU: pdu, Raw: raw}
}

// parseReadValue extracts the single value from a read response. Exceptions and
// malformed PDUs are errors (fail-closed).
func parseReadValue(f frame, fc uint8) (string, error) {
	if len(f.PDU) < 2 {
		return "", fmt.Errorf("readback: short pdu")
	}
	if f.PDU[0] == fc|0x80 {
		return "", fmt.Errorf("readback: exception 0x%02x", f.PDU[1])
	}
	if f.PDU[0] != fc {
		return "", fmt.Errorf("readback: unexpected function 0x%02x", f.PDU[0])
	}
	if f.PDU[1] == 0 {
		return "", fmt.Errorf("readback: empty payload")
	}
	if fc == FCReadHoldingRegisters {
		if int(f.PDU[1]) != 2 || len(f.PDU) < 4 {
			return "", fmt.Errorf("readback: invalid byte count %d", f.PDU[1])
		}
		return strconv.Itoa(int(binary.BigEndian.Uint16(f.PDU[2:4]))), nil
	}
	if fc == FCReadCoils {
		if int(f.PDU[1]) != 1 || len(f.PDU) < 3 {
			return "", fmt.Errorf("readback: invalid byte count %d", f.PDU[1])
		}
		return strconv.Itoa(int(f.PDU[2] & 0x01)), nil
	}
	return "", fmt.Errorf("readback: unsupported read function 0x%02x", fc)
}

// readCurrentValue performs one read on the gate-owned upstream connection.
func (p *Proxy) readCurrentValue(ctx context.Context, up **upstream, unitID, fc uint8, start uint16) (string, error) {
	window := p.cfg.ReadRegisters
	if fc == FCReadCoils {
		window = p.cfg.ReadCoils
	}
	if !readAllowed(window, fc, start, 1) {
		return "", fmt.Errorf("readback: address %d is outside the configured read window", start)
	}
	request := readFrameFor(p.nextTransactionID(), unitID, fc, start)
	raw, err := p.transact(ctx, up, request)
	if err != nil {
		return "", err
	}
	parsed, err := readFrame(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return "", fmt.Errorf("readback: parse response: %w", err)
	}
	return parseReadValue(parsed, fc)
}

// verifyCurrentValues reads and compares every matched operation. It returns a
// deny reason/exception on failure; nothing has been forwarded at that point.
func (p *Proxy) verifyCurrentValues(ctx context.Context, up **upstream, unitID uint8, decision writeDecision) (string, uint8) {
	for _, op := range decision.ops {
		readFC, ok := readFunctionFor(decideWriteFC(op.Function))
		if !ok {
			return ReasonCurrentValueUnreadable, exServerFailure
		}
		expected, ok := canonicalCurrentValue(op, readFC)
		if !ok {
			return ReasonCurrentValueMissing, exServerFailure
		}
		start, ok := rawAddress(op.Address, readFC)
		if !ok {
			return ReasonCurrentValueUnreadable, exServerFailure
		}
		actual, err := p.readCurrentValue(ctx, up, unitID, readFC, start)
		if err != nil {
			p.recordError("readback: " + err.Error())
			return ReasonCurrentValueUnreadable, exServerFailure
		}
		if actual != expected {
			return ReasonCurrentValueMismatch, exServerFailure
		}
	}
	return "", 0
}

// decideWriteFC maps the plan function label back to a function code.
func decideWriteFC(function string) uint8 {
	switch function {
	case "fc5":
		return FCWriteSingleCoil
	case "fc6":
		return FCWriteSingleRegister
	case "fc15":
		return FCWriteMultipleCoils
	case "fc16":
		return FCWriteMultipleRegisters
	case "fc22":
		return FCMaskWriteRegister
	case "fc23":
		return FCReadWriteRegisters
	default:
		return 0
	}
}

// nextTransactionID returns a fresh transaction id for gate-originated reads.
func (p *Proxy) nextTransactionID() uint16 {
	return uint16(p.readTxn.Add(1))
}
