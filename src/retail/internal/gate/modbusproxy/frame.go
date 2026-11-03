// Package modbusproxy implements the Modbus/TCP enforcement proxy of the
// GeDefense Retail Access Gate.
//
// It terminates the vendor connection at the gate, checks every request against
// the default-deny matrix and forwards approved traffic to the controller over a
// gate-owned upstream connection. Reads are limited to the configured register
// window; writes (FC5/6/15/16/22/23) require an active, approved WriteSession
// whose plan matches the register AND value exactly. A denied write never
// reaches the controller: the proxy answers with a local Modbus exception and
// reports domain.DeniedWriteAttempt to the gate core.
package modbusproxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"time"
)

// Modbus function codes from the default-deny matrix (plan §4).
const (
	FCReadCoils              uint8 = 1
	FCReadDiscreteInputs     uint8 = 2
	FCReadHoldingRegisters   uint8 = 3
	FCReadInputRegisters     uint8 = 4
	FCWriteSingleCoil        uint8 = 5
	FCWriteSingleRegister    uint8 = 6
	FCReadExceptionStatus    uint8 = 7
	FCWriteMultipleCoils     uint8 = 15
	FCWriteMultipleRegisters uint8 = 16
	FCReportSlaveID          uint8 = 17
	FCMaskWriteRegister      uint8 = 22
	FCReadWriteRegisters     uint8 = 23
)

// Modbus exception codes used by the gate.
const (
	exIllegalFunction    uint8 = 0x01
	exIllegalDataAddress uint8 = 0x02
	exIllegalDataValue   uint8 = 0x03
	exServerFailure      uint8 = 0x04
	exGatewayTarget      uint8 = 0x0b
)

const (
	mbapHeaderLen = 7
	maxPDULen     = 253
	maxMBAPLength = 1 + maxPDULen // unit id + PDU
	minMBAPLength = 2
)

// ErrBadFrame is returned for structurally invalid MBAP/PDU data. The proxy
// closes the offending connection: a frame boundary that cannot be trusted must
// never be resynchronized into a write.
var ErrBadFrame = errors.New("modbusproxy: malformed frame")

// frame is one decoded MBAP/PDU unit. Raw holds the exact ADU bytes as they
// arrived: the proxy validates and forwards them byte-identically, it never
// re-encodes a request or response.
type frame struct {
	TransactionID uint16
	ProtocolID    uint16
	UnitID        uint8
	PDU           []byte
	Raw           []byte
}

func (f frame) function() uint8 {
	if len(f.PDU) == 0 {
		return 0
	}
	return f.PDU[0]
}

// isWriteFunction reports whether the function code may mutate the device.
func isWriteFunction(fc uint8) bool {
	switch fc {
	case FCWriteSingleCoil, FCWriteSingleRegister, FCWriteMultipleCoils,
		FCWriteMultipleRegisters, FCMaskWriteRegister, FCReadWriteRegisters:
		return true
	}
	return false
}

// isReadFunction reports whether the function code is allowed by the read
// policy (subject to the configured register window).
func isReadFunction(fc uint8) bool {
	switch fc {
	case FCReadCoils, FCReadDiscreteInputs, FCReadHoldingRegisters,
		FCReadInputRegisters, FCReadExceptionStatus, FCReportSlaveID:
		return true
	}
	return false
}

// functionName renders the stable plan/deny label of a function code.
func functionName(fc uint8) string { return "fc" + strconv.Itoa(int(fc)) }

// readFrame reads one complete MBAP frame. It handles TCP fragmentation because
// io.ReadFull is used for both the header and the announced body. Invalid
// protocol/length values are rejected instead of being resynchronized: the
// caller must close the connection (no second framing interpretation).
func readFrame(r *bufio.Reader) (frame, error) {
	header := make([]byte, 6)
	if _, err := io.ReadFull(r, header); err != nil {
		return frame{}, err
	}
	transactionID := binary.BigEndian.Uint16(header[0:2])
	protocolID := binary.BigEndian.Uint16(header[2:4])
	length := int(binary.BigEndian.Uint16(header[4:6]))
	if protocolID != 0 {
		return frame{}, fmt.Errorf("%w: protocol id %d", ErrBadFrame, protocolID)
	}
	// LEN counts unit id + PDU: 2..254 => total ADU 8..260 bytes.
	if length < minMBAPLength || length > maxMBAPLength {
		return frame{}, fmt.Errorf("%w: length %d out of range", ErrBadFrame, length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return frame{}, err
	}
	raw := make([]byte, 0, len(header)+len(body))
	raw = append(raw, header...)
	raw = append(raw, body...)
	return frame{
		TransactionID: transactionID,
		ProtocolID:    protocolID,
		UnitID:        body[0],
		PDU:           body[1:],
		Raw:           raw,
	}, nil
}

// exceptionADU builds a local exception response. This is the only ADU the
// proxy constructs itself; request and response ADUs are forwarded without
// modification.
func exceptionADU(transactionID uint16, unitID uint8, function, code uint8) []byte {
	return []byte{
		byte(transactionID >> 8), byte(transactionID),
		0, 0,
		0, 3,
		unitID,
		function | 0x80,
		code,
	}
}

// exceptionPDU builds a Modbus exception response PDU (local answer only).
func exceptionPDU(function, code uint8) []byte { return []byte{function | 0x80, code} }

// writeIntent is the canonical, plan-checkable form of one write PDU.
type writeIntent struct {
	Function uint8
	Ops      []writeOp
	// hasRead reports an embedded read part (FC23) that must also fit the read
	// window.
	hasRead  bool
	readFC   uint8
	readAddr uint16
	readQty  uint16
}

// writeOp is one canonical address/value pair a plan must contain.
type writeOp struct {
	Address string
	Value   string
}

// decodeWrite validates a write PDU and produces its canonical operations.
// Malformed PDUs are rejected before any authorization decision is made.
func decodeWrite(pdu []byte) (writeIntent, error) {
	if len(pdu) == 0 {
		return writeIntent{}, fmt.Errorf("%w: empty pdu", ErrBadFrame)
	}
	fc := pdu[0]
	intent := writeIntent{Function: fc}
	switch fc {
	case FCWriteSingleCoil:
		if len(pdu) != 5 {
			return writeIntent{}, fmt.Errorf("%w: fc5 pdu length %d", ErrBadFrame, len(pdu))
		}
		address := binary.BigEndian.Uint16(pdu[1:3])
		raw := binary.BigEndian.Uint16(pdu[3:5])
		var value string
		switch raw {
		case 0xff00:
			value = "1"
		case 0x0000:
			value = "0"
		default:
			return writeIntent{}, fmt.Errorf("%w: fc5 coil value 0x%04x", ErrBadFrame, raw)
		}
		intent.Ops = []writeOp{{Address: coilAddress(address), Value: value}}
	case FCWriteSingleRegister:
		if len(pdu) != 5 {
			return writeIntent{}, fmt.Errorf("%w: fc6 pdu length %d", ErrBadFrame, len(pdu))
		}
		address := binary.BigEndian.Uint16(pdu[1:3])
		value := binary.BigEndian.Uint16(pdu[3:5])
		intent.Ops = []writeOp{{Address: holdingAddress(address), Value: registerValue(value)}}
	case FCWriteMultipleCoils:
		qty, data, err := parseWriteMultiple(pdu, 1968)
		if err != nil {
			return writeIntent{}, err
		}
		address := binary.BigEndian.Uint16(pdu[1:3])
		intent.Ops = make([]writeOp, 0, qty)
		for i := 0; i < qty; i++ {
			bit := (data[i/8] >> (uint(i) % 8)) & 0x01
			intent.Ops = append(intent.Ops, writeOp{
				Address: coilAddress(address + uint16(i)),
				Value:   strconv.Itoa(int(bit)),
			})
		}
	case FCWriteMultipleRegisters:
		qty, data, err := parseWriteMultiple(pdu, 123)
		if err != nil {
			return writeIntent{}, err
		}
		address := binary.BigEndian.Uint16(pdu[1:3])
		intent.Ops = make([]writeOp, 0, qty)
		for i := 0; i < qty; i++ {
			value := binary.BigEndian.Uint16(data[i*2 : i*2+2])
			intent.Ops = append(intent.Ops, writeOp{
				Address: holdingAddress(address + uint16(i)),
				Value:   registerValue(value),
			})
		}
	case FCMaskWriteRegister:
		if len(pdu) != 7 {
			return writeIntent{}, fmt.Errorf("%w: fc22 pdu length %d", ErrBadFrame, len(pdu))
		}
		address := binary.BigEndian.Uint16(pdu[1:3])
		andMask := binary.BigEndian.Uint16(pdu[3:5])
		orMask := binary.BigEndian.Uint16(pdu[5:7])
		intent.Ops = []writeOp{{
			Address: holdingAddress(address),
			Value:   fmt.Sprintf("and=%d,or=%d", andMask, orMask),
		}}
	case FCReadWriteRegisters:
		return decodeReadWrite(pdu)
	default:
		return writeIntent{}, fmt.Errorf("%w: fc%d is not a write function", ErrBadFrame, fc)
	}
	return intent, nil
}

func parseWriteMultiple(pdu []byte, maxQty int) (int, []byte, error) {
	if len(pdu) < 6 {
		return 0, nil, fmt.Errorf("%w: write multiple pdu length %d", ErrBadFrame, len(pdu))
	}
	qty := int(binary.BigEndian.Uint16(pdu[3:5]))
	byteCount := int(pdu[5])
	if qty < 1 || qty > maxQty {
		return 0, nil, fmt.Errorf("%w: quantity %d", ErrBadFrame, qty)
	}
	if byteCount != len(pdu)-6 || byteCount < 1 {
		return 0, nil, fmt.Errorf("%w: byte count %d does not match pdu", ErrBadFrame, byteCount)
	}
	return qty, pdu[6:], nil
}

func decodeReadWrite(pdu []byte) (writeIntent, error) {
	// FC23: fc, readAddr, readQty, writeAddr, writeQty, byteCount, data
	if len(pdu) < 10 {
		return writeIntent{}, fmt.Errorf("%w: fc23 pdu length %d", ErrBadFrame, len(pdu))
	}
	readAddress := binary.BigEndian.Uint16(pdu[1:3])
	readQty := binary.BigEndian.Uint16(pdu[3:5])
	writeAddress := binary.BigEndian.Uint16(pdu[5:7])
	writeQty := int(binary.BigEndian.Uint16(pdu[7:9]))
	byteCount := int(pdu[9])
	if readQty < 1 || readQty > 125 {
		return writeIntent{}, fmt.Errorf("%w: fc23 read quantity %d", ErrBadFrame, readQty)
	}
	if writeQty < 1 || writeQty > 121 {
		return writeIntent{}, fmt.Errorf("%w: fc23 write quantity %d", ErrBadFrame, writeQty)
	}
	if byteCount != len(pdu)-10 || byteCount != 2*writeQty {
		return writeIntent{}, fmt.Errorf("%w: fc23 byte count %d", ErrBadFrame, byteCount)
	}
	intent := writeIntent{
		Function: FCReadWriteRegisters,
		hasRead:  true,
		readFC:   FCReadHoldingRegisters,
		readAddr: readAddress,
		readQty:  readQty,
	}
	intent.Ops = make([]writeOp, 0, writeQty)
	data := pdu[10:]
	for i := 0; i < writeQty; i++ {
		value := binary.BigEndian.Uint16(data[i*2 : i*2+2])
		intent.Ops = append(intent.Ops, writeOp{
			Address: holdingAddress(writeAddress + uint16(i)),
			Value:   registerValue(value),
		})
	}
	return intent, nil
}

// coilAddress renders the operator-facing coil number (1-based).
func coilAddress(address uint16) string { return strconv.Itoa(int(address) + 1) }

// holdingAddress renders the operator-facing holding register number (40001
// convention), matching the policy/plan examples in the gate contract.
func holdingAddress(address uint16) string { return strconv.Itoa(40001 + int(address)) }

// registerValue renders the wire value exactly as a plan must contain it.
// Scaling (for example 0.1 °C) belongs to the plan author, never to the proxy.
func registerValue(value uint16) string { return strconv.Itoa(int(value)) }

// primaryAddress returns the first canonical address (deny evidence only).
func (w writeIntent) primaryAddress() string {
	if len(w.Ops) == 0 {
		return "-"
	}
	return w.Ops[0].Address
}

// RegisterRange is the configured read window of a target. Only reads of the
// same function code inside [Start, Start+Count) are allowed.
type RegisterRange struct {
	FC    uint8
	Start uint16
	Count uint16
}

// Validate checks the read window.
func (r RegisterRange) Validate() error {
	switch r.FC {
	case FCReadCoils, FCReadDiscreteInputs, FCReadHoldingRegisters, FCReadInputRegisters:
	default:
		return fmt.Errorf("modbusproxy: read_registers fc %d is not a register read function", r.FC)
	}
	if r.Count == 0 {
		return errors.New("modbusproxy: read_registers count must be > 0")
	}
	return nil
}

// Contains reports whether a read request is fully inside the window.
func (r RegisterRange) Contains(fc uint8, start, count uint16) bool {
	if fc != r.FC || count == 0 {
		return false
	}
	end := int(start) + int(count)
	return int(start) >= int(r.Start) && end <= int(r.Start)+int(r.Count)
}

// readAllowed applies the read policy: CIDR already checked by the caller, plus
// the configured register window. Status reads (FC7/FC17) only require an
// existing read window because they do not address registers.
func readAllowed(window *RegisterRange, fc uint8, start, count uint16) bool {
	if window == nil {
		return false
	}
	switch fc {
	case FCReadExceptionStatus, FCReportSlaveID:
		return window.Validate() == nil
	default:
		return window.Contains(fc, start, count)
	}
}

// parseReadRange extracts the requested register window of a read PDU.
func parseReadRange(pdu []byte) (fc uint8, start, count uint16, ok bool) {
	if len(pdu) < 1 {
		return 0, 0, 0, false
	}
	fc = pdu[0]
	switch fc {
	case FCReadCoils, FCReadDiscreteInputs, FCReadHoldingRegisters, FCReadInputRegisters:
		if len(pdu) != 5 {
			return fc, 0, 0, false
		}
		return fc, binary.BigEndian.Uint16(pdu[1:3]), binary.BigEndian.Uint16(pdu[3:5]), true
	default:
		return fc, 0, 0, false
	}
}

// sourceAllowed reports whether the client IP is inside the configured source
// CIDRs. Empty configuration is a programming error and denies everything.
func sourceAllowed(prefixes []netip.Prefix, clientIP string) bool {
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// clampTimeout returns a bounded timeout.
func clampTimeout(value time.Duration, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	if value > 60*time.Second {
		return 60 * time.Second
	}
	return value
}
