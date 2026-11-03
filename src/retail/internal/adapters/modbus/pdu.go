// MBAP framing, read-request encoding and response decoding.
package modbus

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Modbus function codes used by the product.
const (
	fcReadHolding            uint8 = 3
	fcReadInput              uint8 = 4
	fcWriteSingleCoil        uint8 = 5
	fcWriteSingleRegister    uint8 = 6
	fcWriteMultipleCoils     uint8 = 15
	fcWriteMultipleRegisters uint8 = 16
)

const (
	mbapHeaderLen = 7
	maxPDUBytes   = 253
	maxFrameBytes = 6 + 1 + maxPDUBytes // MBAP length field counts unit id + PDU
	maxReadQty    = 125
)

// Errors of the MBAP parser. Callers use errors.Is; the parser never panics.
var (
	ErrBadMBAP      = errors.New("modbus: malformed mbap frame")
	errNeedMoreData = errors.New("modbus: need more data")
)

// Frame is one decoded MBAP unit.
type Frame struct {
	TransactionID uint16
	ProtocolID    uint16
	Length        uint16
	UnitID        uint8
	PDU           []byte
}

// decodeMBAP parses one complete frame from the front of buf. It returns the
// number of consumed bytes. errNeedMoreData means the buffer is incomplete and
// more bytes should be fed; any other error means the stream is not valid at
// the current offset and the caller must resynchronize.
func decodeMBAP(buf []byte) (Frame, int, error) {
	if len(buf) < 6 {
		return Frame{}, 0, errNeedMoreData
	}
	length := int(binary.BigEndian.Uint16(buf[4:6]))
	if length < 2 || length > 1+maxPDUBytes {
		return Frame{}, 0, fmt.Errorf("%w: length field %d out of range", ErrBadMBAP, length)
	}
	total := 6 + length
	if len(buf) < total {
		return Frame{}, 0, errNeedMoreData
	}
	if proto := binary.BigEndian.Uint16(buf[2:4]); proto != 0 {
		return Frame{}, 0, fmt.Errorf("%w: protocol id %d is not 0", ErrBadMBAP, proto)
	}
	if buf[6] == 0 && length == 2 {
		// Unit id 0 with an empty PDU cannot be a real request/response.
		return Frame{}, 0, fmt.Errorf("%w: empty pdu", ErrBadMBAP)
	}
	frame := Frame{
		TransactionID: binary.BigEndian.Uint16(buf[0:2]),
		ProtocolID:    0,
		Length:        uint16(length),
		UnitID:        buf[6],
		PDU:           buf[7:total],
	}
	return frame, total, nil
}

// encodeReadRequest builds an FC3/FC4 request. This is the ONLY request encoder
// in the package; there is intentionally no encoder for FC5/6/15/16.
func encodeReadRequest(transactionID uint16, unitID uint8, function uint8, address, quantity uint16) []byte {
	pdu := []byte{function, byte(address >> 8), byte(address), byte(quantity >> 8), byte(quantity)}
	out := make([]byte, mbapHeaderLen+len(pdu))
	binary.BigEndian.PutUint16(out[0:2], transactionID)
	binary.BigEndian.PutUint16(out[2:4], 0)
	binary.BigEndian.PutUint16(out[4:6], uint16(1+len(pdu)))
	out[6] = unitID
	copy(out[7:], pdu)
	return out
}

// readRequest is the passive view of an FC3/FC4 request.
type readRequest struct {
	Function uint8
	Address  uint16
	Quantity uint16
}

// parseReadRequest validates an FC3/FC4 request PDU (5 bytes).
func parseReadRequest(pdu []byte) (readRequest, error) {
	if len(pdu) != 5 {
		return readRequest{}, fmt.Errorf("%w: read request pdu length %d", ErrBadMBAP, len(pdu))
	}
	if !isReadFunction(pdu[0]) {
		return readRequest{}, fmt.Errorf("%w: not a read request (fc %d)", ErrBadMBAP, pdu[0])
	}
	req := readRequest{
		Function: pdu[0],
		Address:  binary.BigEndian.Uint16(pdu[1:3]),
		Quantity: binary.BigEndian.Uint16(pdu[3:5]),
	}
	if req.Quantity == 0 || req.Quantity > maxReadQty {
		return readRequest{}, fmt.Errorf("%w: quantity %d out of range", ErrBadMBAP, req.Quantity)
	}
	return req, nil
}

// parseReadResponse validates an FC3/FC4 response PDU and returns its register
// values. The caller correlates the transaction id with the request to know the
// addresses.
func parseReadResponse(pdu []byte) ([]uint16, error) {
	if len(pdu) < 4 {
		return nil, fmt.Errorf("%w: read response pdu length %d", ErrBadMBAP, len(pdu))
	}
	fc := pdu[0]
	if !isReadFunction(fc) {
		return nil, fmt.Errorf("%w: not a read response (fc %d)", ErrBadMBAP, fc)
	}
	byteCount := int(pdu[1])
	if byteCount == 0 || byteCount%2 != 0 || len(pdu) != 2+byteCount {
		return nil, fmt.Errorf("%w: response byte count %d does not match pdu length %d", ErrBadMBAP, byteCount, len(pdu))
	}
	values := make([]uint16, 0, byteCount/2)
	for i := 2; i+1 < len(pdu); i += 2 {
		values = append(values, binary.BigEndian.Uint16(pdu[i:i+2]))
	}
	if len(values) > maxReadQty {
		return nil, fmt.Errorf("%w: response carries %d registers", ErrBadMBAP, len(values))
	}
	return values, nil
}

// isReadResponseShape reports whether the PDU looks like an FC3/FC4 response
// (even, >= 4 bytes) rather than a 5-byte request. The shape check is needed
// because a passive stream does not always reveal the direction.
func isReadResponseShape(pdu []byte) bool {
	if len(pdu) < 4 || len(pdu) == 5 || len(pdu)%2 != 0 {
		return false
	}
	return int(pdu[1]) == len(pdu)-2
}

// exceptionFunction returns the function code of an error response and true.
func exceptionFunction(pdu []byte) (uint8, bool) {
	if len(pdu) == 2 && pdu[0]&0x80 != 0 {
		return pdu[0] & 0x7f, true
	}
	return 0, false
}

// writeRegisterAddress extracts the target address of an observed write PDU.
func writeRegisterAddress(fc uint8, pdu []byte) (uint16, bool) {
	switch fc {
	case fcWriteSingleCoil, fcWriteSingleRegister:
		if len(pdu) == 5 {
			return binary.BigEndian.Uint16(pdu[1:3]), true
		}
	case fcWriteMultipleCoils:
		if len(pdu) >= 6 {
			return binary.BigEndian.Uint16(pdu[1:3]), true
		}
	case fcWriteMultipleRegisters:
		if len(pdu) >= 6 {
			return binary.BigEndian.Uint16(pdu[1:3]), true
		}
	}
	return 0, false
}

// writeRegisterCount returns the number of registers/coils a write PDU targets.
func writeRegisterCount(fc uint8, pdu []byte) (uint16, bool) {
	switch fc {
	case fcWriteSingleCoil, fcWriteSingleRegister:
		return 1, true
	case fcWriteMultipleCoils, fcWriteMultipleRegisters:
		if len(pdu) >= 6 {
			return binary.BigEndian.Uint16(pdu[3:5]), true
		}
	}
	return 0, false
}
