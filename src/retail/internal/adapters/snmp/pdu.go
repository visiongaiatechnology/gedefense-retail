// SNMP GET request encoding and response parsing.
package snmp

import (
	"fmt"
	"math"
	"strconv"
)

// varbind is one decoded response value.
type varbind struct {
	OID     string
	value   float64
	numeric bool
}

// response is the decoded SNMP response PDU.
type response struct {
	version     int
	requestID   int32
	errorStatus int
	errorIndex  int
	varbinds    []varbind
}

// buildGetRequest encodes the ONLY request PDU this package can produce: an
// SNMP GetRequest (0xA0). There is no SET or GETBULK/WALK encoder in the
// package, by construction.
func buildGetRequest(version int, community string, requestID int32, oids []string) ([]byte, error) {
	if len(oids) == 0 {
		return nil, fmt.Errorf("snmp: get request without oids")
	}
	varbinds := make([][]byte, 0, len(oids))
	for _, oid := range oids {
		encoded, err := encodeOID(oid)
		if err != nil {
			return nil, err
		}
		varbinds = append(varbinds, encodeSequence(encoded, encodeNull()))
	}
	pdu := encodeTLV(tagGetRequest, concat(
		encodeInteger(int64(requestID)),
		encodeInteger(0), // error-status
		encodeInteger(0), // error-index
		encodeSequence(varbinds...),
	))
	return encodeSequence(
		encodeInteger(int64(version)),
		encodeOctetString(community),
		pdu,
	), nil
}

func concat(parts ...[]byte) []byte {
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	out := make([]byte, 0, size)
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

// parseResponse decodes an SNMP response datagram. The community string is
// validated only for structural presence and is never stored.
func parseResponse(packet []byte) (response, error) {
	root, next, err := readElement(packet, 0)
	if err != nil || root.tag != tagSequence {
		return response{}, fmt.Errorf("%w: message is not a sequence", errMalformed)
	}
	if next != len(packet) {
		return response{}, fmt.Errorf("%w: trailing data after message", errMalformed)
	}
	offset := 0
	versionElem, offset, err := readElement(root.content, offset)
	if err != nil || versionElem.tag != tagInteger {
		return response{}, fmt.Errorf("%w: missing version", errMalformed)
	}
	version, ok := decodeInt32(versionElem.content)
	if !ok || version < 0 || version > 1 {
		return response{}, fmt.Errorf("%w: unsupported version", errMalformed)
	}
	communityElem, offset, err := readElement(root.content, offset)
	if err != nil || communityElem.tag != tagOctetString {
		return response{}, fmt.Errorf("%w: missing community", errMalformed)
	}
	pduElem, offset, err := readElement(root.content, offset)
	if err != nil || pduElem.tag != tagResponse {
		return response{}, fmt.Errorf("%w: not a get response", errMalformed)
	}
	_ = offset
	resp := response{version: int(version)}
	pduOffset := 0
	requestIDElem, pduOffset, err := readElement(pduElem.content, pduOffset)
	if err != nil || requestIDElem.tag != tagInteger {
		return response{}, fmt.Errorf("%w: missing request id", errMalformed)
	}
	requestID, ok := decodeInt32(requestIDElem.content)
	if !ok {
		return response{}, fmt.Errorf("%w: invalid request id", errMalformed)
	}
	resp.requestID = requestID
	statusElem, pduOffset, err := readElement(pduElem.content, pduOffset)
	if err != nil || statusElem.tag != tagInteger {
		return response{}, fmt.Errorf("%w: missing error status", errMalformed)
	}
	status, ok := decodeInt32(statusElem.content)
	if !ok {
		return response{}, fmt.Errorf("%w: invalid error status", errMalformed)
	}
	resp.errorStatus = int(status)
	indexElem, pduOffset, err := readElement(pduElem.content, pduOffset)
	if err != nil || indexElem.tag != tagInteger {
		return response{}, fmt.Errorf("%w: missing error index", errMalformed)
	}
	index, ok := decodeInt32(indexElem.content)
	if !ok {
		return response{}, fmt.Errorf("%w: invalid error index", errMalformed)
	}
	resp.errorIndex = int(index)
	listElem, pduOffset, err := readElement(pduElem.content, pduOffset)
	if err != nil || listElem.tag != tagSequence {
		return response{}, fmt.Errorf("%w: missing varbind list", errMalformed)
	}
	_ = pduOffset
	varbinds, err := parseVarbinds(listElem.content)
	if err != nil {
		return response{}, err
	}
	resp.varbinds = varbinds
	return resp, nil
}

func parseVarbinds(content []byte) ([]varbind, error) {
	out := make([]varbind, 0, 4)
	offset := 0
	for offset < len(content) {
		seq, next, err := readElement(content, offset)
		if err != nil || seq.tag != tagSequence {
			return nil, fmt.Errorf("%w: invalid varbind", errMalformed)
		}
		offset = next
		position := 0
		oidElem, position, err := readElement(seq.content, position)
		if err != nil || oidElem.tag != tagOID {
			return nil, fmt.Errorf("%w: varbind without oid", errMalformed)
		}
		oid, err := decodeOIDContent(oidElem.content)
		if err != nil {
			return nil, err
		}
		valueElem, _, err := readElement(seq.content, position)
		if err != nil {
			return nil, fmt.Errorf("%w: varbind without value", errMalformed)
		}
		value, numeric, err := decodeSNMPValue(valueElem)
		if err != nil {
			return nil, err
		}
		out = append(out, varbind{OID: oid, value: value, numeric: numeric})
		if len(out) > maxOIDs*2 {
			return nil, fmt.Errorf("%w: too many varbinds", errMalformed)
		}
	}
	return out, nil
}

// decodeSNMPValue decodes the scalar types used by infrastructure agents.
func decodeSNMPValue(elem element) (float64, bool, error) {
	switch elem.tag {
	case tagInteger:
		value, ok := decodeInt32(elem.content)
		if !ok {
			return 0, false, fmt.Errorf("%w: invalid integer", errMalformed)
		}
		return float64(value), true, nil
	case tagCounter32, tagGauge32, tagTimeTicks:
		if len(elem.content) == 0 || len(elem.content) > 4 {
			return 0, false, fmt.Errorf("%w: invalid unsigned", errMalformed)
		}
		var raw uint32
		for _, b := range elem.content {
			raw = raw<<8 | uint32(b)
		}
		return float64(raw), true, nil
	case tagCounter64:
		if len(elem.content) == 0 || len(elem.content) > 8 {
			return 0, false, fmt.Errorf("%w: invalid counter64", errMalformed)
		}
		var raw uint64
		for _, b := range elem.content {
			raw = raw<<8 | uint64(b)
		}
		f := float64(raw)
		if math.IsInf(f, 0) {
			return 0, false, nil
		}
		return f, true, nil
	case tagOctetString:
		// Some agents expose numeric values as decimal text.
		if len(elem.content) == 0 || len(elem.content) > 64 {
			return 0, false, nil
		}
		parsed, err := strconv.ParseFloat(string(elem.content), 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return 0, false, nil
		}
		return parsed, true, nil
	default:
		// OID, Null, IpAddress, opaque types are valid but not telemetry.
		return 0, false, nil
	}
}

func decodeInt32(content []byte) (int32, bool) {
	if len(content) == 0 || len(content) > 4 {
		return 0, false
	}
	var raw int32
	for _, b := range content {
		raw = raw<<8 | int32(b)
	}
	shift := uint(32 - 8*len(content))
	raw = raw << shift >> shift
	return raw, true
}
