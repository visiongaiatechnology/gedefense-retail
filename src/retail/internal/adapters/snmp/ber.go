// Minimal BER/DER subset for SNMP v1/v2c GET.
package snmp

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

// BER tags used by the SNMP subset.
const (
	tagInteger     byte = 0x02
	tagOctetString byte = 0x04
	tagNull        byte = 0x05
	tagOID         byte = 0x06
	tagSequence    byte = 0x30
	tagGetRequest  byte = 0xa0
	tagGetNext     byte = 0xa1
	tagResponse    byte = 0xa2
	tagSetRequest  byte = 0xa3
	tagCounter32   byte = 0x41
	tagGauge32     byte = 0x42
	tagTimeTicks   byte = 0x43
	tagCounter64   byte = 0x46
)

// errMalformed is returned for any invalid BER structure.
var errMalformed = fmt.Errorf("snmp: malformed ber")

// encodeTLV writes a BER tag-length-value.
func encodeTLV(tag byte, content []byte) []byte {
	length := encodeLength(len(content))
	out := make([]byte, 0, 1+len(length)+len(content))
	out = append(out, tag)
	out = append(out, length...)
	out = append(out, content...)
	return out
}

// encodeLength encodes a BER definite length (short or long form).
func encodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp [8]byte
	pos := len(tmp)
	for v := n; v > 0; v >>= 8 {
		pos--
		tmp[pos] = byte(v)
	}
	content := tmp[pos:]
	out := make([]byte, 0, 1+len(content))
	out = append(out, 0x80|byte(len(content)))
	out = append(out, content...)
	return out
}

// encodeInteger encodes a signed number with the minimal two's-complement
// representation required by BER.
func encodeInteger(value int64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(value))
	start := 0
	// Trim redundant leading sign bytes.
	for start < 7 {
		next := raw[start+1]
		if raw[start] == 0x00 && next&0x80 == 0 {
			start++
			continue
		}
		if raw[start] == 0xff && next&0x80 != 0 {
			start++
			continue
		}
		break
	}
	return encodeTLV(tagInteger, raw[start:])
}

// encodeOctetString encodes a byte string.
func encodeOctetString(value string) []byte {
	return encodeTLV(tagOctetString, []byte(value))
}

// encodeNull encodes the ASN.1 NULL value.
func encodeNull() []byte { return []byte{tagNull, 0x00} }

// encodeSequence wraps BER elements into a sequence.
func encodeSequence(parts ...[]byte) []byte {
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	content := make([]byte, 0, size)
	for _, part := range parts {
		content = append(content, part...)
	}
	return encodeTLV(tagSequence, content)
}

// encodeOID encodes a numeric dotted object identifier.
func encodeOID(oid string) ([]byte, error) {
	arcs := splitDot(oid)
	if len(arcs) < 2 {
		return nil, fmt.Errorf("snmp: oid %q needs at least two arcs", oid)
	}
	first, err := strconv.ParseUint(arcs[0], 10, 32)
	if err != nil || first > 2 {
		return nil, fmt.Errorf("snmp: invalid first oid arc")
	}
	second, err := strconv.ParseUint(arcs[1], 10, 32)
	if err != nil || second > 39 {
		return nil, fmt.Errorf("snmp: invalid second oid arc")
	}
	content := make([]byte, 0, len(oid))
	content = appendBase128(content, uint64(first*40+second))
	for _, arc := range arcs[2:] {
		value, err := strconv.ParseUint(arc, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("snmp: invalid oid arc %q", arc)
		}
		content = appendBase128(content, value)
	}
	return encodeTLV(tagOID, content), nil
}

func appendBase128(out []byte, value uint64) []byte {
	var tmp [10]byte
	pos := len(tmp)
	pos--
	tmp[pos] = byte(value & 0x7f)
	value >>= 7
	for value > 0 {
		pos--
		tmp[pos] = byte(value&0x7f) | 0x80
		value >>= 7
	}
	return append(out, tmp[pos:]...)
}

// element is one parsed BER TLV.
type element struct {
	tag     byte
	content []byte
}

// readElement parses one TLV at offset.
func readElement(data []byte, offset int) (element, int, error) {
	if offset < 0 || offset+2 > len(data) {
		return element{}, 0, errMalformed
	}
	tag := data[offset]
	lengthByte := data[offset+1]
	offset += 2
	length := 0
	if lengthByte&0x80 == 0 {
		length = int(lengthByte)
	} else {
		count := int(lengthByte & 0x7f)
		if count == 0 || count > 4 || offset+count > len(data) {
			return element{}, 0, errMalformed
		}
		for i := 0; i < count; i++ {
			length = length<<8 | int(data[offset])
			offset++
		}
	}
	if length < 0 || offset+length > len(data) {
		return element{}, 0, errMalformed
	}
	return element{tag: tag, content: data[offset : offset+length]}, offset + length, nil
}

// decodeOIDContent converts OID content bytes into dotted notation.
func decodeOIDContent(content []byte) (string, error) {
	if len(content) == 0 {
		return "", errMalformed
	}
	arcs := make([]uint64, 0, 8)
	var value uint64
	inArc := false
	for _, b := range content {
		if !inArc && b == 0x80 {
			return "", errMalformed
		}
		value = value<<7 | uint64(b&0x7f)
		inArc = true
		if b&0x80 == 0 {
			arcs = append(arcs, value)
			value = 0
			inArc = false
		}
		if len(arcs) > 32 {
			return "", errMalformed
		}
	}
	if inArc || len(arcs) == 0 {
		return "", errMalformed
	}
	first := arcs[0]
	var out []byte
	if first < 40 {
		out = append(out, '0', '.', byte('0'+first))
	} else if first < 80 {
		out = append(out, '1', '.', byte('0'+first-40))
	} else {
		out = append(out, '2', '.')
		out = strconv.AppendUint(out, first-80, 10)
	}
	for _, arc := range arcs[1:] {
		out = append(out, '.')
		out = strconv.AppendUint(out, arc, 10)
	}
	return string(out), nil
}
