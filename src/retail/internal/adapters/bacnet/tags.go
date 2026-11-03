package bacnet

import (
	"encoding/binary"
	"fmt"
	"math"
)

// taggedValue is one decoded BACnet tag.
type taggedValue struct {
	number    uint8
	value     []byte
	opening   bool
	closing   bool
	appTag    uint8
	uintValue uint64
}

// scalar decodes an application value tag into a numeric or boolean value.
func (t taggedValue) scalar() (value float64, boolean, numeric, ok bool) {
	switch t.number {
	case appTagBoolean:
		if len(t.value) != 1 {
			return 0, false, false, false
		}
		return 0, t.value[0] != 0, false, true
	case appTagUnsigned, appTagEnumerated:
		if len(t.value) == 0 || len(t.value) > 4 {
			return 0, false, false, false
		}
		var raw uint32
		for _, b := range t.value {
			raw = raw<<8 | uint32(b)
		}
		return float64(raw), false, true, true
	case appTagSigned:
		if len(t.value) == 0 || len(t.value) > 4 {
			return 0, false, false, false
		}
		var raw int32
		for _, b := range t.value {
			raw = raw<<8 | int32(b)
		}
		// sign extend
		shift := uint(32 - 8*len(t.value))
		raw = raw << shift >> shift
		return float64(raw), false, true, true
	case appTagReal:
		if len(t.value) != 4 {
			return 0, false, false, false
		}
		f := math.Float32frombits(binary.BigEndian.Uint32(t.value))
		if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
			return 0, false, false, false
		}
		return float64(f), false, true, true
	case appTagDouble:
		if len(t.value) != 8 {
			return 0, false, false, false
		}
		f := math.Float64frombits(binary.BigEndian.Uint64(t.value))
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false, false, false
		}
		return f, false, true, true
	default:
		return 0, false, false, false
	}
}

// decodeAppTags walks a sequence of application-tagged values (I-Am body).
func decodeAppTags(data []byte) ([]taggedValue, error) {
	cursor := &tagCursor{data: data}
	out := make([]taggedValue, 0, 4)
	for cursor.remaining() > 0 {
		tag, ok := cursor.appTag()
		if !ok {
			return nil, fmt.Errorf("bacnet: malformed application tag")
		}
		out = append(out, tag)
		if len(out) > 16 {
			return nil, fmt.Errorf("bacnet: too many application tags")
		}
	}
	return out, nil
}

// tagCursor is a bounds-checked BACnet tag reader.
type tagCursor struct {
	data []byte
	off  int
}

func (c *tagCursor) remaining() int { return len(c.data) - c.off }

// rawTag reads one tag header and its payload.
func (c *tagCursor) rawTag() (taggedValue, bool) {
	if c.off >= len(c.data) {
		return taggedValue{}, false
	}
	first := c.data[c.off]
	number := first >> 4
	lvt := first & 0x0f
	c.off++
	switch {
	case lvt == 6:
		return taggedValue{number: number, opening: true}, true
	case lvt == 7:
		return taggedValue{number: number, closing: true}, true
	case lvt <= 4:
		length := int(lvt)
		if c.off+length > len(c.data) {
			return taggedValue{}, false
		}
		value := c.data[c.off : c.off+length]
		c.off += length
		return taggedValue{number: number, value: value}, true
	case lvt == 5:
		if c.off >= len(c.data) {
			return taggedValue{}, false
		}
		ext := c.data[c.off]
		c.off++
		var length int
		if ext == 254 {
			if c.off+2 > len(c.data) {
				return taggedValue{}, false
			}
			length = int(binary.BigEndian.Uint16(c.data[c.off : c.off+2]))
			c.off += 2
		} else {
			length = int(ext)
		}
		if length < 0 || c.off+length > len(c.data) {
			return taggedValue{}, false
		}
		value := c.data[c.off : c.off+length]
		c.off += length
		return taggedValue{number: number, value: value}, true
	default:
		return taggedValue{}, false
	}
}

// contextTag reads a context tag with the expected number and decodes an
// unsigned integer payload (object id, property id, array index).
func (c *tagCursor) contextTag(number uint8) (taggedValue, bool) {
	tag, ok := c.rawTag()
	if !ok || tag.opening || tag.closing || tag.number != number {
		return taggedValue{}, false
	}
	tag.uintValue = bigEndianUint(tag.value)
	return tag, true
}

// skipContextTag consumes an optional context tag with the given number. It
// peeks first so that a non-matching next tag (for example the application
// value tag) is not consumed.
func (c *tagCursor) skipContextTag(number uint8) bool {
	if c.off >= len(c.data) || c.data[c.off]>>4 != number {
		return false
	}
	tag, ok := c.contextTag(number)
	return ok && tag.number == number
}

// appTag reads one application value tag (all numbers are application tags).
func (c *tagCursor) appTag() (taggedValue, bool) {
	tag, ok := c.rawTag()
	if !ok || tag.opening || tag.closing {
		return taggedValue{}, false
	}
	tag.appTag = tag.number
	tag.uintValue = bigEndianUint(tag.value)
	return tag, true
}

func bigEndianUint(value []byte) uint64 {
	var out uint64
	for _, b := range value {
		out = out<<8 | uint64(b)
	}
	return out
}
