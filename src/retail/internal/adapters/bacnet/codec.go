// BACnet/IP buffer decoding (BVLC, NPDU, APDU) into passive observations.
package bacnet

import (
	"encoding/binary"
	"fmt"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// BVLC function codes accepted by the passive decoder.
const (
	bvlcForwardedNPDU     byte = 0x04
	bvlcOriginalUnicast   byte = 0x0a
	bvlcOriginalBroadcast byte = 0x0b
)

// APDU types.
const (
	apduConfirmedRequest   byte = 0x0
	apduUnconfirmedRequest byte = 0x1
	apduComplexAck         byte = 0x3
)

// BACnet service choices relevant to the product.
const (
	serviceIAm                   byte = 0
	serviceAtomicWriteFile       byte = 7
	serviceAddListElement        byte = 8
	serviceRemoveListElement     byte = 9
	serviceCreateObject          byte = 10
	serviceDeleteObject          byte = 11
	serviceReadProperty          byte = 12
	serviceWriteProperty         byte = 15
	serviceWritePropertyMultiple byte = 16
)

// Application tag numbers used by the decoder.
const (
	appTagNull       uint8 = 0
	appTagBoolean    uint8 = 1
	appTagUnsigned   uint8 = 2
	appTagSigned     uint8 = 3
	appTagReal       uint8 = 4
	appTagDouble     uint8 = 5
	appTagEnumerated uint8 = 9
	appTagObjectID   uint8 = 12
)

// maxObjectID bounds the object identifier to the BACnet 22-bit instance.
const maxObjectID = 0x3fffff

// DecoderOptions configures the passive decoder.
type DecoderOptions struct {
	Meta     collect.Meta
	Mappings []ObjectMapping
}

// Decoder decodes BACnet/IP datagrams into events. It is stateless with respect
// to the wire (one instance may serve many peers).
type Decoder struct {
	opts     DecoderOptions
	counters collect.Counters
}

// NewDecoder creates the decoder and validates its provenance.
func NewDecoder(opts DecoderOptions) (*Decoder, error) {
	if err := opts.Meta.Validate(); err != nil {
		return nil, fmt.Errorf("bacnet: %w", err)
	}
	return &Decoder{opts: opts}, nil
}

// HealthCounters exposes parser/unsupported counters.
func (d *Decoder) HealthCounters() collect.CounterSnapshot { return d.counters.HealthCounters() }

// message is one passive observation decoded from a datagram.
type message struct {
	kind           uint8 // msgIAm, msgReadPropertyAck, msgWriteAttempt
	deviceInstance uint32
	vendorID       uint32
	objectType     uint8
	objectInstance uint32
	property       uint8
	value          float64
	boolean        bool
	numeric        bool
	serviceName    string
}

const (
	msgIAm uint8 = iota + 1
	msgReadPropertyAck
	msgWriteAttempt
)

// Feed decodes one datagram and returns the events that the observation
// supports. Malformed frames are counted, never fatal.
func (d *Decoder) Feed(remoteIP string, datagram []byte) []domain.Event {
	if len(datagram) < 4 {
		d.counters.IncParserError("datagram too short")
		return nil
	}
	npdu, err := decodeBVLC(datagram)
	if err != nil {
		// A non-BACnet UDP datagram on the feed port is not necessarily an error.
		d.counters.IncParserError(err.Error())
		return nil
	}
	apdu, err := decodeNPDU(npdu)
	if err != nil {
		d.counters.IncParserError(err.Error())
		return nil
	}
	msg, err := decodeAPDU(apdu)
	if err != nil {
		d.counters.IncParserError(err.Error())
		return nil
	}
	if msg == nil {
		return nil
	}
	return d.eventsFor(remoteIP, *msg)
}

func decodeBVLC(datagram []byte) ([]byte, error) {
	if datagram[0] != 0x81 {
		return nil, fmt.Errorf("bacnet: not a BVLC frame (0x%02x)", datagram[0])
	}
	if len(datagram) < 4 {
		return nil, fmt.Errorf("bacnet: short BVLC header")
	}
	switch datagram[1] {
	case bvlcForwardedNPDU, bvlcOriginalUnicast, bvlcOriginalBroadcast:
	default:
		return nil, fmt.Errorf("bacnet: unsupported BVLC function 0x%02x", datagram[1])
	}
	length := int(binary.BigEndian.Uint16(datagram[2:4]))
	if length < 4 || length > len(datagram) {
		return nil, fmt.Errorf("bacnet: invalid BVLC length %d", length)
	}
	return datagram[4:length], nil
}

func decodeNPDU(npdu []byte) ([]byte, error) {
	if len(npdu) < 2 {
		return nil, fmt.Errorf("bacnet: short NPDU")
	}
	if npdu[0] != 0x01 {
		return nil, fmt.Errorf("bacnet: unsupported NPDU version %d", npdu[0])
	}
	control := npdu[1]
	if control&0x20 != 0 {
		return nil, fmt.Errorf("bacnet: network layer message not interpreted")
	}
	offset := 2
	if control&0x08 != 0 { // destination specifier
		if offset+3 > len(npdu) {
			return nil, fmt.Errorf("bacnet: short destination specifier")
		}
		dlen := int(npdu[offset+2])
		offset += 3 + dlen + 1 // DNET + DLEN + DADR + hop count
		if offset > len(npdu) {
			return nil, fmt.Errorf("bacnet: destination specifier out of range")
		}
	}
	if control&0x02 != 0 { // source specifier
		if offset+3 > len(npdu) {
			return nil, fmt.Errorf("bacnet: short source specifier")
		}
		slen := int(npdu[offset+2])
		offset += 3 + slen
		if offset > len(npdu) {
			return nil, fmt.Errorf("bacnet: source specifier out of range")
		}
	}
	if offset >= len(npdu) {
		return nil, fmt.Errorf("bacnet: missing APDU")
	}
	return npdu[offset:], nil
}

func decodeAPDU(apdu []byte) (*message, error) {
	if len(apdu) < 2 {
		return nil, fmt.Errorf("bacnet: short APDU")
	}
	switch apdu[0] >> 4 {
	case apduUnconfirmedRequest:
		if apdu[1] != serviceIAm {
			return nil, nil // Who-Is etc. carry no asset evidence here
		}
		return decodeIAm(apdu)
	case apduComplexAck:
		return decodeComplexAck(apdu)
	case apduConfirmedRequest:
		return decodeConfirmedRequest(apdu)
	default:
		return nil, nil
	}
}

func decodeIAm(apdu []byte) (*message, error) {
	// I-Am body: object-id, max-apdu-length, segmentation, vendor-id (all
	// application tagged).
	values, err := decodeAppTags(apdu[2:])
	if err != nil {
		return nil, err
	}
	if len(values) < 2 {
		return nil, fmt.Errorf("bacnet: I-Am without object id")
	}
	objType, instance, ok := splitObjectID(values[0].uintValue)
	if !ok || objType != objTypeDevice {
		return nil, fmt.Errorf("bacnet: I-Am object id is not a device")
	}
	msg := &message{kind: msgIAm, deviceInstance: instance}
	// The last unsigned value of an I-Am is the vendor id.
	for _, value := range values[1:] {
		if value.appTag == appTagUnsigned {
			msg.vendorID = uint32(value.uintValue)
		}
	}
	return msg, nil
}

func decodeComplexAck(apdu []byte) (*message, error) {
	if len(apdu) < 3 {
		return nil, fmt.Errorf("bacnet: short complex ack")
	}
	if apdu[2] != serviceReadProperty {
		return nil, nil
	}
	cursor := &tagCursor{data: apdu[3:]}
	objTag, ok := cursor.contextTag(0)
	if !ok {
		return nil, fmt.Errorf("bacnet: ReadProperty-ACK without object id")
	}
	propTag, ok := cursor.contextTag(1)
	if !ok {
		return nil, fmt.Errorf("bacnet: ReadProperty-ACK without property id")
	}
	_ = cursor.skipContextTag(2) // optional array index
	objType, instance, ok := splitObjectID(objTag.uintValue)
	if !ok {
		return nil, fmt.Errorf("bacnet: invalid object id")
	}
	msg := &message{
		kind:           msgReadPropertyAck,
		objectType:     objType,
		objectInstance: instance,
		property:       uint8(propTag.uintValue),
	}
	if msg.property != propertyPresentValue {
		return nil, nil
	}
	valueTag, ok := cursor.appTag()
	if !ok {
		return nil, fmt.Errorf("bacnet: ReadProperty-ACK without value")
	}
	value, boolean, numeric, ok := valueTag.scalar()
	if !ok {
		return nil, nil // constructed or unsupported value type: not a bug
	}
	msg.value, msg.boolean, msg.numeric = value, boolean, numeric
	return msg, nil
}

func decodeConfirmedRequest(apdu []byte) (*message, error) {
	if len(apdu) < 4 {
		return nil, fmt.Errorf("bacnet: short confirmed request")
	}
	service := apdu[3]
	name, write := mutatingService(service)
	if !write {
		return nil, nil
	}
	msg := &message{kind: msgWriteAttempt, serviceName: name}
	cursor := &tagCursor{data: apdu[4:]}
	if objTag, ok := cursor.contextTag(0); ok {
		if typ, instance, valid := splitObjectID(objTag.uintValue); valid {
			msg.objectType = typ
			msg.objectInstance = instance
		}
	}
	if propTag, ok := cursor.contextTag(1); ok {
		msg.property = uint8(propTag.uintValue)
	}
	return msg, nil
}

// mutatingService lists every BACnet confirmed service that changes a device.
// They are reported as observed write attempts; nothing is ever sent.
func mutatingService(service byte) (string, bool) {
	switch service {
	case serviceAtomicWriteFile:
		return "atomic_write_file", true
	case serviceAddListElement:
		return "add_list_element", true
	case serviceRemoveListElement:
		return "remove_list_element", true
	case serviceCreateObject:
		return "create_object", true
	case serviceDeleteObject:
		return "delete_object", true
	case serviceWriteProperty:
		return "write_property", true
	case serviceWritePropertyMultiple:
		return "write_property_multiple", true
	default:
		return "", false
	}
}

// splitObjectID splits a BACnet object identifier into 10-bit type and 22-bit
// instance.
func splitObjectID(raw uint64) (uint8, uint32, bool) {
	if raw > 0xffffffff {
		return 0, 0, false
	}
	id := uint32(raw)
	instance := id & maxObjectID
	objType := uint8(id >> 22)
	return objType, instance, true
}
