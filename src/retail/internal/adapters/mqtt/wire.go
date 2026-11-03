// MQTT 3.1.1 wire format for the read-only subset.
package mqtt

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MQTT control packet types used by the product.
const (
	pktConnect    byte = 1
	pktConnack    byte = 2
	pktPublish    byte = 3
	pktSubscribe  byte = 8
	pktSuback     byte = 9
	pktPingreq    byte = 12
	pktPingresp   byte = 13
	pktDisconnect byte = 14
)

const (
	maxRemainingBytes = 4
	maxPacketBody     = 256 << 10
	// maxPublishPayload bounds inbound telemetry payloads we are willing to
	// buffer. Larger messages are counted and skipped, never stored.
	maxPublishPayload = 64 << 10
)

// Errors of the MQTT wire layer.
var (
	ErrBadPacket      = errors.New("mqtt: malformed packet")
	ErrUnsupportedPkt = errors.New("mqtt: unsupported packet type")
)

// encodeRemainingLength encodes a remaining-length value (variable byte int).
func encodeRemainingLength(n int) ([]byte, error) {
	if n < 0 || n > 268435455 {
		return nil, fmt.Errorf("%w: remaining length %d", ErrBadPacket, n)
	}
	out := make([]byte, 0, 4)
	for {
		digit := byte(n % 128)
		n /= 128
		if n > 0 {
			digit |= 0x80
		}
		out = append(out, digit)
		if n == 0 {
			return out, nil
		}
	}
}

// decodeRemainingLength reads a variable byte int from r.
func decodeRemainingLength(r io.ByteReader) (int, error) {
	multiplier := 1
	value := 0
	for i := 0; i < maxRemainingBytes; i++ {
		digit, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		value += int(digit&0x7f) * multiplier
		if digit&0x80 == 0 {
			return value, nil
		}
		multiplier *= 128
	}
	return 0, fmt.Errorf("%w: remaining length varint too long", ErrBadPacket)
}

// writePacket writes one MQTT packet.
func writePacket(w io.Writer, first byte, body []byte) error {
	length, err := encodeRemainingLength(len(body))
	if err != nil {
		return err
	}
	header := make([]byte, 0, 1+len(length)+len(body))
	header = append(header, first)
	header = append(header, length...)
	header = append(header, body...)
	_, err = w.Write(header)
	return err
}

// readPacket reads one packet from a buffered connection.
func readPacket(r *bufio.Reader) (byte, []byte, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	remaining, err := decodeRemainingLength(r)
	if err != nil {
		return 0, nil, err
	}
	if remaining < 0 || remaining > maxPacketBody {
		return 0, nil, fmt.Errorf("%w: remaining length %d", ErrBadPacket, remaining)
	}
	body := make([]byte, remaining)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return first, body, nil
}

// connectOptions is the read-only connection setup.
type connectOptions struct {
	ClientID     string
	Username     string
	Password     string
	Keepalive    uint16
	CleanSession bool
}

// encodeConnect builds the CONNECT packet. It is the only packet that can carry
// credentials; the credentials never leave this function.
func encodeConnect(opts connectOptions) ([]byte, error) {
	if err := validateUTF8String(opts.ClientID, maxClientIDLen); err != nil {
		return nil, err
	}
	var body bytes.Buffer
	writeUTF8(&body, "MQTT")
	body.WriteByte(4) // protocol level 4 = MQTT 3.1.1
	var flags byte
	if opts.CleanSession {
		flags |= 0x02
	}
	if opts.Username != "" {
		flags |= 0x80
		if opts.Password != "" {
			flags |= 0x40
		}
	}
	body.WriteByte(flags)
	var keepalive [2]byte
	binary.BigEndian.PutUint16(keepalive[:], opts.Keepalive)
	body.Write(keepalive[:])
	writeUTF8(&body, opts.ClientID)
	if opts.Username != "" {
		writeUTF8(&body, opts.Username)
		if opts.Password != "" {
			writeUTF8(&body, opts.Password)
		}
	}
	return body.Bytes(), nil
}

// encodeSubscribe builds a QoS0 SUBSCRIBE packet.
func encodeSubscribe(packetID uint16, filters []string) ([]byte, error) {
	if packetID == 0 {
		return nil, fmt.Errorf("%w: packet id 0", ErrBadPacket)
	}
	if len(filters) == 0 {
		return nil, fmt.Errorf("%w: no topic filters", ErrBadPacket)
	}
	var body bytes.Buffer
	var id [2]byte
	binary.BigEndian.PutUint16(id[:], packetID)
	body.Write(id[:])
	for _, filter := range filters {
		if err := validateUTF8String(filter, 256); err != nil {
			return nil, err
		}
		writeUTF8(&body, filter)
		body.WriteByte(0x00) // requested QoS 0
	}
	return body.Bytes(), nil
}

// encodePingReq builds a PINGREQ packet.
func encodePingReq() []byte { return []byte{pktPingreq << 4, 0} }

// encodeDisconnect builds a DISCONNECT packet.
func encodeDisconnect() []byte { return []byte{pktDisconnect << 4, 0} }

func writeUTF8(buf *bytes.Buffer, value string) {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	buf.Write(length[:])
	buf.WriteString(value)
}

// readUTF8 reads a length-prefixed MQTT string from body at *offset.
func readUTF8(body []byte, offset *int) (string, error) {
	if *offset+2 > len(body) {
		return "", fmt.Errorf("%w: string length", ErrBadPacket)
	}
	length := int(binary.BigEndian.Uint16(body[*offset : *offset+2]))
	*offset += 2
	if *offset+length > len(body) {
		return "", fmt.Errorf("%w: string data", ErrBadPacket)
	}
	value := string(body[*offset : *offset+length])
	*offset += length
	return value, nil
}

// connackResult is the decoded CONNACK.
type connackResult struct {
	SessionPresent bool
	ReturnCode     byte
}

func parseConnack(body []byte) (connackResult, error) {
	if len(body) != 2 {
		return connackResult{}, fmt.Errorf("%w: connack length %d", ErrBadPacket, len(body))
	}
	if body[0]&0xfe != 0 {
		return connackResult{}, fmt.Errorf("%w: connack flags", ErrBadPacket)
	}
	return connackResult{SessionPresent: body[0]&0x01 != 0, ReturnCode: body[1]}, nil
}

// subackResult is the decoded SUBACK.
type subackResult struct {
	PacketID uint16
	Codes    []byte
}

func parseSuback(body []byte) (subackResult, error) {
	if len(body) < 3 {
		return subackResult{}, fmt.Errorf("%w: suback length %d", ErrBadPacket, len(body))
	}
	return subackResult{PacketID: binary.BigEndian.Uint16(body[0:2]), Codes: body[2:]}, nil
}

// publishPacket is the decoded inbound PUBLISH.
type publishPacket struct {
	Topic    string
	Payload  []byte
	QoS      byte
	Retained bool
}

func parsePublish(first byte, body []byte) (publishPacket, error) {
	qos := (first >> 1) & 0x03
	if qos > 1 {
		return publishPacket{}, fmt.Errorf("%w: qos %d not supported", ErrUnsupportedPkt, qos)
	}
	offset := 0
	topic, err := readUTF8(body, &offset)
	if err != nil {
		return publishPacket{}, err
	}
	if len(topic) == 0 || len(topic) > 256 {
		return publishPacket{}, fmt.Errorf("%w: topic length %d", ErrBadPacket, len(topic))
	}
	if qos > 0 {
		if offset+2 > len(body) {
			return publishPacket{}, fmt.Errorf("%w: publish packet id", ErrBadPacket)
		}
		offset += 2
	}
	payload := body[offset:]
	if len(payload) > maxPublishPayload {
		return publishPacket{}, fmt.Errorf("%w: payload %d bytes", ErrBadPacket, len(payload))
	}
	return publishPacket{Topic: topic, Payload: payload, QoS: qos, Retained: first&0x01 != 0}, nil
}

// connectPacket is the passive view of a client CONNECT (never the credentials).
type connectPacket struct {
	ClientID     string
	CleanSession bool
	HasUsername  bool
	HasPassword  bool
	Keepalive    uint16
}

func parseConnect(body []byte) (connectPacket, error) {
	offset := 0
	protocol, err := readUTF8(body, &offset)
	if err != nil {
		return connectPacket{}, err
	}
	if protocol != "MQTT" && protocol != "MQIsdp" {
		return connectPacket{}, fmt.Errorf("%w: protocol %q", ErrBadPacket, protocol)
	}
	if offset+4 > len(body) {
		return connectPacket{}, fmt.Errorf("%w: connect flags", ErrBadPacket)
	}
	level := body[offset]
	if level != 4 && level != 3 {
		return connectPacket{}, fmt.Errorf("%w: protocol level %d", ErrBadPacket, level)
	}
	offset++
	flags := body[offset]
	offset++
	keepalive := binary.BigEndian.Uint16(body[offset : offset+2])
	offset += 2
	// A will topic/message complicates the position of the client id; the MVP
	// does not need the client id when flags are unusual, so bail out safely.
	if flags&0x04 != 0 {
		return connectPacket{}, fmt.Errorf("%w: will flag not parsed", ErrUnsupportedPkt)
	}
	clientID, err := readUTF8(body, &offset)
	if err != nil {
		return connectPacket{}, err
	}
	if len(clientID) > maxClientIDLen {
		return connectPacket{}, fmt.Errorf("%w: client id too long", ErrBadPacket)
	}
	packet := connectPacket{
		ClientID:     clientID,
		CleanSession: flags&0x02 != 0,
		HasUsername:  flags&0x80 != 0,
		HasPassword:  flags&0x40 != 0,
		Keepalive:    keepalive,
	}
	if packet.HasUsername {
		if _, err := readUTF8(body, &offset); err != nil { // value intentionally dropped
			return connectPacket{}, err
		}
	}
	if packet.HasPassword {
		if _, err := readUTF8(body, &offset); err != nil {
			return connectPacket{}, err
		}
	}
	return packet, nil
}

// validateUTF8String checks the MQTT string subset used by the adapter:
// non-empty (when required by caller), bounded, UTF-8 and free of control
// characters (log/JSON safety).
func validateUTF8String(value string, max int) error {
	if len(value) > max {
		return fmt.Errorf("%w: string longer than %d bytes", ErrBadPacket, max)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("%w: string contains a control character", ErrBadPacket)
		}
	}
	return nil
}
