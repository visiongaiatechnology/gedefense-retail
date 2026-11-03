// Passive TLS ClientHello SNI extraction (no decryption, no certificate data).
package httpui

import (
	"encoding/binary"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

const (
	maxTLSRecordBytes   = 18432
	maxTLSBufferBytes   = 64 << 10
	maxTLSHandshake     = 128 << 10
	tlsHandshakeMsgType = 22
)

// tlsState is the per-connection TLS reassembly state.
type tlsState struct {
	records   []byte
	handshake []byte
}

func (d *Decoder) feedTLS(meta ConnMeta, chunk []byte) []domain.Event {
	d.tls.records = append(d.tls.records, chunk...)
	if len(d.tls.records) > maxTLSBufferBytes {
		d.counters.IncParserError("tls reassembly buffer exceeded")
		d.tls.records = d.tls.records[:0]
		d.tls.handshake = d.tls.handshake[:0]
		return nil
	}
	var events []domain.Event
	offset := 0
	for offset+tlsRecordHeaderLen <= len(d.tls.records) {
		contentType := d.tls.records[offset]
		length := int(binary.BigEndian.Uint16(d.tls.records[offset+3 : offset+5]))
		if length > maxTLSRecordBytes {
			d.counters.IncParserError("tls record length out of range")
			d.tls.records = d.tls.records[:0]
			return events
		}
		total := tlsRecordHeaderLen + length
		if offset+total > len(d.tls.records) {
			break
		}
		record := d.tls.records[offset+tlsRecordHeaderLen : offset+total]
		offset += total
		if contentType != tlsHandshakeMsgType {
			// Application data / alerts / heartbeats carry no metadata for us.
			continue
		}
		d.tls.handshake = append(d.tls.handshake, record...)
		if len(d.tls.handshake) > maxTLSHandshake {
			d.counters.IncParserError("tls handshake reassembly exceeded")
			d.tls.handshake = d.tls.handshake[:0]
			break
		}
		events = append(events, d.parseHandshake(meta)...)
	}
	if offset > 0 {
		remaining := len(d.tls.records) - offset
		copy(d.tls.records, d.tls.records[offset:])
		d.tls.records = d.tls.records[:remaining]
	}
	return events
}

func (d *Decoder) parseHandshake(meta ConnMeta) []domain.Event {
	var events []domain.Event
	for {
		if len(d.tls.handshake) < 4 {
			break
		}
		msgLen := int(d.tls.handshake[1])<<16 | int(d.tls.handshake[2])<<8 | int(d.tls.handshake[3])
		if msgLen < 0 || msgLen > maxTLSHandshake {
			d.counters.IncParserError("tls handshake message length out of range")
			d.tls.handshake = d.tls.handshake[:0]
			break
		}
		if len(d.tls.handshake) < 4+msgLen {
			break
		}
		msgType := d.tls.handshake[0]
		body := d.tls.handshake[4 : 4+msgLen]
		remaining := len(d.tls.handshake) - (4 + msgLen)
		copy(d.tls.handshake, d.tls.handshake[4+msgLen:])
		d.tls.handshake = d.tls.handshake[:remaining]
		if msgType != tlsHandshakeTypeHello {
			continue
		}
		sni, ok := parseClientHelloSNI(body)
		if !ok {
			d.counters.IncParserError("tls client hello without usable sni")
		}
		events = append(events, d.tlsEvents(meta, sni)...)
	}
	return events
}

func (d *Decoder) tlsEvents(meta ConnMeta, sni string) []domain.Event {
	now := d.opts.Meta.Now()
	events := make([]domain.Event, 0, 2)
	if meta.Valid() {
		flow := domain.FlowMeta{
			SrcIP:     meta.ClientIP,
			DstIP:     meta.ServerIP,
			SrcPort:   int(meta.ClientPort),
			DstPort:   int(meta.ServerPort),
			Protocol:  "https",
			Packets:   1,
			Direction: "internal",
		}
		if ev, err := d.opts.Meta.FlowEvent(flow, 0.6, now); err == nil {
			events = append(events, ev)
		}
	}
	host := sanitizeHost(sni)
	if host == "" {
		return events
	}
	vendor, model := uiHint(host)
	confidence := 0.5
	if vendor != "" || model != "" {
		confidence = 0.6
	}
	dev := domain.DeviceMeta{IP: meta.ServerIP, Hostname: host, Vendor: vendor, Model: model}
	if ev, err := d.opts.Meta.AssetSeenEvent(dev, confidence, now); err == nil {
		events = append(events, ev)
	}
	return events
}

// parseClientHelloSNI walks the ClientHello structure and returns the first
// host_name SNI value. All length fields are bounded; malformed input returns
// ok=false without panicking.
func parseClientHelloSNI(body []byte) (string, bool) {
	cur := &cursor{b: body}
	if _, ok := cur.skip(2); !ok { // legacy_version
		return "", false
	}
	if _, ok := cur.skip(32); !ok { // random
		return "", false
	}
	sessionID, ok := cur.u8Prefixed()
	if !ok {
		return "", false
	}
	_ = sessionID
	if _, ok := cur.u16Prefixed(); !ok { // cipher_suites
		return "", false
	}
	if _, ok := cur.u8Prefixed(); !ok { // compression_methods
		return "", false
	}
	if cur.remaining() == 0 {
		return "", false
	}
	extensions, ok := cur.u16Prefixed()
	if !ok {
		return "", false
	}
	ext := &cursor{b: extensions}
	for ext.remaining() >= 4 {
		extType, ok := ext.u16()
		if !ok {
			return "", false
		}
		extData, ok := ext.u16Prefixed()
		if !ok {
			return "", false
		}
		if extType != 0x0000 { // server_name
			continue
		}
		list := &cursor{b: extData}
		if _, ok := list.u16(); !ok { // server_name_list length
			return "", false
		}
		for list.remaining() >= 3 {
			nameType, ok := list.u8()
			if !ok {
				return "", false
			}
			name, ok := list.u16Prefixed()
			if !ok {
				return "", false
			}
			if nameType != 0 { // host_name
				continue
			}
			return string(name), true
		}
		return "", false
	}
	return "", false
}

// cursor is a bounds-checked byte reader for the TLS structures.
type cursor struct {
	b   []byte
	off int
}

func (c *cursor) remaining() int { return len(c.b) - c.off }

func (c *cursor) skip(n int) ([]byte, bool) {
	if n < 0 || c.off+n > len(c.b) {
		return nil, false
	}
	out := c.b[c.off : c.off+n]
	c.off += n
	return out, true
}

func (c *cursor) u8() (uint8, bool) {
	if c.off+1 > len(c.b) {
		return 0, false
	}
	v := c.b[c.off]
	c.off++
	return v, true
}

func (c *cursor) u16() (uint16, bool) {
	if c.off+2 > len(c.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(c.b[c.off : c.off+2])
	c.off += 2
	return v, true
}

func (c *cursor) u8Prefixed() ([]byte, bool) {
	n, ok := c.u8()
	if !ok {
		return nil, false
	}
	return c.skip(int(n))
}

func (c *cursor) u16Prefixed() ([]byte, bool) {
	n, ok := c.u16()
	if !ok {
		return nil, false
	}
	return c.skip(int(n))
}
