// Passive MQTT stream decoder for PCAP/offline analysis (no client, no writes).
package mqtt

import (
	"errors"
	"fmt"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// StreamOptions configures a passive MQTT stream decoder (one TCP connection).
type StreamOptions struct {
	Meta     collect.Meta
	Mappings []TopicMapping
}

// StreamDecoder parses observed MQTT packets and maps PUBLISH telemetry. It is
// used by the PCAP adapter; it cannot send anything.
type StreamDecoder struct {
	opts     StreamOptions
	buf      []byte
	counters collect.Counters
}

// NewStreamDecoder creates the decoder and validates its provenance.
func NewStreamDecoder(opts StreamOptions) (*StreamDecoder, error) {
	if err := opts.Meta.Validate(); err != nil {
		return nil, fmt.Errorf("mqtt stream: %w", err)
	}
	return &StreamDecoder{opts: opts}, nil
}

// HealthCounters exposes parser/unsupported counters.
func (d *StreamDecoder) HealthCounters() collect.CounterSnapshot { return d.counters.HealthCounters() }

// Feed consumes a TCP payload chunk and returns decoded telemetry events.
func (d *StreamDecoder) Feed(chunk []byte) []domain.Event {
	if len(chunk) == 0 {
		return nil
	}
	d.buf = append(d.buf, chunk...)
	var events []domain.Event
	for len(d.buf) >= 2 {
		remaining, lengthBytes, err := decodeRemainingBuf(d.buf[1:])
		if err != nil {
			d.counters.IncParserError(err.Error())
			d.buf = d.buf[1:]
			continue
		}
		total := 1 + lengthBytes + remaining
		if remaining > maxPacketBody {
			d.counters.IncParserError("packet body exceeds limit")
			d.buf = d.buf[1:]
			continue
		}
		if len(d.buf) < total {
			break
		}
		first := d.buf[0]
		body := d.buf[1+lengthBytes : total]
		events = append(events, d.handle(first, body)...)
		d.buf = d.buf[total:]
	}
	if len(d.buf) == 0 {
		d.buf = d.buf[:0]
	} else if cap(d.buf) > 1<<20 {
		compact := make([]byte, len(d.buf))
		copy(compact, d.buf)
		d.buf = compact
	}
	return events
}

func (d *StreamDecoder) handle(first byte, body []byte) []domain.Event {
	switch first >> 4 {
	case pktPublish:
		publish, err := parsePublish(first, body)
		if err != nil {
			d.counters.IncParserError(err.Error())
			return nil
		}
		mapping, ok := findMapping(d.opts.Mappings, publish.Topic)
		if !ok {
			d.counters.IncUnsupported()
			return nil
		}
		value, unitHint, ok := parsePayload(publish.Payload)
		if !ok {
			d.counters.IncUnsupported()
			return nil
		}
		unit := mapping.Unit
		if unitHint.Valid() {
			unit = unitHint
		}
		now := d.opts.Meta.Now()
		meas := domain.Measurement{
			Value:      value,
			Unit:       unit,
			Quality:    domain.QualityGood,
			Metric:     mapping.Metric,
			ObservedAt: now,
		}
		ev, err := d.opts.Meta.TelemetryEvent(mapping.SensorID, mapping.AssetID, meas, 0.75, now)
		if err != nil {
			d.counters.IncError(err.Error())
			return nil
		}
		return []domain.Event{ev}
	case pktConnect:
		if _, err := parseConnect(body); err != nil {
			d.counters.IncParserError(err.Error())
		}
		return nil
	case pktPingreq, pktPingresp, pktDisconnect, pktSubscribe, pktSuback, pktConnack:
		return nil
	default:
		d.counters.IncUnsupported()
		return nil
	}
}

// decodeRemainingBuf decodes the MQTT variable byte int from the front of buf.
func decodeRemainingBuf(buf []byte) (value int, consumed int, err error) {
	multiplier := 1
	value = 0
	for i := 0; i < maxRemainingBytes; i++ {
		if i >= len(buf) {
			return 0, 0, errors.New("mqtt: incomplete remaining length")
		}
		digit := buf[i]
		value += int(digit&0x7f) * multiplier
		if digit&0x80 == 0 {
			return value, i + 1, nil
		}
		multiplier *= 128
	}
	return 0, 0, fmt.Errorf("%w: remaining length varint too long", ErrBadPacket)
}
