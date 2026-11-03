// Read-only client session (CONNECT/SUBSCRIBE QoS0/PINGREQ, inbound PUBLISH).
package mqtt

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// session runs one broker connection until it fails or ctx is cancelled.
func (a *Adapter) session(ctx context.Context, sink ports.Sink) error {
	dialer := net.Dialer{Timeout: a.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", a.broker)
	if err != nil {
		return fmt.Errorf("connect %s: %w", a.broker, err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if err := conn.SetDeadline(time.Now().Add(a.timeout)); err != nil {
		return err
	}
	connectPacket, err := encodeConnect(connectOptions{
		ClientID:     a.clientID,
		Username:     a.username,
		Password:     a.password,
		Keepalive:    uint16(a.keepalive / time.Second),
		CleanSession: true,
	})
	if err != nil {
		return err
	}
	if err := writePacket(conn, pktConnect<<4, connectPacket); err != nil {
		return fmt.Errorf("send connect: %w", err)
	}
	reader := bufio.NewReaderSize(conn, 8<<10)
	first, body, err := readPacket(reader)
	if err != nil {
		return fmt.Errorf("read connack: %w", err)
	}
	if first != pktConnack<<4 {
		return fmt.Errorf("%w: expected connack, got packet type %d", ErrBadPacket, first>>4)
	}
	connack, err := parseConnack(body)
	if err != nil {
		return err
	}
	if connack.ReturnCode != 0 {
		return fmt.Errorf("mqtt: broker rejected connect with code %d", connack.ReturnCode)
	}

	subscribeBody, err := encodeSubscribe(1, a.topics)
	if err != nil {
		return err
	}
	if err := writePacket(conn, pktSubscribe<<4|0x02, subscribeBody); err != nil {
		return fmt.Errorf("send subscribe: %w", err)
	}
	first, body, err = readPacket(reader)
	if err != nil {
		return fmt.Errorf("read suback: %w", err)
	}
	if first != pktSuback<<4 {
		return fmt.Errorf("%w: expected suback, got packet type %d", ErrBadPacket, first>>4)
	}
	suback, err := parseSuback(body)
	if err != nil {
		return err
	}
	for _, code := range suback.Codes {
		if code == 0x80 {
			return fmt.Errorf("mqtt: broker rejected subscription")
		}
	}
	a.emitBrokerAssetSeen(ctx, sink)

	// From here on the adapter only reads; the only packets it may write are
	// PINGREQ and DISCONNECT (encoded exclusively by encodePingReq/encodeDisconnect).
	keepaliveRead := a.keepalive
	for {
		if err := conn.SetReadDeadline(time.Now().Add(keepaliveRead)); err != nil {
			return err
		}
		first, body, err = readPacket(reader)
		if err != nil {
			if ctx.Err() != nil {
				a.sendDisconnect(conn)
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if err := writePacket(conn, pktPingreq<<4, nil); err != nil {
					return fmt.Errorf("send pingreq: %w", err)
				}
				continue
			}
			return fmt.Errorf("read packet: %w", err)
		}
		events, err := a.handlePacket(first, body)
		if err != nil {
			a.counters.IncParserError(err.Error())
			continue
		}
		if len(events) > 0 {
			if err := collect.EmitAll(ctx, sink, events); err != nil {
				return err
			}
		}
	}
}

// handlePacket interprets one inbound packet. It never produces a write.
func (a *Adapter) handlePacket(first byte, body []byte) ([]domain.Event, error) {
	switch first >> 4 {
	case pktPublish:
		publish, err := parsePublish(first, body)
		if err != nil {
			return nil, err
		}
		return a.telemetryForPublish(publish)
	case pktPingresp:
		return nil, nil
	case pktConnack:
		return nil, nil
	case pktSuback:
		return nil, nil
	default:
		a.counters.IncUnsupported()
		return nil, nil
	}
}

// telemetryForPublish maps a received topic/payload onto one sensor reading.
func (a *Adapter) telemetryForPublish(publish publishPacket) ([]domain.Event, error) {
	mapping, ok := findMapping(a.mappings, publish.Topic)
	if !ok {
		a.counters.IncUnsupported()
		return nil, nil
	}
	value, unitHint, ok := parsePayload(publish.Payload)
	if !ok {
		a.counters.IncUnsupported()
		return nil, nil
	}
	unit := mapping.Unit
	if unitHint.Valid() {
		unit = unitHint
	}
	now := a.now()
	meas := domain.Measurement{
		Value:      value,
		Unit:       unit,
		Quality:    domain.QualityGood,
		Metric:     mapping.Metric,
		ObservedAt: now,
	}
	ev, err := a.meta.TelemetryEvent(mapping.SensorID, mapping.AssetID, meas, 0.7, now)
	if err != nil {
		return nil, err
	}
	return []domain.Event{ev}, nil
}

func (a *Adapter) emitBrokerAssetSeen(ctx context.Context, sink ports.Sink) {
	host, _, err := net.SplitHostPort(a.broker)
	if err != nil {
		return
	}
	ev, err := a.meta.AssetSeenEvent(domain.DeviceMeta{IP: host}, 0.5, a.now())
	if err != nil {
		return
	}
	if err := collect.EmitAll(ctx, sink, []domain.Event{ev}); err != nil {
		a.counters.IncError(err.Error())
	}
}

// sendDisconnect is a best-effort polite close. It can only send DISCONNECT.
func (a *Adapter) sendDisconnect(conn net.Conn) {
	_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = conn.Write(encodeDisconnect())
}
