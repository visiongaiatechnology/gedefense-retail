package mqtt

import (
	"bufio"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// brokerRecorder is a loopback fake broker. It records the packet types the
// client sends and never expects a PUBLISH from the client.
type brokerRecorder struct {
	listener  net.Listener
	mu        sync.Mutex
	types     []byte
	firsts    []byte
	connects  int
	publishCh chan publishPacket

	// onSubscribe is called after SUBACK so the test can push a PUBLISH.
	onSubscribe func(conn net.Conn, writer *bufio.Writer)
}

func newBrokerRecorder(t *testing.T) *brokerRecorder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := &brokerRecorder{listener: ln, publishCh: make(chan publishPacket, 4)}
	go b.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return b
}

func (b *brokerRecorder) addr() string { return b.listener.Addr().String() }

func (b *brokerRecorder) packetTypes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte{}, b.types...)
}

func (b *brokerRecorder) connectCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.connects
}

func (b *brokerRecorder) serve() {
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			return
		}
		go b.serveConn(conn)
	}
}

func (b *brokerRecorder) serveConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	for {
		first, body, err := readPacket(reader)
		if err != nil {
			return
		}
		packetType := first >> 4
		b.mu.Lock()
		b.types = append(b.types, packetType)
		b.firsts = append(b.firsts, first)
		if packetType == pktConnect {
			b.connects++
		}
		b.mu.Unlock()
		switch packetType {
		case pktConnect:
			_ = writePacket(writer, pktConnack<<4, []byte{0x00, 0x00})
			_ = writer.Flush()
		case pktSubscribe:
			_ = writePacket(writer, pktSuback<<4, []byte{0x00, 0x01, 0x00})
			_ = writer.Flush()
			if b.onSubscribe != nil {
				b.onSubscribe(conn, writer)
			}
		case pktPingreq:
			_ = writePacket(writer, pktPingresp<<4, nil)
			_ = writer.Flush()
		case pktDisconnect:
			return
		}
		_ = body
	}
}

func writePublish(t *testing.T, writer *bufio.Writer, topic, payload string) {
	t.Helper()
	body := []byte{byte(len(topic) >> 8), byte(len(topic))}
	body = append(body, topic...)
	body = append(body, payload...)
	if err := writePacket(writer, pktPublish<<4, body); err != nil {
		t.Fatalf("write publish: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("flush publish: %v", err)
	}
}

func TestSessionEmitsTelemetryAndNeverPublishes(t *testing.T) {
	t.Parallel()
	broker := newBrokerRecorder(t)
	broker.onSubscribe = func(conn net.Conn, writer *bufio.Writer) {
		writePublish(t, writer, "store/filiale-001/freezer/temp", "4.2")
	}
	cfg := collect.AdapterConfig{
		AdapterID: "mqtt.test",
		SiteID:    "filiale-001",
		Options: map[string]string{
			"broker":  broker.addr(),
			"topics":  "store/filiale-001/freezer/temp",
			"sensors": "store/filiale-001/freezer/temp|sensor_01|air_temperature|celsius",
		},
	}
	col, err := New(cfg)
	if err != nil {
		t.Fatalf("new mqtt adapter: %v", err)
	}
	if !col.Info().ReadOnly {
		t.Fatal("mqtt adapter reports ReadOnly=false")
	}
	sink := &mqttCaptureSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- col.Start(ctx, sink) }()
	waitMQTT(t, 3*time.Second, func() bool { return len(sink.ofKind(domain.EventTelemetry)) >= 1 })
	telemetry := sink.ofKind(domain.EventTelemetry)
	meas := telemetry[0].Measurement
	if meas == nil || meas.Value != 4.2 || meas.Unit != domain.UnitCelsius || meas.Metric != "air_temperature" {
		t.Fatalf("unexpected measurement: %+v", meas)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("mqtt adapter did not stop on cancel")
	}
	types := broker.packetTypes()
	broker.mu.Lock()
	firsts := append([]byte{}, broker.firsts...)
	broker.mu.Unlock()
	for i, packetType := range types {
		switch packetType {
		case pktConnect, pktSubscribe, pktPingreq, pktDisconnect:
		default:
			t.Fatalf("client sent forbidden packet type %d (first byte 0x%02x, all types %v, firsts %v): no PUBLISH is allowed",
				packetType, firsts[i], types, firsts)
		}
	}
}

func TestReconnectsAfterBrokerClose(t *testing.T) {
	t.Parallel()
	broker := newBrokerRecorder(t)
	broker.onSubscribe = func(conn net.Conn, _ *bufio.Writer) {
		_ = conn.Close()
	}
	cfg := collect.AdapterConfig{
		AdapterID: "mqtt.test",
		SiteID:    "filiale-001",
		Options: map[string]string{
			"broker": broker.addr(),
			"topics": "store/filiale-001/freezer/temp",
		},
	}
	col, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- col.Start(ctx, &mqttCaptureSink{}) }()
	waitMQTT(t, 3*time.Second, func() bool { return broker.connectCount() >= 2 })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("mqtt adapter did not stop")
	}
}

func TestNewRejectsUnsafeOptions(t *testing.T) {
	t.Parallel()
	base := func(opts map[string]string) collect.AdapterConfig {
		return collect.AdapterConfig{AdapterID: "mqtt.test", SiteID: "filiale-001", Options: opts}
	}
	cases := []struct {
		name string
		cfg  collect.AdapterConfig
	}{
		{"missing broker", base(map[string]string{"topics": "a/b"})},
		{"missing topics", base(map[string]string{"broker": "127.0.0.1:1883"})},
		{"wildcard denied", base(map[string]string{"broker": "127.0.0.1:1883", "topics": "store/#"})},
		{"bad mapping", base(map[string]string{"broker": "127.0.0.1:1883", "sensors": "x"})},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tc.cfg); err == nil {
				t.Fatalf("config %s should be rejected", tc.name)
			}
		})
	}
}

func TestStreamDecoderMapsTopicAndRejectsNonNumericalPayload(t *testing.T) {
	t.Parallel()
	mappings, err := ParseTopicMappings("store/filiale-001/freezer/temp|sensor_01|air_temperature|celsius")
	if err != nil {
		t.Fatalf("mappings: %v", err)
	}
	meta := collect.Meta{SiteID: "filiale-001", Source: "pcap.test", Collection: collect.CollectionOperatorExport}
	decoder, err := NewStreamDecoder(StreamOptions{Meta: meta, Mappings: mappings})
	if err != nil {
		t.Fatalf("stream decoder: %v", err)
	}
	connect := buildConnectBytes("panel-01")
	if events := decoder.Feed(connect); len(events) != 0 {
		t.Fatalf("connect produced events: %d", len(events))
	}
	subscribe := buildSubscribeBytes(1, "store/filiale-001/freezer/temp")
	if events := decoder.Feed(subscribe); len(events) != 0 {
		t.Fatalf("subscribe produced events: %d", len(events))
	}
	publish := buildPublishBytes("store/filiale-001/freezer/temp", "3.9")
	events := decoder.Feed(publish)
	if len(events) != 1 || events[0].Kind != domain.EventTelemetry || events[0].Measurement.Value != 3.9 {
		t.Fatalf("publish decoding failed: %+v", events)
	}
	// Non-numeric payload is counted, not fabricated into a measurement.
	decoder.Feed(buildPublishBytes("store/filiale-001/freezer/temp", "not-a-number"))
	if decoder.HealthCounters().Unsupported == 0 {
		t.Fatal("non-numeric payload was not counted")
	}
	if err := events[0].Validate(); err != nil {
		t.Fatalf("invalid event: %v", err)
	}
}

func FuzzStreamDecoder(f *testing.F) {
	f.Add(buildConnectBytes("panel-01"))
	f.Add(buildPublishBytes("store/filiale-001/freezer/temp", "4.1"))
	f.Add([]byte{0x30, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		meta := collect.Meta{SiteID: "filiale-001", Source: "fuzz", Collection: collect.CollectionPassiveTap}
		mappings, _ := ParseTopicMappings("a/b|sensor_01|air_temperature|celsius")
		decoder, err := NewStreamDecoder(StreamOptions{Meta: meta, Mappings: mappings})
		if err != nil {
			t.Fatalf("decoder: %v", err)
		}
		for _, ev := range decoder.Feed(data) {
			if err := ev.Validate(); err != nil {
				t.Fatalf("invalid event: %v", err)
			}
		}
	})
}

// Test-only packet builders (the adapter itself has no PUBLISH encoder).

func buildConnectBytes(clientID string) []byte {
	body, _ := encodeConnect(connectOptions{ClientID: clientID, CleanSession: true, Keepalive: 30})
	full := append([]byte{pktConnect << 4}, encodeLen(len(body))...)
	return append(full, body...)
}

func buildSubscribeBytes(packetID uint16, filter string) []byte {
	body, _ := encodeSubscribe(packetID, []string{filter})
	full := append([]byte{pktSubscribe<<4 | 0x02}, encodeLen(len(body))...)
	return append(full, body...)
}

func buildPublishBytes(topic, payload string) []byte {
	body := []byte{byte(len(topic) >> 8), byte(len(topic))}
	body = append(body, topic...)
	body = append(body, payload...)
	full := append([]byte{pktPublish << 4}, encodeLen(len(body))...)
	return append(full, body...)
}

func encodeLen(n int) []byte {
	out, err := encodeRemainingLength(n)
	if err != nil {
		return nil
	}
	return out
}

type mqttCaptureSink struct {
	mu     sync.Mutex
	events []domain.Event
}

func (s *mqttCaptureSink) Emit(_ context.Context, ev domain.Event) error {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	return nil
}

func (s *mqttCaptureSink) ofKind(kind domain.EventKind) []domain.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.Event, 0, len(s.events))
	for _, ev := range s.events {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

func waitMQTT(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
