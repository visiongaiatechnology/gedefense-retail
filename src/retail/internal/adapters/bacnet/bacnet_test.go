package bacnet

import (
	"context"
	"encoding/binary"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func testMeta(t *testing.T) collect.Meta {
	t.Helper()
	return collect.Meta{SiteID: "filiale-001", Source: "bacnet.test", Collection: collect.CollectionPassiveTap, Protocol: "bacnet_ip"}
}

func newTestDecoder(t *testing.T) *Decoder {
	t.Helper()
	decoder, err := NewDecoder(DecoderOptions{Meta: testMeta(t)})
	if err != nil {
		t.Fatalf("new decoder: %v", err)
	}
	return decoder
}

func TestDecodeIAmEmitsAssetSeen(t *testing.T) {
	t.Parallel()
	decoder := newTestDecoder(t)
	events := decoder.Feed("172.16.50.10", testIAmFrame(1001, 5))
	if len(events) != 1 || events[0].Kind != domain.EventAssetSeen {
		t.Fatalf("want asset_seen, got %d events", len(events))
	}
	meta := events[0].PayloadMeta
	if meta["bacnet_device_instance"] != "1001" || meta["bacnet_vendor_id"] != "5" {
		t.Fatalf("payload meta = %v", meta)
	}
	if events[0].Device == nil || events[0].Device.IP != "172.16.50.10" {
		t.Fatalf("device = %+v", events[0].Device)
	}
	if err := events[0].Validate(); err != nil {
		t.Fatalf("invalid event: %v", err)
	}
}

func TestDecodeReadPropertyAckAnalogValue(t *testing.T) {
	t.Parallel()
	decoder := newTestDecoder(t)
	events := decoder.Feed("172.16.50.10", testReadPropertyAckFrame(objTypeAnalogInput, 1, 85, 4.2))
	if len(events) != 1 || events[0].Kind != domain.EventTelemetry {
		t.Fatalf("want telemetry, got %d events", len(events))
	}
	meas := events[0].Measurement
	if meas == nil || meas.Metric != "present_value" {
		t.Fatalf("measurement = %+v", meas)
	}
	if meas.Value < 4.19 || meas.Value > 4.21 {
		t.Fatalf("value = %v", meas.Value)
	}
	if events[0].SensorID != "bacnet_analog_input_1" {
		t.Fatalf("sensor id = %q", events[0].SensorID)
	}
}

func TestDecodeReadPropertyAckBinaryValue(t *testing.T) {
	t.Parallel()
	decoder := newTestDecoder(t)
	// BinaryValue, instance 3, present-value enumerated 1.
	frame := testBinaryAckFrame(objTypeBinaryValue, 3, 85, 1)
	events := decoder.Feed("172.16.50.10", frame)
	if len(events) != 1 || events[0].Kind != domain.EventTelemetry {
		t.Fatalf("want telemetry, got %d events", len(events))
	}
	meas := events[0].Measurement
	if meas == nil || meas.Unit != domain.UnitBoolean || meas.Value != 1 || meas.Metric != "binary_state" {
		t.Fatalf("measurement = %+v", meas)
	}
}

func TestDecodeWritePropertyIsOnlyObserved(t *testing.T) {
	t.Parallel()
	decoder := newTestDecoder(t)
	events := decoder.Feed("192.168.99.50", testWritePropertyFrame(objTypeAnalogInput, 1, 85))
	if len(events) != 1 || events[0].Kind != domain.EventWriteAttempt {
		t.Fatalf("want write_attempt, got %d events", len(events))
	}
	attempt := events[0].WriteAttempt
	if attempt == nil || attempt.Function != "write_property" || attempt.Allowed {
		t.Fatalf("attempt = %+v", attempt)
	}
	if events[0].Validate() == nil {
		return
	}
	t.Fatal("invalid write attempt event")
}

func TestMalformedDatagramsAreCounted(t *testing.T) {
	t.Parallel()
	decoder := newTestDecoder(t)
	inputs := [][]byte{
		{},
		{0x81},
		{0x81, 0x0A, 0xFF, 0xFF},
		append([]byte{0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x30}, make([]byte, 8)...),
		[]byte("GET / HTTP/1.1"),
	}
	for _, input := range inputs {
		decoder.Feed("172.16.50.10", input)
	}
	if decoder.HealthCounters().ParserErrors == 0 {
		t.Fatal("malformed datagrams were not counted")
	}
}

func TestAdapterIsPassiveAndDoesNotAnswer(t *testing.T) {
	t.Parallel()
	reserved, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserve udp: %v", err)
	}
	addr := reserved.LocalAddr().String()
	_ = reserved.Close()

	cfg := collect.AdapterConfig{AdapterID: "bacnet.test", SiteID: "filiale-001", Options: map[string]string{"listen": addr}}
	col, err := New(cfg)
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	if !col.Info().ReadOnly {
		t.Fatal("bacnet adapter reports ReadOnly=false")
	}
	sink := &bacnetCaptureSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- col.Start(ctx, sink) }()

	serverAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	probe, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("probe socket: %v", err)
	}
	defer func() { _ = probe.Close() }()
	// Retry the datagram until the adapter socket is bound (the goroutine may
	// still be starting under -race scheduling).
	sent := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case startErr := <-done:
			t.Fatalf("bacnet adapter stopped during startup: %v", startErr)
		default:
		}
		if len(sink.ofKind(domain.EventAssetSeen)) >= 1 {
			break
		}
		if _, err := probe.WriteToUDP(testIAmFrame(7, 5), serverAddr); err == nil {
			sent = true
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sent {
		t.Fatal("could not send probe datagram")
	}
	if len(sink.ofKind(domain.EventAssetSeen)) < 1 {
		t.Fatal("passive adapter did not decode the probe datagram")
	}
	// The passive adapter must never answer: a read on the probe socket has to
	// time out.
	if err := probe.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 64)
	if _, _, err := probe.ReadFromUDP(buf); err == nil {
		t.Fatal("bacnet adapter sent a datagram; passive adapter must never answer")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("bacnet adapter did not stop on cancel")
	}
}

func FuzzDecodeDatagram(f *testing.F) {
	f.Add(testIAmFrame(1001, 5))
	f.Add(testReadPropertyAckFrame(objTypeAnalogValue, 2, 85, 3.5))
	f.Add(testWritePropertyFrame(objTypeAnalogInput, 1, 85))
	f.Add([]byte{0x81, 0x0a, 0x00, 0x06, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		meta := collect.Meta{SiteID: "filiale-001", Source: "fuzz", Collection: collect.CollectionPassiveTap}
		decoder, err := NewDecoder(DecoderOptions{Meta: meta})
		if err != nil {
			t.Fatalf("decoder: %v", err)
		}
		for _, ev := range decoder.Feed("172.16.50.10", data) {
			if err := ev.Validate(); err != nil {
				t.Fatalf("invalid event: %v", err)
			}
		}
	})
}

// Test frame builders (synthetic captures only).

func testIAmFrame(deviceInstance uint32, vendorID uint16) []byte {
	objectID := uint32(8)<<22 | (deviceInstance & 0x3fffff)
	body := []byte{0x10, 0x00, 0xC4}
	body = append(body, byte(objectID>>24), byte(objectID>>16), byte(objectID>>8), byte(objectID))
	body = append(body, 0x22, 0x01, 0xE0) // unsigned 480 (max APDU), app tag 2 length 2
	body = append(body, 0x91, 0x03)       // enumerated, no segmentation
	body = append(body, 0x22, byte(vendorID>>8), byte(vendorID))
	return testBVLC(body)
}

func testReadPropertyAckFrame(objectType uint8, instance uint32, property uint8, value float32) []byte {
	objectID := uint32(objectType)<<22 | (instance & 0x3fffff)
	body := []byte{0x30, 0x01, 0x0C, 0x04}
	body = append(body, byte(objectID>>24), byte(objectID>>16), byte(objectID>>8), byte(objectID))
	body = append(body, 0x11, property, 0x44)
	bits := mathFloat32bits(value)
	body = append(body, byte(bits>>24), byte(bits>>16), byte(bits>>8), byte(bits))
	return testBVLC(body)
}

func testBinaryAckFrame(objectType uint8, instance uint32, property uint8, value uint8) []byte {
	objectID := uint32(objectType)<<22 | (instance & 0x3fffff)
	body := []byte{0x30, 0x01, 0x0C, 0x04}
	body = append(body, byte(objectID>>24), byte(objectID>>16), byte(objectID>>8), byte(objectID))
	body = append(body, 0x11, property, 0x91, value)
	return testBVLC(body)
}

func testWritePropertyFrame(objectType uint8, instance uint32, property uint8) []byte {
	objectID := uint32(objectType)<<22 | (instance & 0x3fffff)
	body := []byte{0x00, 0x05, 0x02, 0x0F, 0x04}
	body = append(body, byte(objectID>>24), byte(objectID>>16), byte(objectID>>8), byte(objectID))
	body = append(body, 0x11, property, 0x44)
	bits := mathFloat32bits(12.0)
	body = append(body, byte(bits>>24), byte(bits>>16), byte(bits>>8), byte(bits))
	return testBVLC(body)
}

func testBVLC(apdu []byte) []byte {
	npdu := append([]byte{0x01, 0x00}, apdu...)
	frame := []byte{0x81, 0x0A, 0x00, 0x00}
	binary.BigEndian.PutUint16(frame[2:4], uint16(4+len(npdu)))
	return append(frame, npdu...)
}

func mathFloat32bits(value float32) uint32 { return math.Float32bits(value) }

type bacnetCaptureSink struct {
	mu     sync.Mutex
	events []domain.Event
}

func (s *bacnetCaptureSink) Emit(_ context.Context, ev domain.Event) error {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	return nil
}

func (s *bacnetCaptureSink) ofKind(kind domain.EventKind) []domain.Event {
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

func waitBacnet(t *testing.T, timeout time.Duration, condition func() bool) {
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
