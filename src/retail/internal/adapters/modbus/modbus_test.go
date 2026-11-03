package modbus

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/guard"
)

func testMeta(t *testing.T) collect.Meta {
	t.Helper()
	return collect.Meta{
		SiteID:     "filiale-001",
		Source:     "modbus.test",
		Collection: collect.CollectionPassiveTap,
		Protocol:   "modbus_tcp",
	}
}

func testOpts(t *testing.T) collect.AdapterConfig {
	t.Helper()
	return collect.AdapterConfig{AdapterID: "modbus.test", SiteID: "filiale-001"}
}

func TestRegisterSpecRejectsWriteFunctionCodes(t *testing.T) {
	t.Parallel()
	for _, fc := range []string{"5", "6", "15", "16"} {
		entry := fc + ":0:sensor_01:setpoint:celsius"
		_, err := ParseRegisterSpec(entry)
		if !errors.Is(err, guard.ErrWriteDenied) {
			t.Fatalf("fc %s: want guard.ErrWriteDenied, got %v", fc, err)
		}
	}
	if _, err := ParseRegisterSpec("3:0:sensor_01:air_temperature:celsius:0.1"); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	// Negative scale and malformed entries are rejected.
	for _, entry := range []string{
		"3:0:sensor_01:air_temperature:celsius:0",
		"3:0:sensor_01:air_temperature:banana",
		"9:0:sensor_01:air_temperature:celsius",
		"3:0:not valid:sensor:celsius",
		"3:0:sensor_01:air_temperature:celsius:1:2:3",
	} {
		if _, err := ParseRegisterSpec(entry); err == nil {
			t.Fatalf("spec %q should be rejected", entry)
		}
	}
	if err := enforceReadOnly(guard.ReadOnly(), fcReadHolding); err != nil {
		t.Fatalf("read fc denied: %v", err)
	}
	if err := enforceReadOnly(guard.ReadOnly(), fcWriteMultipleRegisters); !errors.Is(err, guard.ErrWriteDenied) {
		t.Fatalf("fc16 not denied: %v", err)
	}
}

func TestTapObservesWriteAttemptsExactlyOnce(t *testing.T) {
	t.Parallel()
	tap, err := NewTap(TapOptions{Meta: testMeta(t), Peer: "192.168.99.50:50010"})
	if err != nil {
		t.Fatalf("new tap: %v", err)
	}
	// FC6 request toward the server.
	request := writeSingleRegisterFrame(7, 1, 1, 120)
	events := tap.Feed(request, DirectionUnknown)
	if len(events) != 1 || events[0].Kind != domain.EventWriteAttempt {
		t.Fatalf("want one write_attempt, got %d events", len(events))
	}
	attempt := events[0].WriteAttempt
	if attempt == nil || attempt.Function != "fc6_write_single_register" || attempt.Allowed {
		t.Fatalf("write attempt metadata = %+v", attempt)
	}
	if attempt.ValueHint != "items=1" || attempt.Register == "" {
		t.Fatalf("write attempt hint = %+v", attempt)
	}
	// The echo response from the device must not create a second event.
	if events := tap.Feed(request, DirectionToClient); len(events) != 0 {
		t.Fatalf("echo produced %d events", len(events))
	}
	// Direction-aware double feed also de-duplicates by transaction id.
	if events := tap.Feed(writeSingleRegisterFrame(8, 1, 1, 120), DirectionUnknown); len(events) != 1 {
		t.Fatalf("second write not observed")
	}
	if events := tap.Feed(writeSingleRegisterFrame(8, 1, 1, 120), DirectionUnknown); len(events) != 0 {
		t.Fatalf("duplicate transaction was counted twice")
	}
}

func TestTapDecodesReadTelemetry(t *testing.T) {
	t.Parallel()
	registers, err := ParseRegisterSpec("3:0:sensor_01:air_temperature:celsius:0.1;3:1:sensor_02:air_temperature:celsius:0.1;4:0:sensor_03:door_state:boolean")
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	tap, err := NewTap(TapOptions{Meta: testMeta(t), Registers: registers, DeviceIP: "172.16.50.10"})
	if err != nil {
		t.Fatalf("new tap: %v", err)
	}
	// asset_seen once on first frame.
	events := tap.Feed(readRequestFrame(1, 3, 0, 2), DirectionToServer)
	if len(events) != 1 || events[0].Kind != domain.EventAssetSeen {
		t.Fatalf("want asset_seen, got %v", kinds(events))
	}
	// Response with 4.2 C and 3.9 C (signed int16 * 0.1).
	events = tap.Feed(readResponseFrame(1, 3, []uint16{42, 39}), DirectionToClient)
	if len(events) != 2 {
		t.Fatalf("want two telemetry events, got %v", kinds(events))
	}
	for _, ev := range events {
		if ev.Kind != domain.EventTelemetry || ev.Measurement == nil {
			t.Fatalf("unexpected event: %+v", ev)
		}
		if ev.Measurement.Unit != domain.UnitCelsius {
			t.Fatalf("unit = %q", ev.Measurement.Unit)
		}
	}
	if !almostEqual(events[0].Measurement.Value, 4.2) || !almostEqual(events[1].Measurement.Value, 3.9) {
		t.Fatalf("values = %v, %v", events[0].Measurement.Value, events[1].Measurement.Value)
	}
	// Negative temperature is decoded as signed int16.
	tap2, err := NewTap(TapOptions{Meta: testMeta(t), Registers: registers})
	if err != nil {
		t.Fatalf("new tap: %v", err)
	}
	if events := tap2.Feed(readRequestFrame(2, 3, 0, 1), DirectionUnknown); len(events) != 0 {
		t.Fatalf("request should not emit telemetry")
	}
	events = tap2.Feed(readResponseFrame(2, 3, []uint16{uint16(0xFF4C)}), DirectionUnknown)
	if len(events) != 1 || !almostEqual(events[0].Measurement.Value, -18.0) {
		t.Fatalf("negative temperature not decoded: %+v", events)
	}
}

func TestTapParserErrorsDoNotStopDecoding(t *testing.T) {
	t.Parallel()
	tap, err := NewTap(TapOptions{Meta: testMeta(t), Registers: mustSpecs(t, "3:0:sensor_01:air_temperature:celsius")})
	if err != nil {
		t.Fatalf("new tap: %v", err)
	}
	tap.Feed([]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04}, DirectionUnknown)
	if tap.HealthCounters().ParserErrors == 0 {
		t.Fatal("malformed input was not counted")
	}
	events := tap.Feed(readRequestFrame(3, 3, 0, 1), DirectionToServer)
	if len(events) != 0 {
		t.Fatalf("unexpected events: %v", kinds(events))
	}
	events = tap.Feed(readResponseFrame(3, 3, []uint16{42}), DirectionToClient)
	if len(events) != 1 || events[0].Kind != domain.EventTelemetry {
		t.Fatalf("decoder did not recover after parser errors: %v", kinds(events))
	}
}

func TestTapBufferIsBounded(t *testing.T) {
	t.Parallel()
	tap, err := NewTap(TapOptions{Meta: testMeta(t), MaxBufferBytes: 256})
	if err != nil {
		t.Fatalf("new tap: %v", err)
	}
	tap.Feed(make([]byte, 1024), DirectionUnknown)
	if tap.HealthCounters().ParserErrors == 0 {
		t.Fatal("oversized chunk was not counted")
	}
	// A valid frame after garbage must still be decodable (resync).
	if events := tap.Feed(readRequestFrame(9, 3, 0, 1), DirectionUnknown); len(events) != 0 {
		t.Fatalf("unexpected events after resync: %v", kinds(events))
	}
}

func TestPollSendsOnlyReadFunctionCodes(t *testing.T) {
	t.Parallel()
	server := newFakeModbusServer(t)
	defer server.Close()

	cfg := testOpts(t)
	cfg.Options = map[string]string{
		"mode":      "poll",
		"target":    server.Addr(),
		"interval":  "60ms",
		"timeout":   "500ms",
		"registers": "3:0:sensor_01:air_temperature:celsius:0.1;4:0:sensor_02:air_temperature:celsius:0.1",
	}
	col, err := New(cfg)
	if err != nil {
		t.Fatalf("new poll adapter: %v", err)
	}
	sink := &captureSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- col.Start(ctx, sink) }()
	waitFor(t, 3*time.Second, func() bool { return len(sink.telemetry()) >= 2 })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("poll adapter did not stop on cancel")
	}
	server.mu.Lock()
	fcs := append([]uint8{}, server.functionCodes...)
	server.mu.Unlock()
	if len(fcs) == 0 {
		t.Fatal("simulator server received no request")
	}
	for _, fc := range fcs {
		if fc != fcReadHolding && fc != fcReadInput {
			t.Fatalf("poll adapter sent function code %d", fc)
		}
	}
	if got := col.Info(); !got.ReadOnly {
		t.Fatalf("poll adapter reports ReadOnly=false: %+v", got)
	}
}

func TestTapAdapterListenFeed(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := testOpts(t)
	cfg.Options = map[string]string{
		"mode":      "tap",
		"listen":    addr,
		"device_ip": "172.16.50.10",
		"registers": "3:0:sensor_01:air_temperature:celsius:0.1",
	}
	col, err := New(cfg)
	if err != nil {
		t.Fatalf("new tap adapter: %v", err)
	}
	sink := &captureSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- col.Start(ctx, sink) }()

	var conn net.Conn
	waitFor(t, 2*time.Second, func() bool {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return false
		}
		conn = c
		return true
	})
	if conn == nil {
		t.Fatal("tap listener did not accept a feed connection")
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(readRequestFrame(1, 3, 0, 1)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if _, err := conn.Write(readResponseFrame(1, 3, []uint16{42})); err != nil {
		t.Fatalf("write response: %v", err)
	}
	waitFor(t, 3*time.Second, func() bool { return len(sink.telemetry()) >= 1 })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("tap adapter did not stop on cancel")
	}
	if len(sink.writeAttempts()) != 0 {
		t.Fatalf("tap adapter emitted write attempts from a read stream")
	}
}

func TestInfoIsReadOnly(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"tap", "poll"} {
		cfg := testOpts(t)
		opts := map[string]string{"mode": mode}
		if mode == "tap" {
			opts["listen"] = "127.0.0.1:0"
		} else {
			opts["target"] = "127.0.0.1:1502"
			opts["registers"] = "3:0:sensor_01:air_temperature:celsius"
		}
		cfg.Options = opts
		col, err := New(cfg)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		info := col.Info()
		if !info.ReadOnly || !collect.ValidCollection(info.Collection) {
			t.Fatalf("%s info = %+v", mode, info)
		}
	}
}

func FuzzTapFeed(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01})
	f.Add(readRequestFrame(1, 3, 0, 2))
	f.Add(readResponseFrame(1, 3, []uint16{42, 39}))
	f.Add(writeSingleRegisterFrame(5, 1, 2, 120))
	tap, err := NewTap(TapOptions{Meta: testMetaFuzz()})
	if err != nil {
		f.Fatalf("new tap: %v", err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		for _, dir := range []Direction{DirectionUnknown, DirectionToServer, DirectionToClient} {
			events := tap.Feed(data, dir)
			for _, ev := range events {
				if err := ev.Validate(); err != nil {
					t.Fatalf("decoder produced invalid event: %v", err)
				}
			}
		}
	})
}
