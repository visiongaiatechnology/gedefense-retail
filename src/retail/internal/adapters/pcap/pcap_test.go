package pcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func pcapHeader(t helperTB, magic []byte, order binary.ByteOrder, nano bool, linkType uint32) []byte {
	t.Helper()
	header := make([]byte, 24)
	copy(header[0:4], magic)
	order.PutUint16(header[4:6], 2)
	order.PutUint16(header[6:8], 4)
	order.PutUint32(header[16:20], 262144)
	order.PutUint32(header[20:24], linkType)
	return header
}

func pcapRecord(t helperTB, order binary.ByteOrder, ts time.Time, data []byte, nano bool) []byte {
	t.Helper()
	sub := ts.Nanosecond() / 1000
	if nano {
		sub = ts.Nanosecond()
	}
	header := make([]byte, 16)
	order.PutUint32(header[0:4], uint32(ts.Unix()))
	order.PutUint32(header[4:8], uint32(sub))
	order.PutUint32(header[8:12], uint32(len(data)))
	order.PutUint32(header[12:16], uint32(len(data)))
	return append(header, data...)
}

func TestReaderByteOrdersAndResolution(t *testing.T) {
	t.Parallel()
	frame := []byte{1, 2, 3, 4}
	cases := []struct {
		name       string
		magic      []byte
		order      binary.ByteOrder
		nanosecond bool
	}{
		{"little micro", []byte{0xd4, 0xc3, 0xb2, 0xa1}, binary.LittleEndian, false},
		{"big micro", []byte{0xa1, 0xb2, 0xc3, 0xd4}, binary.BigEndian, false},
		{"little nano", []byte{0x4d, 0x3c, 0xb2, 0xa1}, binary.LittleEndian, true},
		{"big nano", []byte{0xa1, 0xb2, 0x3c, 0x4d}, binary.BigEndian, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := time.Date(2026, 11, 3, 12, 0, 0, 123456789, time.UTC)
			var raw []byte
			raw = append(raw, pcapHeader(t, tc.magic, tc.order, tc.nanosecond, LinkTypeEthernet)...)
			raw = append(raw, pcapRecord(t, tc.order, ts, frame, tc.nanosecond)...)
			reader, err := NewReader(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("new reader: %v", err)
			}
			record, err := reader.Next()
			if err != nil {
				t.Fatalf("next: %v", err)
			}
			if !bytes.Equal(record.Data, frame) {
				t.Fatalf("frame = %v", record.Data)
			}
			want := time.Unix(ts.Unix(), int64(ts.Nanosecond()/1000)*1000).UTC()
			if tc.nanosecond {
				want = ts
			}
			if !record.Timestamp.Equal(want) {
				t.Fatalf("timestamp = %v, want %v", record.Timestamp, want)
			}
			if _, err := reader.Next(); !errors.Is(err, io.EOF) {
				t.Fatalf("want io.EOF, got %v", err)
			}
		})
	}
}

func TestReaderRejectsMalformedFiles(t *testing.T) {
	t.Parallel()
	if _, err := NewReader(bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23})); !errors.Is(err, ErrBadMagic) {
		t.Fatalf("bad magic error = %v", err)
	}
	valid := pcapHeader(t, []byte{0xd4, 0xc3, 0xb2, 0xa1}, binary.LittleEndian, false, LinkTypeEthernet)
	if _, err := NewReader(bytes.NewReader(valid[:10])); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated header error = %v", err)
	}
	badLink := pcapHeader(t, []byte{0xd4, 0xc3, 0xb2, 0xa1}, binary.LittleEndian, false, 999)
	if _, err := NewReader(bytes.NewReader(badLink)); !errors.Is(err, ErrUnsupportedLink) {
		t.Fatalf("bad link error = %v", err)
	}
	// A record claiming more data than the file contains.
	raw := append(valid, pcapRecord(t, binary.LittleEndian, time.Now(), []byte{1, 2, 3}, false)[:10]...)
	reader, err := NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	if _, err := reader.Next(); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated record error = %v", err)
	}
}

func TestWriterRoundTrip(t *testing.T) {
	t.Parallel()
	var buffer bytes.Buffer
	writer, err := NewWriter(&buffer)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	frame, err := BuildEthernetIPv4TCP([6]byte{1, 2, 3, 4, 5, 6}, [6]byte{6, 5, 4, 3, 2, 1},
		Endpoint{IP: "172.16.50.20", Port: 50000}, Endpoint{IP: "172.16.50.10", Port: 502},
		1, 2, TCPFlagPSH|TCPFlagACK, []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02})
	if err != nil {
		t.Fatalf("build frame: %v", err)
	}
	ts := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	if err := writer.WritePacket(ts, frame); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	reader, err := NewReader(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	record, err := reader.Next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if !record.Timestamp.Equal(ts) {
		t.Fatalf("timestamp = %v", record.Timestamp)
	}
	pkt, err := Decode(LinkTypeEthernet, record.Data, record.Timestamp)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pkt.SrcIP != "172.16.50.20" || pkt.DstIP != "172.16.50.10" || pkt.DstPort != 502 || len(pkt.Payload) != 12 {
		t.Fatalf("packet = %+v", pkt)
	}
}

func TestDecodeFrames(t *testing.T) {
	t.Parallel()
	ts := time.Now().UTC()
	tcpFrame, err := BuildEthernetIPv4TCP([6]byte{1, 1, 1, 1, 1, 1}, [6]byte{2, 2, 2, 2, 2, 2},
		Endpoint{IP: "172.16.50.20", Port: 50000}, Endpoint{IP: "172.16.50.10", Port: 502}, 0, 0, TCPFlagACK, []byte("abc"))
	if err != nil {
		t.Fatalf("build tcp: %v", err)
	}
	pkt, err := Decode(LinkTypeEthernet, tcpFrame, ts)
	if err != nil || pkt.Protocol != ipProtoTCP || string(pkt.Payload) != "abc" {
		t.Fatalf("tcp decode: %+v %v", pkt, err)
	}
	udpFrame, err := BuildEthernetIPv4UDP([6]byte{1, 1, 1, 1, 1, 1}, [6]byte{2, 2, 2, 2, 2, 2},
		Endpoint{IP: "172.16.50.10", Port: 47808}, Endpoint{IP: "172.16.50.255", Port: 47808}, []byte("bacnet"))
	if err != nil {
		t.Fatalf("build udp: %v", err)
	}
	pkt, err = Decode(LinkTypeEthernet, udpFrame, ts)
	if err != nil || pkt.Protocol != ipProtoUDP || string(pkt.Payload) != "bacnet" {
		t.Fatalf("udp decode: %+v %v", pkt, err)
	}
	// VLAN-tagged frame.
	ipPayload := udpFrame[14:]
	vlan := BuildEthernet([6]byte{1, 1, 1, 1, 1, 1}, [6]byte{2, 2, 2, 2, 2, 2}, etherTypeVLAN, append([]byte{0x00, 0x64, 0x08, 0x00}, ipPayload...))
	if _, err := Decode(LinkTypeEthernet, vlan, ts); err != nil {
		t.Fatalf("vlan decode: %v", err)
	}
	// Non-IP frames are valid capture content but not IPv4.
	arp := BuildEthernet([6]byte{1, 1, 1, 1, 1, 1}, [6]byte{2, 2, 2, 2, 2, 2}, etherTypeARP, []byte("arp"))
	if _, err := Decode(LinkTypeEthernet, arp, ts); !errors.Is(err, ErrNotIPv4) {
		t.Fatalf("arp decode error = %v", err)
	}
	if _, err := Decode(LinkTypeEthernet, []byte{1, 2}, ts); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("short frame error = %v", err)
	}
}

// fixturePath resolves the committed simulator fixtures.
func fixturePath(name string) string {
	return filepath.Join("..", "..", "..", "..", "..", "tests", "testdata", "pcap", name)
}

func TestAdapterImportsNormalFixture(t *testing.T) {
	t.Parallel()
	cfg := collect.AdapterConfig{
		AdapterID: "pcap.test",
		SiteID:    "filiale-001",
		Options: map[string]string{
			"files":     fixturePath("normal.pcap"),
			"registers": "3:0:sensor_01:air_temperature:celsius:0.1",
			"sensors":   "store/filiale-001/freezer/temp|sensor_mqtt|air_temperature|celsius",
			"objects":   "0:1|sensor_bacnet|air_temperature|celsius",
		},
	}
	col, err := New(cfg)
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	if !col.Info().ReadOnly {
		t.Fatal("pcap adapter reports ReadOnly=false")
	}
	sink := &captureSinkType{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- col.Start(ctx, sink) }()
	// Wait for the end of the import: the flow/asset aggregation is emitted as
	// a single flush after all records were processed. Cancelling earlier would
	// test shutdown behavior instead of the fixture import.
	waitPcap(t, 5*time.Second, func() bool {
		return len(sink.ofKind(domain.EventTelemetry)) >= 2 &&
			len(sink.ofKind(domain.EventFlow)) >= 1 &&
			len(sink.ofKind(domain.EventAssetSeen)) >= 1
	})
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pcap adapter did not stop")
	}
	if len(sink.ofKind(domain.EventFlow)) == 0 {
		t.Fatal("no flow events emitted")
	}
	if len(sink.ofKind(domain.EventAssetSeen)) == 0 {
		t.Fatal("no asset_seen events emitted")
	}
	for _, ev := range sink.eventsCopy() {
		if err := ev.Validate(); err != nil {
			t.Fatalf("invalid event: %v", err)
		}
	}
}

func TestAdapterImportsAttackFixture(t *testing.T) {
	t.Parallel()
	cfg := collect.AdapterConfig{
		AdapterID: "pcap.test",
		SiteID:    "filiale-001",
		Options:   map[string]string{"files": fixturePath("angriff.pcap")},
	}
	col, err := New(cfg)
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	sink := &captureSinkType{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- col.Start(ctx, sink) }()
	waitPcap(t, 3*time.Second, func() bool {
		functions := observedWriteFunctions(sink)
		return functions["fc6_write_single_register"] && functions["http_post"] && functions["write_property"]
	})
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pcap adapter did not stop")
	}
	attempts := sink.ofKind(domain.EventWriteAttempt)
	functions := make(map[string]bool, len(attempts))
	for _, ev := range attempts {
		if ev.WriteAttempt == nil {
			t.Fatalf("write attempt without metadata")
		}
		if ev.WriteAttempt.Allowed {
			t.Fatalf("observed write attempt marked allowed")
		}
		functions[ev.WriteAttempt.Function] = true
	}
	if !functions["fc6_write_single_register"] || !functions["write_property"] {
		t.Fatalf("observed write attempts = %v", functions)
	}
}

func TestAdapterRejectsMissingInput(t *testing.T) {
	t.Parallel()
	cfg := collect.AdapterConfig{AdapterID: "pcap.test", SiteID: "filiale-001"}
	if _, err := New(cfg); !errors.Is(err, ErrNoInput) {
		t.Fatalf("missing input error = %v", err)
	}
	cfg.Options = map[string]string{"files": "does-not-exist.pcap"}
	if _, err := New(cfg); err == nil {
		t.Fatal("missing file must fail at construction")
	}
}

func FuzzReader(f *testing.F) {
	valid := pcapHeader(fakeTB{}, []byte{0xd4, 0xc3, 0xb2, 0xa1}, binary.LittleEndian, false, LinkTypeEthernet)
	valid = append(valid, pcapRecord(fakeTB{}, binary.LittleEndian, time.Now(), []byte{1, 2, 3, 4}, false)...)
	f.Add(valid)
	f.Add([]byte{0xd4, 0xc3, 0xb2, 0xa1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		reader, err := NewReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		for i := 0; i < 16; i++ {
			record, err := reader.Next()
			if err != nil {
				return
			}
			_, _ = Decode(reader.LinkType(), record.Data, record.Timestamp)
		}
	})
}

// helperTB is the minimal testing helper surface used by fixture builders.
type helperTB interface{ Helper() }

// fakeTB satisfies helperTB for fixture construction inside fuzz targets.
type fakeTB struct{}

func (fakeTB) Helper() {}

type captureSinkType struct {
	mu     sync.Mutex
	events []domain.Event
}

func (s *captureSinkType) Emit(_ context.Context, ev domain.Event) error {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	return nil
}

func (s *captureSinkType) eventsCopy() []domain.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]domain.Event{}, s.events...)
}

func (s *captureSinkType) ofKind(kind domain.EventKind) []domain.Event {
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

func observedWriteFunctions(sink *captureSinkType) map[string]bool {
	functions := map[string]bool{}
	for _, ev := range sink.ofKind(domain.EventWriteAttempt) {
		if ev.WriteAttempt != nil {
			functions[ev.WriteAttempt.Function] = true
		}
	}
	return functions
}

func waitPcap(t *testing.T, timeout time.Duration, condition func() bool) {
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
