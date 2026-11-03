package httpui

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func testMeta(t *testing.T) collect.Meta {
	t.Helper()
	return collect.Meta{SiteID: "filiale-001", Source: "httpui.test", Collection: collect.CollectionPassiveTap, Protocol: "http"}
}

func testConn() ConnMeta {
	return ConnMeta{ClientIP: "192.168.99.50", ClientPort: 50100, ServerIP: "172.16.50.10", ServerPort: 443}
}

func newTestDecoder(t *testing.T) *Decoder {
	t.Helper()
	decoder, err := NewDecoder(DecoderOptions{Meta: testMeta(t)})
	if err != nil {
		t.Fatalf("new decoder: %v", err)
	}
	return decoder
}

func TestPlainHTTPRequestMetadataOnly(t *testing.T) {
	t.Parallel()
	decoder := newTestDecoder(t)
	request := "GET /storeview/login HTTP/1.1\r\nHost: storeview-ak-sm-800.filiale.local\r\n" +
		"User-Agent: panel-01\r\nCookie: session=SECRET\r\nAuthorization: Bearer SECRET\r\n\r\n"
	events := decoder.Feed(testConn(), []byte(request))
	var flowEvent, assetEvent *domain.Event
	for i := range events {
		switch events[i].Kind {
		case domain.EventFlow:
			flowEvent = &events[i]
		case domain.EventAssetSeen:
			assetEvent = &events[i]
		}
	}
	if flowEvent == nil || flowEvent.Flow == nil || flowEvent.Flow.Protocol != "http" || flowEvent.Flow.DstPort != 443 {
		t.Fatalf("flow event = %+v", flowEvent)
	}
	if assetEvent == nil || assetEvent.Device == nil {
		t.Fatalf("asset event = %+v", assetEvent)
	}
	if assetEvent.Device.Hostname != "storeview-ak-sm-800.filiale.local" {
		t.Fatalf("hostname = %q", assetEvent.Device.Hostname)
	}
	if assetEvent.Device.Model != "StoreView" && assetEvent.Device.Vendor != "Danfoss" {
		t.Fatalf("no product hint derived: %+v", assetEvent.Device)
	}
	for _, ev := range events {
		raw := strings.ToLower(ev.Source + ev.Collection + ev.Protocol)
		if strings.Contains(raw, "secret") || strings.Contains(raw, "cookie") || strings.Contains(raw, "bearer") {
			t.Fatalf("event leaked sensitive header data: %+v", ev)
		}
		if ev.WriteAttempt != nil {
			t.Fatalf("GET must not be a write attempt: %+v", ev.WriteAttempt)
		}
	}
}

func TestWriteAttemptObservedWithoutQueryOrBody(t *testing.T) {
	t.Parallel()
	decoder := newTestDecoder(t)
	request := "POST /xml.cgi?user=admin&password=SECRET HTTP/1.1\r\nHost: storeview-ak-sm-800.filiale.local\r\n" +
		"Content-Length: 0\r\n\r\n"
	events := decoder.Feed(testConn(), []byte(request))
	var attempt *domain.WriteAttempt
	for i := range events {
		if events[i].Kind == domain.EventWriteAttempt {
			attempt = events[i].WriteAttempt
		}
	}
	if attempt == nil {
		t.Fatal("POST was not observed as write attempt")
	}
	if attempt.Register != "/xml.cgi" {
		t.Fatalf("register/path = %q, query string must be dropped", attempt.Register)
	}
	if attempt.Allowed {
		t.Fatal("write attempt must not be marked allowed")
	}
	if strings.Contains(attempt.Register, "SECRET") || strings.Contains(attempt.Target, "SECRET") {
		t.Fatalf("write attempt leaked query credentials: %+v", attempt)
	}
}

func TestTLSClientHelloSNI(t *testing.T) {
	t.Parallel()
	decoder := newTestDecoder(t)
	hello := testTLSClientHello("storeview-ak-sm-800.filiale.local")
	events := decoder.Feed(ConnMeta{ClientIP: "192.168.99.50", ClientPort: 50101, ServerIP: "172.16.50.10", ServerPort: 8443}, hello)
	var asset *domain.DeviceMeta
	var flow *domain.FlowMeta
	for i := range events {
		switch events[i].Kind {
		case domain.EventAssetSeen:
			asset = events[i].Device
		case domain.EventFlow:
			flow = events[i].Flow
		}
	}
	if flow == nil || flow.Protocol != "https" {
		t.Fatalf("flow = %+v", flow)
	}
	if asset == nil || asset.Hostname != "storeview-ak-sm-800.filiale.local" {
		t.Fatalf("SNI not extracted: %+v", asset)
	}
	// No certificate contents are decoded; only the SNI host is stored.
	if asset.Model != "StoreView" && asset.Vendor != "Danfoss" {
		t.Fatalf("no product hint derived from SNI: %+v", asset)
	}
}

func TestResponseServerHeader(t *testing.T) {
	t.Parallel()
	decoder := newTestDecoder(t)
	response := "HTTP/1.1 200 OK\r\nServer: StoreView\r\nContent-Type: text/html\r\n\r\n"
	events := decoder.Feed(ConnMeta{ClientIP: "172.16.50.20", ClientPort: 50102, ServerIP: "172.16.50.10", ServerPort: 80}, []byte(response))
	var asset *domain.DeviceMeta
	for i := range events {
		if events[i].Kind == domain.EventAssetSeen {
			asset = events[i].Device
		}
	}
	if asset == nil || asset.Model != "StoreView" {
		t.Fatalf("server header not mapped to a product hint: %+v", asset)
	}
}

func TestOversizedHeaderIsCountedAndDropped(t *testing.T) {
	t.Parallel()
	decoder := newTestDecoder(t)
	decoder.opts.MaxHeader = 128
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = 'A'
	}
	events := decoder.Feed(testConn(), payload)
	if len(events) != 0 {
		t.Fatalf("oversized header produced events: %d", len(events))
	}
	if decoder.HealthCounters().ParserErrors == 0 {
		t.Fatal("oversized header was not counted")
	}
}

func TestAdapterRequiresEvidence(t *testing.T) {
	t.Parallel()
	base := collect.AdapterConfig{AdapterID: "httpui.test", SiteID: "filiale-001"}
	base.Options = map[string]string{"listen": "127.0.0.1:0"}
	if _, err := New(base); err == nil {
		t.Fatal("adapter without device_ip must be rejected")
	}
	base.Options["device_ip"] = "172.16.50.10"
	col, err := New(base)
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	if !col.Info().ReadOnly {
		t.Fatal("httpui adapter reports ReadOnly=false")
	}
}

func TestAdapterFeedEndToEnd(t *testing.T) {
	t.Parallel()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	addr := reserved.Addr().String()
	_ = reserved.Close()
	cfg := collect.AdapterConfig{AdapterID: "httpui.test", SiteID: "filiale-001", Options: map[string]string{
		"listen": addr, "device_ip": "172.16.50.10", "device_port": "443",
	}}
	col, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	sink := &httpCaptureSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- col.Start(ctx, sink) }()
	conn := dialEventually(t, addr)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("POST /xml.cgi HTTP/1.1\r\nHost: storeview-ak-sm-800.filiale.local\r\nContent-Length: 0\r\n\r\n"))
	if err != nil {
		t.Fatalf("write request: %v", err)
	}
	waitHTTPUI(t, 2*time.Second, func() bool { return len(sink.ofKind(domain.EventWriteAttempt)) >= 1 })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("adapter did not stop")
	}
}

func FuzzDecoderFeed(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	f.Add(testTLSClientHello("storeview.local"))
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff})
	f.Add([]byte("POST /xml.cgi HTTP/1.1\r\nHost: h\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		meta := collect.Meta{SiteID: "filiale-001", Source: "fuzz", Collection: collect.CollectionPassiveTap}
		decoder, err := NewDecoder(DecoderOptions{Meta: meta, MaxHeader: 4096})
		if err != nil {
			t.Fatalf("decoder: %v", err)
		}
		for _, ev := range decoder.Feed(testConn(), data) {
			if err := ev.Validate(); err != nil {
				t.Fatalf("invalid event: %v", err)
			}
		}
	})
}

// testTLSClientHello builds a minimal ClientHello with SNI (fixture only).
func testTLSClientHello(sni string) []byte {
	hello := []byte{0x03, 0x03}
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0x00)
	hello = append(hello, 0x00, 0x02, 0x00, 0x2f)
	hello = append(hello, 0x01, 0x00)
	name := []byte(sni)
	entry := []byte{0x00, byte(len(name) >> 8), byte(len(name))}
	entry = append(entry, name...)
	list := []byte{byte(len(entry) >> 8), byte(len(entry))}
	list = append(list, entry...)
	ext := []byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list))}
	ext = append(ext, list...)
	extensions := append([]byte{byte(len(ext) >> 8), byte(len(ext))}, ext...)
	hello = append(hello, extensions...)
	handshake := []byte{0x01, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}
	handshake = append(handshake, hello...)
	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

type httpCaptureSink struct {
	mu     sync.Mutex
	events []domain.Event
}

func (s *httpCaptureSink) Emit(_ context.Context, ev domain.Event) error {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	return nil
}

func (s *httpCaptureSink) ofKind(kind domain.EventKind) []domain.Event {
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

func dialEventually(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			return conn
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("could not dial %s", addr)
	return nil
}

func waitHTTPUI(t *testing.T, timeout time.Duration, condition func() bool) {
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
