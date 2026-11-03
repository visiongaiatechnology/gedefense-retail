package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pcapdb "github.com/visiongaiatechnology/gedefense/retail/internal/adapters/pcap"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

type ingestCapture struct {
	mu      sync.Mutex
	batches [][]domain.Event
	auths   []string
	sims    []string
	types   []string
}

func (c *ingestCapture) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != devIngestPath {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Events []domain.Event `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.batches = append(c.batches, body.Events)
		c.auths = append(c.auths, r.Header.Get("Authorization"))
		c.sims = append(c.sims, r.Header.Get("X-GeDefense-Sim"))
		c.types = append(c.types, r.Header.Get("Content-Type"))
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"accepted": len(body.Events), "rejected": 0, "errors": []any{}})
	}
}

func (c *ingestCapture) totalEvents() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for _, batch := range c.batches {
		total += len(batch)
	}
	return total
}

func TestFeedSendsValidEventsAndPrintsSummary(t *testing.T) {
	capture := &ingestCapture{}
	server := httptest.NewServer(capture.handler(t))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	args := []string{
		"--url", server.URL,
		"--token", "test-token",
		"--scenario", "angriff",
		"--count", "12",
		"--batch", "5",
		"--rate", "5000",
	}
	if err := runFeed(args, &stdout, &stderr); err != nil {
		t.Fatalf("feed failed: %v (stderr %s)", err, stderr.String())
	}
	summary := stdout.String()
	if !strings.Contains(summary, "FEED_SUMMARY sent=12 failed=0 http_status=200") {
		t.Fatalf("summary = %q", summary)
	}
	if capture.totalEvents() != 12 {
		t.Fatalf("server received %d events", capture.totalEvents())
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.batches) != 3 {
		t.Fatalf("batches = %d, want 3", len(capture.batches))
	}
	for i := range capture.batches {
		if capture.auths[i] != "Bearer test-token" {
			t.Fatalf("authorization header = %q", capture.auths[i])
		}
		if capture.sims[i] != "1" {
			t.Fatalf("X-GeDefense-Sim header = %q", capture.sims[i])
		}
		if !strings.HasPrefix(capture.types[i], "application/json") {
			t.Fatalf("content type = %q", capture.types[i])
		}
		if len(capture.batches[i]) > maxBatchSize {
			t.Fatalf("batch size %d exceeds limit", len(capture.batches[i]))
		}
		for _, ev := range capture.batches[i] {
			if err := ev.Validate(); err != nil {
				t.Fatalf("invalid synthetic event: %v", err)
			}
			if ev.Source != "sim.feed" {
				t.Fatalf("event source = %q", ev.Source)
			}
		}
	}
	writes := 0
	for _, ev := range capture.batches[0] {
		if ev.Kind == domain.EventWriteAttempt {
			writes++
		}
	}
	if writes == 0 {
		// The attack scenario writes only in some cycles; check all batches.
		for _, batch := range capture.batches {
			for _, ev := range batch {
				if ev.Kind == domain.EventWriteAttempt {
					writes++
				}
			}
		}
	}
	if writes == 0 {
		t.Fatal("attack scenario produced no write_attempt event")
	}
}

func TestFeedRequiresToken(t *testing.T) {
	t.Setenv(simTokenEnvVar, "")
	var stdout, stderr bytes.Buffer
	err := runFeed([]string{"--url", "http://127.0.0.1:8080", "--count", "1"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("error = %v", err)
	}
}

func TestFeedRejectsNonLoopbackURL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runFeed([]string{"--url", "http://10.1.2.3:8080", "--token", "x", "--count", "1"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error = %v", err)
	}
}

func TestFeedReports404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	err := runFeed([]string{"--url", server.URL, "--token", "x", "--count", "5", "--batch", "5", "--rate", "5000"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(stdout.String(), "FEED_SUMMARY") || !strings.Contains(stdout.String(), "http_status=404") {
		t.Fatalf("summary = %q", stdout.String())
	}
}

func TestBuildIngestEndpoint(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080/api/v1/dev/events", false},
		{"http://localhost:8080/", "http://localhost:8080/api/v1/dev/events", false},
		{"http://[::1]:8080", "http://[::1]:8080/api/v1/dev/events", false},
		{"http://127.0.0.1:8080/api/v1/dev/events", "http://127.0.0.1:8080/api/v1/dev/events", false},
		{"http://10.1.2.3:8080", "", true},
		{"ftp://127.0.0.1:8080", "", true},
		{"http://user:pass@127.0.0.1:8080", "", true},
		{"http://127.0.0.1:8080?token=x", "", true},
	}
	for _, tc := range cases {
		got, err := buildIngestEndpoint(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%q accepted", tc.in)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("%q -> %q (%v)", tc.in, got, err)
		}
	}
}

func TestGeneratorsProduceValidEvents(t *testing.T) {
	for _, scenario := range []string{scenarioNormal, scenarioAbtau, scenarioTuer, scenarioAngriff, scenarioAngriffMgmtUI} {
		scenario := scenario
		t.Run(scenario, func(t *testing.T) {
			generator, err := newFeedGenerator(scenario, "filiale-001", "zone-kaelte-1")
			if err != nil {
				t.Fatalf("generator: %v", err)
			}
			kinds := make(map[domain.EventKind]int)
			for i := 0; i < 120; i++ {
				event, err := generator.Next()
				if err != nil {
					t.Fatalf("next: %v", err)
				}
				if err := event.Validate(); err != nil {
					t.Fatalf("invalid event: %v", err)
				}
				kinds[event.Kind]++
			}
			if kinds[domain.EventTelemetry] == 0 {
				t.Fatal("no telemetry event generated")
			}
			switch scenario {
			case scenarioAngriff, scenarioAngriffMgmtUI:
				if kinds[domain.EventWriteAttempt] == 0 {
					t.Fatal("attack scenario generates no write_attempt")
				}
			case scenarioNormal, scenarioAbtau, scenarioTuer:
				if kinds[domain.EventWriteAttempt] != 0 {
					t.Fatal("benign scenario must not generate write_attempt")
				}
			}
		})
	}
	if _, err := newFeedGenerator("unbekannt", "filiale-001", "zone-1"); err == nil {
		t.Fatal("unknown scenario accepted")
	}
}

func TestPCAPGeneration(t *testing.T) {
	out := t.TempDir()
	var stdout, errOut bytes.Buffer
	if err := runPCAP([]string{"--out", out, "--scenario", "all"}, &stdout, &errOut); err != nil {
		t.Fatalf("pcap: %v (stderr %s)", err, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("summary lines = %v", lines)
	}
	for _, name := range []string{"normal.pcap", "angriff.pcap", "angriff-management-ui.pcap"} {
		path := filepath.Join(out, name)
		info, err := os.Stat(path)
		if err != nil || info.Size() == 0 {
			t.Fatalf("%s missing: %v", name, err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		reader, err := pcapdb.NewReader(file)
		if err != nil {
			_ = file.Close()
			t.Fatalf("reader %s: %v", name, err)
		}
		packets := 0
		for {
			record, err := reader.Next()
			if err != nil {
				break
			}
			if _, err := pcapdb.Decode(reader.LinkType(), record.Data, record.Timestamp); err == nil {
				packets++
			}
		}
		_ = file.Close()
		if packets == 0 {
			t.Fatalf("%s has no decodable packets", name)
		}
	}
}

func TestModbusServerRejectsWritesAndServesReads(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	addr := reserved.Addr().String()
	_ = reserved.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		done <- serveModbusServer(ctx, addr, "normal", 1, &stdout, &stderr)
	}()
	conn := dialEventually(t, addr)
	defer func() { _ = conn.Close() }()

	// A write request is rejected with exception 0x01 and must not mutate state.
	if _, err := conn.Write(modbusFrame(10, 1, 6, 1, 120)); err != nil {
		t.Fatalf("write fc6: %v", err)
	}
	header, body := readModbusFrame(t, conn)
	if header != 10 {
		t.Fatalf("transaction id = %d", header)
	}
	if len(body) != 2 || body[0] != 0x86 || body[1] != 0x01 {
		t.Fatalf("write exception = %v", body)
	}
	// A read returns the unmodified setpoint (4.0 C -> 40).
	if _, err := conn.Write(modbusFrame(11, 1, 3, 0, 5)); err != nil {
		t.Fatalf("read: %v", err)
	}
	_, body = readModbusFrame(t, conn)
	if len(body) != 12 || body[0] != 0x03 || body[1] != 10 {
		t.Fatalf("read response = %v", body)
	}
	values := []uint16{}
	for i := 2; i+1 < len(body); i += 2 {
		values = append(values, binary.BigEndian.Uint16(body[i:i+2]))
	}
	if values[0] != 42 || values[1] != 40 {
		t.Fatalf("register values = %v", values)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("modbus server did not stop")
	}
}

func TestRunUsageAndVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(nil, &stdout, &stderr); err == nil {
		t.Fatal("missing subcommand must fail")
	}
	stdout.Reset()
	if err := run([]string{"version"}, &stdout, &stderr); err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(stdout.String(), "retail-sim") {
		t.Fatalf("version output = %q", stdout.String())
	}
	stdout.Reset()
	if err := run([]string{"help"}, &stdout, &stderr); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(stdout.String(), "modbus-server") {
		t.Fatalf("help output = %q", stdout.String())
	}
	if err := run([]string{"nope"}, &stdout, &stderr); err == nil {
		t.Fatal("unknown subcommand accepted")
	}
}

// helpers

func modbusFrame(txID uint16, unit uint8, fc uint8, address, value uint16) []byte {
	pdu := []byte{fc, byte(address >> 8), byte(address), byte(value >> 8), byte(value)}
	frame := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(frame[0:2], txID)
	binary.BigEndian.PutUint16(frame[4:6], uint16(1+len(pdu)))
	frame[6] = unit
	copy(frame[7:], pdu)
	return frame
}

func readModbusFrame(t *testing.T, conn net.Conn) (uint16, []byte) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	header := make([]byte, 6)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("read header: %v", err)
	}
	length := int(binary.BigEndian.Uint16(header[4:6]))
	t.Logf("modbus response header=%v length=%d", header, length)
	if length < 2 || length > 260 {
		t.Fatalf("bad length %d", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return binary.BigEndian.Uint16(header[0:2]), body[1:]
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
