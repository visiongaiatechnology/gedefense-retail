package snmp

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// fakeAgent is a loopback SNMP agent that records request PDU types and answers
// GetRequest with fixed integer values.
type fakeAgent struct {
	conn *net.UDPConn

	mu      sync.Mutex
	pduTags []byte
}

func newFakeAgent(t *testing.T) *fakeAgent {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	agent := &fakeAgent{conn: conn}
	t.Cleanup(func() { _ = conn.Close() })
	go agent.serve()
	return agent
}

func (a *fakeAgent) addr() string { return a.conn.LocalAddr().String() }

func (a *fakeAgent) recordedTags() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte{}, a.pduTags...)
}

func (a *fakeAgent) serve() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		request, err := parseRequestForTest(buf[:n])
		if err != nil {
			continue
		}
		a.mu.Lock()
		a.pduTags = append(a.pduTags, request.pduTag)
		a.mu.Unlock()
		response := buildResponseForTest(request)
		_, _ = a.conn.WriteToUDP(response, addr)
	}
}

type parsedRequest struct {
	version   int
	requestID int32
	pduTag    byte
	oids      []string
}

func parseRequestForTest(packet []byte) (parsedRequest, error) {
	root, _, err := readElement(packet, 0)
	if err != nil || root.tag != tagSequence {
		return parsedRequest{}, errMalformed
	}
	out := parsedRequest{}
	offset := 0
	versionElem, offset, err := readElement(root.content, offset)
	if err != nil || versionElem.tag != tagInteger {
		return parsedRequest{}, errMalformed
	}
	version, ok := decodeInt32(versionElem.content)
	if !ok {
		return parsedRequest{}, errMalformed
	}
	out.version = int(version)
	if _, offset, err = readElement(root.content, offset); err != nil { // community
		return parsedRequest{}, err
	}
	pdu, _, err := readElement(root.content, offset)
	if err != nil {
		return parsedRequest{}, err
	}
	out.pduTag = pdu.tag
	inner := 0
	requestIDElem, inner, err := readElement(pdu.content, inner)
	if err != nil || requestIDElem.tag != tagInteger {
		return parsedRequest{}, errMalformed
	}
	requestID, ok := decodeInt32(requestIDElem.content)
	if !ok {
		return parsedRequest{}, errMalformed
	}
	out.requestID = requestID
	if _, inner, err = readElement(pdu.content, inner); err != nil { // error status
		return parsedRequest{}, err
	}
	if _, inner, err = readElement(pdu.content, inner); err != nil { // error index
		return parsedRequest{}, err
	}
	list, _, err := readElement(pdu.content, inner)
	if err != nil || list.tag != tagSequence {
		return parsedRequest{}, errMalformed
	}
	vbOffset := 0
	for vbOffset < len(list.content) {
		sequence, next, err := readElement(list.content, vbOffset)
		if err != nil || sequence.tag != tagSequence {
			return parsedRequest{}, errMalformed
		}
		vbOffset = next
		oidElem, _, err := readElement(sequence.content, 0)
		if err != nil || oidElem.tag != tagOID {
			return parsedRequest{}, errMalformed
		}
		oid, err := decodeOIDContent(oidElem.content)
		if err != nil {
			return parsedRequest{}, err
		}
		out.oids = append(out.oids, oid)
	}
	return out, nil
}

func buildResponseForTest(request parsedRequest) []byte {
	varbinds := make([][]byte, 0, len(request.oids))
	for i, oid := range request.oids {
		encodedOID, err := encodeOID(oid)
		if err != nil {
			continue
		}
		varbinds = append(varbinds, encodeSequence(encodedOID, encodeInteger(int64(100+i))))
	}
	pdu := encodeTLV(tagResponse, concat(
		encodeInteger(int64(request.requestID)),
		encodeInteger(0),
		encodeInteger(0),
		encodeSequence(varbinds...),
	))
	return encodeSequence(
		encodeInteger(int64(request.version)),
		encodeOctetString("public"),
		pdu,
	)
}

func newSNMPAdapter(t *testing.T, target string) collect.AdapterConfig {
	t.Helper()
	return collect.AdapterConfig{
		AdapterID: "snmp.test",
		SiteID:    "filiale-001",
		Options: map[string]string{
			"targets":   target,
			"community": "public",
			"version":   "2c",
			"interval":  "60ms",
			"timeout":   "500ms",
			"oids":      "1.3.6.1.2.1.1.3.0|sensor_01|sys_uptime|seconds",
		},
	}
}

func TestPollsWithGetRequestOnly(t *testing.T) {
	t.Parallel()
	agent := newFakeAgent(t)
	col, err := New(newSNMPAdapter(t, agent.addr()))
	if err != nil {
		t.Fatalf("new snmp adapter: %v", err)
	}
	if !col.Info().ReadOnly {
		t.Fatal("snmp adapter reports ReadOnly=false")
	}
	sink := &snmpCaptureSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- col.Start(ctx, sink) }()
	waitSNMP(t, 3*time.Second, func() bool { return len(sink.ofKind(domain.EventTelemetry)) >= 1 })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("snmp adapter did not stop on cancel")
	}
	tags := agent.recordedTags()
	if len(tags) == 0 {
		t.Fatal("agent received no request")
	}
	for _, tag := range tags {
		if tag != tagGetRequest {
			t.Fatalf("adapter sent PDU 0x%02x; only GetRequest is allowed", tag)
		}
	}
	telemetry := sink.ofKind(domain.EventTelemetry)
	if telemetry[0].Measurement == nil || telemetry[0].Measurement.Metric != "sys_uptime" {
		t.Fatalf("measurement = %+v", telemetry[0].Measurement)
	}
}

func TestSNMPv3IsExplicitlyNotImplemented(t *testing.T) {
	t.Parallel()
	cfg := collect.AdapterConfig{AdapterID: "snmp.v3", SiteID: "filiale-001", Options: map[string]string{
		"targets": "127.0.0.1:161", "community": "secret", "version": "3",
		"oids": "1.3.6.1.2.1.1.3.0|sensor_01|sys_uptime|seconds",
	}}
	_, err := New(cfg)
	if !errors.Is(err, ErrSNMPv3NotImplemented) {
		t.Fatalf("want ErrSNMPv3NotImplemented, got %v", err)
	}
	if SNMPv3Supported {
		t.Fatal("SNMPv3Supported must be false in the MVP")
	}
}

func TestHealthWarnsAboutPlaintextCommunity(t *testing.T) {
	t.Parallel()
	cfg := newSNMPAdapter(t, "127.0.0.1:161")
	col, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	health, ok := col.(collect.HealthState)
	if !ok {
		t.Fatal("snmp adapter does not implement collect.HealthState")
	}
	state, warning := health.HealthState()
	if state != "degraded" || warning == "" || warning != HealthWarning {
		t.Fatalf("health state = %q warning = %q", state, warning)
	}
}

func TestParseOIDMappingsValidation(t *testing.T) {
	t.Parallel()
	if _, err := ParseOIDMappings("1.3.6.1.2.1.1.3.0|sensor_01|sys_uptime|seconds"); err != nil {
		t.Fatalf("valid mapping rejected: %v", err)
	}
	for _, raw := range []string{
		"not-an-oid|sensor_01|m|seconds",
		"1.3.6.1|bad sensor|m|seconds",
		"1.3.6.1|sensor_01|m|banana",
		"1.3.6.1|sensor_01|m",
	} {
		if _, err := ParseOIDMappings(raw); err == nil {
			t.Fatalf("mapping %q should be rejected", raw)
		}
	}
}

func TestBuildGetRequestHasNoSetPdu(t *testing.T) {
	t.Parallel()
	request, err := buildGetRequest(1, "public", 7, []string{"1.3.6.1.2.1.1.3.0"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	root, _, err := readElement(request, 0)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	offset := 0
	if _, offset, err = readElement(root.content, offset); err != nil {
		t.Fatalf("version: %v", err)
	}
	if _, offset, err = readElement(root.content, offset); err != nil {
		t.Fatalf("community: %v", err)
	}
	pdu, _, err := readElement(root.content, offset)
	if err != nil {
		t.Fatalf("pdu: %v", err)
	}
	if pdu.tag != tagGetRequest {
		t.Fatalf("request PDU = 0x%02x, want GetRequest", pdu.tag)
	}
}

func TestParseResponseRejectsMalformed(t *testing.T) {
	t.Parallel()
	for _, packet := range [][]byte{
		nil,
		{0x30},
		{0x30, 0x03, 0x02, 0x01, 0x00},
		[]byte("not-ber"),
	} {
		if _, err := parseResponse(packet); err == nil {
			t.Fatalf("packet %v should be rejected", packet)
		}
	}
}

func FuzzParseResponse(f *testing.F) {
	agent := parsedRequest{version: 1, requestID: 3, pduTag: tagResponse, oids: []string{"1.3.6.1.2.1.1.3.0"}}
	f.Add(buildResponseForTest(agent))
	f.Add(buildResponseForTest(parsedRequest{version: 1, requestID: 4, oids: []string{"1.3.6.1.4.1.9.1"}}))
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 4096 {
			return
		}
		_, _ = parseResponse(packet)
	})
}

type snmpCaptureSink struct {
	mu     sync.Mutex
	events []domain.Event
}

func (s *snmpCaptureSink) Emit(_ context.Context, ev domain.Event) error {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	return nil
}

func (s *snmpCaptureSink) ofKind(kind domain.EventKind) []domain.Event {
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

func waitSNMP(t *testing.T, timeout time.Duration, condition func() bool) {
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
