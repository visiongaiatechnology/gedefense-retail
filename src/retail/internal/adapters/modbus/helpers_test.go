package modbus

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Fuzz helpers and frame builders (test-only; write frames exist only here and
// in the simulator, never in the adapter API).

func testMetaFuzz() collect.Meta {
	return collect.Meta{SiteID: "filiale-001", Source: "modbus.fuzz", Collection: collect.CollectionPassiveTap}
}

func readRequestFrame(txID uint16, fc uint8, addr, qty uint16) []byte {
	return encodeReadRequest(txID, 1, fc, addr, qty)
}

func readResponseFrame(txID uint16, fc uint8, values []uint16) []byte {
	pdu := []byte{fc, byte(2 * len(values))}
	for _, value := range values {
		pdu = append(pdu, byte(value>>8), byte(value))
	}
	return mbapTestFrame(txID, 1, pdu)
}

func writeSingleRegisterFrame(txID uint16, unit uint8, addr, value uint16) []byte {
	pdu := []byte{fcWriteSingleRegister, byte(addr >> 8), byte(addr), byte(value >> 8), byte(value)}
	return mbapTestFrame(txID, unit, pdu)
}

func mbapTestFrame(txID uint16, unit uint8, pdu []byte) []byte {
	frame := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(frame[0:2], txID)
	binary.BigEndian.PutUint16(frame[4:6], uint16(1+len(pdu)))
	frame[6] = unit
	copy(frame[7:], pdu)
	return frame
}

func mustSpecs(t *testing.T, raw string) []RegisterSpec {
	t.Helper()
	specs, err := ParseRegisterSpec(raw)
	if err != nil {
		t.Fatalf("spec %q: %v", raw, err)
	}
	return specs
}

func almostEqual(a, b float64) bool {
	if a > b {
		a, b = b, a
	}
	return b-a < 1e-9
}

func kinds(events []domain.Event) []domain.EventKind {
	out := make([]domain.EventKind, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.Kind)
	}
	return out
}

// captureSink records events by kind.
type captureSink struct {
	mu     sync.Mutex
	events []domain.Event
}

func (s *captureSink) Emit(_ context.Context, ev domain.Event) error {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	return nil
}

func (s *captureSink) byKind(kind domain.EventKind) []domain.Event {
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

func (s *captureSink) telemetry() []domain.Event { return s.byKind(domain.EventTelemetry) }
func (s *captureSink) writeAttempts() []domain.Event {
	return s.byKind(domain.EventWriteAttempt)
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

// fakeModbusServer is a loopback-only simulator that records request function
// codes and answers FC3/FC4 reads with fixed values.
type fakeModbusServer struct {
	listener      net.Listener
	mu            sync.Mutex
	functionCodes []uint8
	writeFnCodes  []uint8
}

func newFakeModbusServer(t *testing.T) *fakeModbusServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeModbusServer{listener: ln}
	go s.serve()
	return s
}

func (s *fakeModbusServer) Addr() string { return s.listener.Addr().String() }

func (s *fakeModbusServer) Close() {
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func (s *fakeModbusServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.serveConn(conn)
	}
}

func (s *fakeModbusServer) serveConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	header := make([]byte, 6)
	for {
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(header[4:6]))
		if length < 2 || length > 260 {
			return
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		txID := binary.BigEndian.Uint16(header[0:2])
		unit := body[0]
		pdu := body[1:]
		fc := pdu[0]
		s.mu.Lock()
		s.functionCodes = append(s.functionCodes, fc)
		if fc != fcReadHolding && fc != fcReadInput {
			s.writeFnCodes = append(s.writeFnCodes, fc)
		}
		s.mu.Unlock()
		var response []byte
		switch fc {
		case fcReadHolding, fcReadInput:
			quantity := binary.BigEndian.Uint16(pdu[3:5])
			values := make([]uint16, quantity)
			for i := range values {
				values[i] = 42
			}
			response = readResponseFrame(txID, fc, values)
			response[6] = unit
		default:
			response = mbapTestFrame(txID, unit, []byte{fc | 0x80, 0x01})
		}
		if _, err := conn.Write(response); err != nil {
			return
		}
	}
}
