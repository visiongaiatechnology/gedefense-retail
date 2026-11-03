// Package fakedev provides loopback-only fake OT devices for the Access Gate
// test suite. It is deliberately not able to listen on a routable address: the
// gate tests must never touch real controllers.
package fakedev

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ModbusConfig configures the fake Modbus/TCP controller.
type ModbusConfig struct {
	Listen  string // loopback only; default 127.0.0.1:0
	UnitID  uint8
	Holding []uint16
	Input   []uint16
	// ResponseDelay simulates a slow controller (timeout tests).
	ResponseDelay time.Duration
	Coils         []bool
}

// ModbusState is a consistent snapshot of the fake controller.
type ModbusState struct {
	Holding        []uint16
	Input          []uint16
	Coils          []bool
	Requests       uint64
	WriteADUs      uint64
	LastWriteFC    uint8
	LastWriteAddr  uint16
	LastWriteValue uint16
	Connects       uint64
	Connected      int
	LastRequestRaw []byte
}

// Modbus is a minimal, loopback-only Modbus/TCP slave used as a test fixture.
type Modbus struct {
	cfg ModbusConfig

	mu      sync.Mutex
	ln      net.Listener
	holding []uint16
	input   []uint16
	coils   []bool
	conns   map[net.Conn]struct{}
	lastRaw []byte
	closed  bool
	wg      sync.WaitGroup

	connects atomic.Uint64
	requests atomic.Uint64
	writes   atomic.Uint64
	lastFC   atomic.Uint32
	lastAddr atomic.Uint32
	lastVal  atomic.Uint32
}

// NewModbus validates the configuration and returns an unstarted fake device.
func NewModbus(cfg ModbusConfig) (*Modbus, error) {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	if err := requireLoopback(cfg.Listen); err != nil {
		return nil, err
	}
	if cfg.UnitID == 0 {
		cfg.UnitID = 1
	}
	if len(cfg.Holding) == 0 {
		cfg.Holding = []uint16{40, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	}
	if len(cfg.Input) == 0 {
		cfg.Input = []uint16{42, 39, 44, 0, 0, 0, 0, 0}
	}
	if len(cfg.Coils) == 0 {
		cfg.Coils = make([]bool, 8)
	}
	return &Modbus{
		cfg:     cfg,
		holding: append([]uint16{}, cfg.Holding...),
		input:   append([]uint16{}, cfg.Input...),
		coils:   append([]bool{}, cfg.Coils...),
		conns:   make(map[net.Conn]struct{}),
	}, nil
}

// Start binds the loopback listener.
func (m *Modbus) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ln != nil {
		return errors.New("fakedev: modbus already started")
	}
	ln, err := net.Listen("tcp", m.cfg.Listen)
	if err != nil {
		return fmt.Errorf("fakedev modbus: listen: %w", err)
	}
	m.ln = ln
	m.wg.Add(1)
	go m.acceptLoop(ln)
	return nil
}

// Addr returns the bound address.
func (m *Modbus) Addr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ln == nil {
		return ""
	}
	return m.ln.Addr().String()
}

// Close stops the fake device.
func (m *Modbus) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	ln := m.ln
	m.ln = nil
	for conn := range m.conns {
		_ = conn.Close()
	}
	m.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	m.wg.Wait()
	return nil
}

// State returns the current register map and counters.
func (m *Modbus) State() ModbusState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return ModbusState{
		Holding:        append([]uint16{}, m.holding...),
		Input:          append([]uint16{}, m.input...),
		Coils:          append([]bool{}, m.coils...),
		Connects:       m.connects.Load(),
		Requests:       m.requests.Load(),
		WriteADUs:      m.writes.Load(),
		LastWriteFC:    uint8(m.lastFC.Load()),
		LastWriteAddr:  uint16(m.lastAddr.Load()),
		LastWriteValue: uint16(m.lastVal.Load()),
		Connected:      len(m.conns),
		LastRequestRaw: append([]byte{}, m.lastRaw...),
	}
}

func (m *Modbus) acceptLoop(ln net.Listener) {
	defer m.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			_ = conn.Close()
			return
		}
		m.conns[conn] = struct{}{}
		m.connects.Add(1)
		m.mu.Unlock()
		m.wg.Add(1)
		go func(c net.Conn) {
			defer m.wg.Done()
			defer func() { _ = c.Close() }()
			defer func() {
				m.mu.Lock()
				delete(m.conns, c)
				m.mu.Unlock()
			}()
			m.serve(c)
		}(conn)
	}
}

// serve answers read requests and records every write ADU that reaches the
// device. The counter is the null-write proof for the gate tests.
func (m *Modbus) serve(conn net.Conn) {
	reader := bufio.NewReaderSize(conn, 4096)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}
		header := make([]byte, 6)
		if _, err := io.ReadFull(reader, header); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(header[4:6]))
		if length < 2 || length > 254 {
			return
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(reader, body); err != nil {
			return
		}
		transactionID := binary.BigEndian.Uint16(header[0:2])
		unit := body[0]
		pdu := body[1:]
		if len(pdu) == 0 {
			return
		}
		m.mu.Lock()
		m.lastRaw = append(append([]byte{}, header...), body...)
		m.mu.Unlock()
		m.requests.Add(1)
		if m.cfg.ResponseDelay > 0 {
			time.Sleep(m.cfg.ResponseDelay)
		}
		m.mu.Lock()
		response := m.respond(unit, pdu)
		m.mu.Unlock()
		if response == nil {
			continue
		}
		out := make([]byte, 7+len(response))
		binary.BigEndian.PutUint16(out[0:2], transactionID)
		binary.BigEndian.PutUint16(out[4:6], uint16(1+len(response)))
		out[6] = unit
		copy(out[7:], response)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// respond executes one PDU against the register map (caller holds m.mu).
func (m *Modbus) respond(unit uint8, pdu []byte) []byte {
	if unit != m.cfg.UnitID {
		return exceptionPDU(pdu[0], 0x0b)
	}
	fc := pdu[0]
	switch fc {
	case 1, 2: // read coils / discrete inputs
		if len(pdu) != 5 {
			return exceptionPDU(fc, 0x03)
		}
		start := binary.BigEndian.Uint16(pdu[1:3])
		qty := int(binary.BigEndian.Uint16(pdu[3:5]))
		if qty < 1 || qty > 2000 {
			return exceptionPDU(fc, 0x03)
		}
		if fc == 2 {
			// The fake device exposes no discrete inputs: valid but empty bits.
			return readBitsResponse(fc, uint16(qty), nil, int(start))
		}
		return readBitsResponse(fc, uint16(qty), m.coils, int(start))
	case 3, 4: // read holding / input registers
		if len(pdu) != 5 {
			return exceptionPDU(fc, 0x03)
		}
		start := int(binary.BigEndian.Uint16(pdu[1:3]))
		qty := int(binary.BigEndian.Uint16(pdu[3:5]))
		if qty < 1 || qty > 125 {
			return exceptionPDU(fc, 0x03)
		}
		source := m.holding
		if fc == 4 {
			source = m.input
		}
		if start < 0 || start+qty > len(source) {
			return exceptionPDU(fc, 0x02)
		}
		response := []byte{fc, byte(2 * qty)}
		for i := 0; i < qty; i++ {
			value := source[start+i]
			response = append(response, byte(value>>8), byte(value))
		}
		return response
	case 5: // write single coil
		if len(pdu) != 5 {
			return exceptionPDU(fc, 0x03)
		}
		m.writes.Add(1)
		address := binary.BigEndian.Uint16(pdu[1:3])
		raw := binary.BigEndian.Uint16(pdu[3:5])
		m.lastFC.Store(uint32(fc))
		m.lastAddr.Store(uint32(address))
		m.lastVal.Store(uint32(raw))
		if int(address) >= len(m.coils) {
			return exceptionPDU(fc, 0x02)
		}
		switch raw {
		case 0xff00:
			m.coils[address] = true
		case 0x0000:
			m.coils[address] = false
		default:
			return exceptionPDU(fc, 0x03)
		}
		return append([]byte{}, pdu...)
	case 6: // write single register
		if len(pdu) != 5 {
			return exceptionPDU(fc, 0x03)
		}
		m.writes.Add(1)
		address := binary.BigEndian.Uint16(pdu[1:3])
		value := binary.BigEndian.Uint16(pdu[3:5])
		m.lastFC.Store(uint32(fc))
		m.lastAddr.Store(uint32(address))
		m.lastVal.Store(uint32(value))
		if int(address) >= len(m.holding) {
			return exceptionPDU(fc, 0x02)
		}
		m.holding[address] = value
		return append([]byte{}, pdu...)
	case 15, 16:
		// The fixture supports single writes; multi-writes are still counted as
		// write ADUs so the null-write proof remains valid.
		m.writes.Add(1)
		m.lastFC.Store(uint32(fc))
		return exceptionPDU(fc, 0x01)
	default:
		return exceptionPDU(fc, 0x01)
	}
}

func readBitsResponse(fc uint8, qty uint16, bits []bool, start int) []byte {
	byteCount := int(qty+7) / 8
	response := []byte{fc, byte(byteCount)}
	payload := make([]byte, byteCount)
	for i := 0; i < int(qty); i++ {
		idx := start + i
		if idx < 0 || idx >= len(bits) || !bits[idx] {
			continue
		}
		payload[i/8] |= 1 << (uint(i) % 8)
	}
	return append(response, payload...)
}

func exceptionPDU(function, code uint8) []byte {
	return []byte{function | 0x80, code}
}

// requireLoopback rejects any listen address that is not a loopback address.
func requireLoopback(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("fakedev: invalid listen %q: %w", listen, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("fakedev: listen host must be an IP address: %w", err)
	}
	if !addr.IsLoopback() {
		return fmt.Errorf("fakedev: %q is not loopback (fixtures may only bind loopback)", listen)
	}
	return nil
}
