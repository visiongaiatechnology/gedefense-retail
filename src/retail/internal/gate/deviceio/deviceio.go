// Package deviceio is the strict Modbus/TCP client used by the gate integrity
// worker and recovery path. It only implements the two operations needed for
// setpoint integrity: read one holding register (FC3) and write one holding
// register (FC6). Every malformed, partial, wrong-transaction or exception
// response fails closed; the connection is discarded and the caller must treat
// the outcome as unknown/unreadable.
package deviceio

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// Limits keep a hostile/broken device from exhausting gate resources.
const (
	maxADUBytes    = 260
	readHeaderLen  = 6
	unitIDOffset   = 0
	fcReadHolding  = 3
	fcWriteSingle  = 6
	mbapHeaderSize = 7
)

// ErrProtocol reports a structurally invalid Modbus response (fail-closed).
var ErrProtocol = errors.New("deviceio: modbus protocol error")

// ErrException reports a Modbus exception response from the device.
var ErrException = errors.New("deviceio: modbus exception")

// Config configures one downstream device connection.
type Config struct {
	Addr    string
	UnitID  uint8
	Timeout time.Duration
}

// Validate checks the mandatory settings.
func (c Config) Validate() error {
	if c.Addr == "" {
		return errors.New("deviceio: address is required")
	}
	if c.UnitID == 0 {
		return errors.New("deviceio: unit id 0 (broadcast) is not allowed")
	}
	if c.Timeout <= 0 {
		return errors.New("deviceio: timeout is required")
	}
	return nil
}

// Client is one short-lived strict Modbus/TCP connection. It is not safe for
// concurrent use: the integrity worker serializes all device access.
type Client struct {
	cfg  Config
	conn net.Conn
	rd   *bufio.Reader
	txn  atomic.Uint32
}

// Dial opens the downstream connection.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("deviceio: dial %s: %w", cfg.Addr, err)
	}
	return &Client{cfg: cfg, conn: conn, rd: bufio.NewReaderSize(conn, 512)}, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// ReadHoldingRegister reads exactly one holding register (FC3).
func (c *Client) ReadHoldingRegister(ctx context.Context, register uint16) (uint16, error) {
	txn := uint16(c.txn.Add(1))
	req := buildRequest(txn, c.cfg.UnitID, []byte{fcReadHolding, byte(register >> 8), byte(register), 0, 1})
	resp, err := c.transact(ctx, req)
	if err != nil {
		return 0, err
	}
	if len(resp) < 2 || resp[0] != fcReadHolding {
		return 0, fmt.Errorf("%w: unexpected read response %x", ErrProtocol, resp)
	}
	byteCount := int(resp[1])
	if byteCount != 2 || len(resp) != 2+byteCount {
		return 0, fmt.Errorf("%w: invalid read byte count %d", ErrProtocol, byteCount)
	}
	return binary.BigEndian.Uint16(resp[2:4]), nil
}

// WriteSingleRegister writes one holding register (FC6) and validates the
// device echo. A write is never retried by this client.
func (c *Client) WriteSingleRegister(ctx context.Context, register, value uint16) error {
	txn := uint16(c.txn.Add(1))
	req := buildRequest(txn, c.cfg.UnitID, []byte{fcWriteSingle, byte(register >> 8), byte(register), byte(value >> 8), byte(value)})
	resp, err := c.transact(ctx, req)
	if err != nil {
		return err
	}
	if len(resp) != 5 || resp[0] != fcWriteSingle ||
		binary.BigEndian.Uint16(resp[1:3]) != register || binary.BigEndian.Uint16(resp[3:5]) != value {
		return fmt.Errorf("%w: write echo mismatch %x", ErrProtocol, resp)
	}
	return nil
}

// transact sends one PDU and returns the response PDU (without MBAP header).
func (c *Client) transact(ctx context.Context, req []byte) ([]byte, error) {
	if c.conn == nil {
		return nil, errors.New("deviceio: connection closed")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("deviceio: set deadline: %w", err)
		}
	} else {
		if err := c.conn.SetDeadline(time.Now().Add(c.cfg.Timeout)); err != nil {
			return nil, fmt.Errorf("deviceio: set deadline: %w", err)
		}
	}
	if _, err := c.conn.Write(req); err != nil {
		return nil, fmt.Errorf("deviceio: write: %w", err)
	}
	header := make([]byte, readHeaderLen)
	if _, err := io.ReadFull(c.rd, header); err != nil {
		return nil, fmt.Errorf("deviceio: read header: %w", err)
	}
	txn := binary.BigEndian.Uint16(header[0:2])
	proto := binary.BigEndian.Uint16(header[2:4])
	length := int(binary.BigEndian.Uint16(header[4:6]))
	if proto != 0 {
		return nil, fmt.Errorf("%w: protocol id %d", ErrProtocol, proto)
	}
	if length < 2 || length > maxADUBytes-mbapHeaderSize+1 {
		return nil, fmt.Errorf("%w: length %d out of range", ErrProtocol, length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c.rd, body); err != nil {
		return nil, fmt.Errorf("deviceio: read body: %w", err)
	}
	if txn != binary.BigEndian.Uint16(req[0:2]) {
		return nil, fmt.Errorf("%w: transaction id %d != %d", ErrProtocol, txn, binary.BigEndian.Uint16(req[0:2]))
	}
	if body[unitIDOffset] != c.cfg.UnitID {
		return nil, fmt.Errorf("%w: unit id %d != %d", ErrProtocol, body[0], c.cfg.UnitID)
	}
	pdu := body[1:]
	if len(pdu) == 0 {
		return nil, fmt.Errorf("%w: empty pdu", ErrProtocol)
	}
	if pdu[0]&0x80 != 0 {
		code := uint8(0)
		if len(pdu) > 1 {
			code = pdu[1]
		}
		return nil, fmt.Errorf("%w: function 0x%02x code 0x%02x", ErrException, pdu[0]&0x7f, code)
	}
	if pdu[0] != req[mbapHeaderSize] {
		return nil, fmt.Errorf("%w: function 0x%02x != 0x%02x", ErrProtocol, pdu[0], req[mbapHeaderSize])
	}
	return pdu, nil
}

// buildRequest builds one MBAP + PDU request.
func buildRequest(txn uint16, unitID uint8, pdu []byte) []byte {
	raw := make([]byte, mbapHeaderSize+len(pdu))
	binary.BigEndian.PutUint16(raw[0:2], txn)
	binary.BigEndian.PutUint16(raw[2:4], 0)
	binary.BigEndian.PutUint16(raw[4:6], uint16(1+len(pdu)))
	raw[6] = unitID
	copy(raw[7:], pdu)
	return raw
}
