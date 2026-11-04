package deviceio

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/fakedev"
)

func newFake(t *testing.T) (*fakedev.Modbus, Config) {
	t.Helper()
	device, err := fakedev.NewModbus(fakedev.ModbusConfig{Holding: []uint16{40, 41}})
	if err != nil {
		t.Fatalf("fake device: %v", err)
	}
	if err := device.Start(); err != nil {
		t.Fatalf("start fake: %v", err)
	}
	t.Cleanup(func() { _ = device.Close() })
	host, port, err := net.SplitHostPort(device.Addr())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	_ = host
	return device, Config{Addr: net.JoinHostPort("127.0.0.1", port), UnitID: 1, Timeout: 2 * time.Second}
}

func TestReadWriteHoldingRegister(t *testing.T) {
	device, cfg := newFake(t)
	client, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	value, err := client.ReadHoldingRegister(context.Background(), 0)
	if err != nil || value != 40 {
		t.Fatalf("read = %d, err=%v", value, err)
	}
	if err := client.WriteSingleRegister(context.Background(), 0, 35); err != nil {
		t.Fatalf("write: %v", err)
	}
	value, err = client.ReadHoldingRegister(context.Background(), 0)
	if err != nil || value != 35 {
		t.Fatalf("read after write = %d, err=%v", value, err)
	}
	if got := device.State(); got.WriteADUs != 1 || got.Holding[0] != 35 {
		t.Fatalf("device state = %+v", got)
	}
}

func TestReadExceptionFailsClosed(t *testing.T) {
	_, cfg := newFake(t)
	client, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	// Address 500 is outside the fake device's 16-register map -> exception 0x02.
	if _, err := client.ReadHoldingRegister(context.Background(), 500); !errors.Is(err, ErrException) {
		t.Fatalf("read exception error = %v", err)
	}
}

func TestShortAndPartialResponsesFailClosed(t *testing.T) {
	cases := []struct {
		name    string
		respond func(conn net.Conn, req []byte)
	}{
		{"short header", func(conn net.Conn, _ []byte) { _, _ = conn.Write([]byte{0, 1}) }},
		{"partial body", func(conn net.Conn, req []byte) {
			_, _ = conn.Write([]byte{req[0], req[1], 0, 0, 0, 3, 1, 3})
		}},
		{"wrong transaction", func(conn net.Conn, req []byte) {
			body := []byte{1, 3, 2, 0, 40}
			_, _ = conn.Write(append([]byte{0, 9, 0, 0, 0, byte(len(body))}, body...))
		}},
		{"wrong unit", func(conn net.Conn, req []byte) {
			body := []byte{2, 3, 2, 0, 40}
			_, _ = conn.Write(append([]byte{req[0], req[1], 0, 0, 0, byte(len(body))}, body...))
		}},
		{"garbage", func(conn net.Conn, _ []byte) { _, _ = conn.Write([]byte("not-modbus")) }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = ln.Close() }()
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				req := make([]byte, 12)
				_, _ = conn.Read(req)
				tc.respond(conn, req)
			}()
			client, err := Dial(context.Background(), Config{Addr: ln.Addr().String(), UnitID: 1, Timeout: time.Second})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = client.Close() }()
			if _, err := client.ReadHoldingRegister(context.Background(), 0); err == nil {
				t.Fatal("expected fail-closed error")
			}
		})
	}
}

func TestTimeoutFailsClosed(t *testing.T) {
	device, err := fakedev.NewModbus(fakedev.ModbusConfig{Holding: []uint16{40}, ResponseDelay: 300 * time.Millisecond})
	if err != nil {
		t.Fatalf("fake: %v", err)
	}
	if err := device.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = device.Close() }()
	client, err := Dial(context.Background(), Config{Addr: device.Addr(), UnitID: 1, Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	start := time.Now()
	if _, err := client.ReadHoldingRegister(context.Background(), 0); err == nil {
		t.Fatal("timeout not enforced")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
}

func TestBuildRequestLayout(t *testing.T) {
	raw := buildRequest(7, 1, []byte{3, 0, 0, 0, 1})
	if len(raw) != 12 || binary.BigEndian.Uint16(raw[0:2]) != 7 || binary.BigEndian.Uint16(raw[4:6]) != 6 || raw[6] != 1 {
		t.Fatalf("request = %x", raw)
	}
}
