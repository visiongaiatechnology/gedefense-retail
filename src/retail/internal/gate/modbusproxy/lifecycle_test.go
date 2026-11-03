package modbusproxy

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestProxyLifecycle(t *testing.T) {
	t.Parallel()
	auth := &fakeAuth{consumeOK: true}
	proxy, _ := newTestProxy(t, auth, nil)
	if proxy.Addr() == "" {
		t.Fatal("no listen address after start")
	}
	if err := proxy.Start(context.Background()); err == nil {
		t.Fatal("second Start must fail")
	}
	if err := proxy.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := proxy.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if got := proxy.Stats().State; got != "stopped" {
		t.Fatalf("state = %q", got)
	}
}

func FuzzDecodeWrites(f *testing.F) {
	f.Add(fc6(0, 35))
	f.Add(fc3(0, 5))
	f.Add([]byte{FCWriteMultipleRegisters, 0, 0, 0, 2, 4, 0, 35, 0, 40})
	f.Add(fc22(0, 0xff00, 0x00ff))
	f.Add(fc23(0, 1, 0, 1, []uint16{35}))
	f.Fuzz(func(t *testing.T, pdu []byte) {
		if len(pdu) > 512 {
			return
		}
		if intent, err := decodeWrite(pdu); err == nil {
			if len(intent.Ops) == 0 {
				t.Fatal("write intent without operations")
			}
			for _, op := range intent.Ops {
				if op.Address == "" || op.Value == "" {
					t.Fatalf("empty canonical operation: %+v", op)
				}
			}
		}
		_, _, _, _ = parseReadRange(pdu)
		reader := bufio.NewReader(bytes.NewReader(append([]byte{0, 1, 0, 0, 0, 1}, pdu...)))
		_, _ = readFrame(reader)
	})
}

// writeAndRead sends one PDU and returns the response PDU (nil on error).
func writeAndRead(conn net.Conn, pdu []byte) []byte {
	if _, err := conn.Write(testADU(1, 1, pdu)); err != nil {
		return nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	f, err := readFrame(bufio.NewReader(conn))
	if err != nil {
		return nil
	}
	return f.PDU
}
