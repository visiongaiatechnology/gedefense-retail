// TCP feed listener for passive tap mode.
package modbus

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/netx"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// runTap listens on the configured local feed port. It accepts passive byte
// streams (from a SPAN/TAP shim) and never dials an OT device.
func (a *Adapter) runTap(ctx context.Context, sink ports.Sink) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", a.listen)
	if err != nil {
		return fmt.Errorf("modbus %q: listen %q: %w", a.cfg.AdapterID, a.listen, err)
	}
	defer func() { _ = ln.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	var wg sync.WaitGroup
	sem := make(chan struct{}, a.maxConns)
loop:
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			a.counters.IncError(fmt.Sprintf("accept: %v", err))
			select {
			case <-time.After(100 * time.Millisecond):
				continue
			case <-ctx.Done():
				break loop
			}
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			break loop
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { _ = c.Close() }()
			defer func() {
				if p := recover(); p != nil {
					a.counters.IncError(fmt.Sprintf("tap connection panic: %v", p))
				}
			}()
			a.serveTapConn(ctx, c, sink)
		}(conn)
	}
	wg.Wait()
	return nil
}

// serveTapConn decodes one feed connection until it closes or ctx is done.
func (a *Adapter) serveTapConn(ctx context.Context, conn net.Conn, sink ports.Sink) {
	peer := conn.RemoteAddr().String()
	decoder, err := NewTap(TapOptions{
		Meta:      a.meta,
		Registers: a.registers,
		DeviceIP:  a.deviceIP,
		Peer:      peer,
	})
	if err != nil {
		a.counters.IncError(err.Error())
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()

	var bytesRead int64
	var frames int64
	buf := make([]byte, 4096)
	for {
		n, readErr := conn.Read(buf)
		if n > 0 {
			bytesRead += int64(n)
			events := decoder.Feed(buf[:n], DirectionUnknown)
			frames += int64(len(events))
			if len(events) > 0 {
				if err := collect.EmitAll(ctx, sink, events); err != nil {
					a.counters.IncError(err.Error())
				}
			}
		}
		if readErr != nil {
			if ctx.Err() != nil {
				break
			}
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
	}
	a.counters.Merge(decoder.HealthCounters())
	if ctx.Err() != nil {
		return
	}
	a.emitFeedFlow(ctx, sink, conn, bytesRead, frames)
}

// emitFeedFlow records the feed stream liveness. The original L3 addresses of
// the monitored controller are not visible on a byte-stream feed; the PCAP
// adapter provides the real per-packet flows.
func (a *Adapter) emitFeedFlow(ctx context.Context, sink ports.Sink, conn net.Conn, bytesRead, frames int64) {
	srcIP, srcPort, ok := splitEndpoint(conn.RemoteAddr())
	if !ok {
		return
	}
	dstIP, dstPort, ok := splitEndpoint(conn.LocalAddr())
	if !ok {
		return
	}
	flow := domain.FlowMeta{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  "modbus_tcp",
		Bytes:     bytesRead,
		Packets:   frames,
		Direction: "internal",
	}
	ev, err := a.meta.FlowEvent(flow, 0.4, a.now())
	if err != nil {
		a.counters.IncError(err.Error())
		return
	}
	if err := collect.EmitAll(ctx, sink, []domain.Event{ev}); err != nil {
		a.counters.IncError(err.Error())
	}
}

func splitEndpoint(addr net.Addr) (string, int, bool) {
	if addr == nil {
		return "", 0, false
	}
	raw := addr.String()
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return "", 0, false
	}
	if _, err := netx.ParseAddr(host); err != nil {
		return "", 0, false
	}
	port, err := netx.ParsePort(portText)
	if err != nil {
		return "", 0, false
	}
	return host, int(port), true
}
