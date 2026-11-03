// Package httpui implements the passive HTTP/HTTPS management-interface
// observer (P0 after the 2026 cold-chain incident: the documented entry path
// was the web UI of the refrigeration supervisors, not Modbus/BACnet).
//
// The decoder extracts METADATA only:
//   - plaintext HTTP: request method, path (without query string), Host,
//     User-Agent, Server, Content-Type, status code;
//   - HTTPS: TLS ClientHello SNI (server_name) and the endpoint addresses, no
//     certificate contents, no decryption.
//
// Cookies, Authorization headers, bodies and query strings are never stored or
// logged. The package contains no HTTP client and never opens a connection.
package httpui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Adapter version reported through ports.Info.
const adapterVersion = "1"

// Option keys owned by the adapter.
const (
	optListen         = "listen"
	optPorts          = "ports"
	optDeviceIP       = "device_ip"
	optDevicePort     = "device_port"
	optMaxHeaderBytes = "max_header_bytes"
	optMaxConnections = "max_connections"
)

// Defaults: the ports the management UIs of cold-chain supervisors use.
const (
	defaultDevicePort     = 443
	defaultMaxHeaderBytes = 16 << 10
	defaultMaxConnections = 8
	tlsRecordHeaderLen    = 5
	tlsHandshakeTypeHello = 1
	tlsContentTypeHello   = 0x16
)

// ErrNoEvidence is returned when the adapter has no passive identity evidence.
var ErrNoEvidence = errors.New("httpui: option device_ip is required (no identity without evidence)")

// Adapter is the passive HTTP/UI collector for a per-device TAP feed.
type Adapter struct {
	cfg        collect.AdapterConfig
	listen     string
	deviceIP   string
	devicePort int
	maxHeader  int
	maxConns   int
	meta       collect.Meta
	counters   collect.Counters
}

// New creates the adapter. It needs a local feed listener and the device IP for
// flow/asset provenance; it never dials the device itself.
func New(cfg collect.AdapterConfig) (ports.Collector, error) {
	site, err := cfg.ResolveSite()
	if err != nil {
		return nil, err
	}
	a := &Adapter{
		cfg:        cfg,
		listen:     cfg.Option(optListen),
		deviceIP:   cfg.Option(optDeviceIP),
		devicePort: defaultDevicePort,
		maxHeader:  defaultMaxHeaderBytes,
		maxConns:   defaultMaxConnections,
	}
	if a.listen == "" {
		return nil, fmt.Errorf("httpui %q: option %s is required", cfg.AdapterID, optListen)
	}
	if _, _, err := net.SplitHostPort(a.listen); err != nil {
		return nil, fmt.Errorf("httpui %q: option %s %q: %w", cfg.AdapterID, optListen, a.listen, err)
	}
	if a.deviceIP == "" {
		return nil, fmt.Errorf("httpui %q: %w", cfg.AdapterID, ErrNoEvidence)
	}
	if err := validateIPv4(a.deviceIP); err != nil {
		return nil, fmt.Errorf("httpui %q: option %s: %w", cfg.AdapterID, optDeviceIP, err)
	}
	if raw := cfg.Option(optDevicePort); raw != "" {
		port, err := netxParsePort(raw)
		if err != nil {
			return nil, fmt.Errorf("httpui %q: option %s: %w", cfg.AdapterID, optDevicePort, err)
		}
		a.devicePort = port
	}
	if raw := cfg.Option(optMaxHeaderBytes); raw != "" {
		var n int
		if _, err := fmt.Sscanf(raw, "%d", &n); err != nil || n < 1024 || n > 1<<20 {
			return nil, fmt.Errorf("httpui %q: option %s must be 1024..1048576", cfg.AdapterID, optMaxHeaderBytes)
		}
		a.maxHeader = n
	}
	if raw := cfg.Option(optMaxConnections); raw != "" {
		var n int
		if _, err := fmt.Sscanf(raw, "%d", &n); err != nil || n < 1 || n > 64 {
			return nil, fmt.Errorf("httpui %q: option %s must be 1..64", cfg.AdapterID, optMaxConnections)
		}
		a.maxConns = n
	}
	a.meta = collect.Meta{
		SiteID:     site,
		ZoneID:     cfg.ZoneID,
		Source:     cfg.AdapterID,
		Collection: collect.CollectionPassiveTap,
		Protocol:   "http",
		Clock:      cfg.Clock,
	}
	if err := a.meta.Validate(); err != nil {
		return nil, fmt.Errorf("httpui %q: %w", cfg.AdapterID, err)
	}
	return a, nil
}

// Info implements ports.Collector.
func (a *Adapter) Info() ports.Info {
	return ports.Info{
		AdapterID:  a.cfg.AdapterID,
		Version:    adapterVersion,
		Protocols:  []string{"http", "https"},
		Collection: collect.CollectionPassiveTap,
		ReadOnly:   true,
		Description: "Passive HTTP/HTTPS management-interface metadata observer " +
			"(request line, Host/Server/User-Agent, status code, TLS SNI); no payloads, no cookies, no active requests.",
	}
}

// Start implements ports.Collector. It blocks until ctx is cancelled.
func (a *Adapter) Start(ctx context.Context, sink ports.Sink) error {
	if ctx == nil {
		return errors.New("httpui: nil context")
	}
	if sink == nil {
		return errors.New("httpui: nil sink")
	}
	return a.runFeed(ctx, sink)
}

// HealthCounters implements collect.Instrumented.
func (a *Adapter) HealthCounters() collect.CounterSnapshot { return a.counters.HealthCounters() }

func (a *Adapter) now() time.Time {
	if a.cfg.Clock != nil {
		return a.cfg.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (a *Adapter) runFeed(ctx context.Context, sink ports.Sink) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", a.listen)
	if err != nil {
		return fmt.Errorf("httpui %q: listen %q: %w", a.cfg.AdapterID, a.listen, err)
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
					a.counters.IncError(fmt.Sprintf("feed connection panic: %v", p))
				}
			}()
			a.serveConn(ctx, c, sink)
		}(conn)
	}
	wg.Wait()
	return nil
}

func (a *Adapter) serveConn(ctx context.Context, conn net.Conn, sink ports.Sink) {
	meta := ConnMeta{
		ClientIP:   remoteIP(conn),
		ClientPort: remotePort(conn),
		ServerIP:   a.deviceIP,
		ServerPort: uint16(a.devicePort),
	}
	decoder, err := NewDecoder(DecoderOptions{
		Meta:      a.meta,
		MaxHeader: a.maxHeader,
	})
	if err != nil {
		a.counters.IncError(err.Error())
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()

	buf := make([]byte, 4096)
	for {
		n, readErr := conn.Read(buf)
		if n > 0 {
			events := decoder.Feed(meta, buf[:n])
			if len(events) > 0 {
				if err := collect.EmitAll(ctx, sink, events); err != nil {
					a.counters.IncError(err.Error())
				}
			}
		}
		if readErr != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
	}
	a.counters.Merge(decoder.HealthCounters())
}

// headerBlockEnd finds the end of one HTTP header block.
func headerBlockEnd(buf []byte) (int, bool) {
	idx := bytes.Index(buf, []byte("\r\n\r\n"))
	return idx, idx >= 0
}
