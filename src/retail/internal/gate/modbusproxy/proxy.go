// Proxy lifecycle: listener per target, bounded connections, health counters.
package modbusproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Defaults kept deliberately small so a misconfiguration cannot open a large
// attack surface.
const (
	defaultTimeout     = 5 * time.Second
	defaultIdleTimeout = 120 * time.Second
	defaultMaxConns    = 32
	maxAllowedConns    = 256
	maxAllowedTimeout  = 60 * time.Second
)

// Config is the enforcement configuration of one Modbus target.
type Config struct {
	TargetID    domain.TargetID
	Listen      string
	Upstream    string
	UnitID      uint8
	Timeout     time.Duration
	IdleTimeout time.Duration
	// ReadRegisters is the only readable register window. Nil denies all reads.
	ReadRegisters *RegisterRange
	// ReadCoils is the optional FC1 coil window for read-before-write of FC5/15.
	ReadCoils *RegisterRange
	// ReadOnlyMode denies every write regardless of plans/sessions.
	ReadOnlyMode bool
	// AllowedUnitIDs is the explicit unit-id allowlist. Empty means only UnitID.
	AllowedUnitIDs []uint8
	// SourceCIDRs is mandatory (fail-closed); empty means "deny everything".
	SourceCIDRs    []netip.Prefix
	MaxConnections int
	Clock          ports.Clock
}

// Validate checks the mandatory fields.
func (c Config) Validate() error {
	if err := c.TargetID.Validate(); err != nil {
		return fmt.Errorf("modbusproxy: %w", err)
	}
	if c.Listen == "" || c.Upstream == "" {
		return errors.New("modbusproxy: listen and upstream are required")
	}
	if _, err := netip.ParseAddrPort(c.Upstream); err != nil {
		return fmt.Errorf("modbusproxy: upstream %q must be ip:port: %w", c.Upstream, err)
	}
	if c.ReadRegisters != nil {
		if err := c.ReadRegisters.Validate(); err != nil {
			return err
		}
	}
	if len(c.SourceCIDRs) == 0 {
		return errors.New("modbusproxy: source_cidrs is required (fail-closed)")
	}
	return nil
}

// Stats is the health snapshot of one proxy.
type Stats struct {
	Connections       uint64
	ActiveConnections int
	Requests          uint64
	Reads             uint64
	ReadsDenied       uint64
	WritesAllowed     uint64
	WritesDenied      uint64
	Unsupported       uint64
	ParserErrors      uint64
	UpstreamErrors    uint64
	LastError         string
	ListenAddress     string
	State             string
}

// Proxy is one Modbus/TCP enforcement listener.
type Proxy struct {
	cfg      Config
	sessions SessionLookup
	clock    ports.Clock

	mu     sync.Mutex
	ln     net.Listener
	cancel context.CancelFunc
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
	state  string

	requests       atomic.Uint64
	reads          atomic.Uint64
	readsDenied    atomic.Uint64
	writesAllowed  atomic.Uint64
	writesDenied   atomic.Uint64
	unsupported    atomic.Uint64
	parserErrors   atomic.Uint64
	upstreamErrors atomic.Uint64
	connections    atomic.Uint64
	readTxn        atomic.Uint32

	errMu   sync.Mutex
	lastErr string
}

// New validates the configuration and returns an unstarted proxy.
func New(cfg Config, sessions SessionLookup) (*Proxy, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.Timeout = clampTimeout(cfg.Timeout, defaultTimeout)
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.IdleTimeout > 30*time.Minute {
		cfg.IdleTimeout = 30 * time.Minute
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = defaultMaxConns
	}
	if cfg.MaxConnections > maxAllowedConns {
		cfg.MaxConnections = maxAllowedConns
	}
	if len(cfg.AllowedUnitIDs) == 0 {
		cfg.AllowedUnitIDs = []uint8{cfg.UnitID}
	}
	for _, unit := range cfg.AllowedUnitIDs {
		if unit == 0 {
			return nil, errors.New("modbusproxy: unit id 0 (broadcast) must not be allowlisted")
		}
	}
	return &Proxy{
		cfg:      cfg,
		sessions: sessions,
		clock:    cfg.Clock,
		conns:    make(map[net.Conn]struct{}),
		state:    "stopped",
	}, nil
}

// Start binds the listener and launches the accept loop. It returns once the
// listener is ready; Addr() then reports the actual address.
func (p *Proxy) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("modbusproxy: nil context")
	}
	p.mu.Lock()
	if p.ln != nil {
		p.mu.Unlock()
		return errors.New("modbusproxy: already started")
	}
	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		p.mu.Unlock()
		return fmt.Errorf("modbusproxy %q: listen %q: %w", p.cfg.TargetID, p.cfg.Listen, err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	p.ln = ln
	p.cancel = cancel
	p.state = "running"
	p.mu.Unlock()

	p.wg.Add(1)
	go p.acceptLoop(runCtx, ln)
	return nil
}

// Addr returns the bound listener address ("" before Start).
func (p *Proxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln == nil {
		return ""
	}
	return p.ln.Addr().String()
}

// Stats returns a consistent health snapshot.
func (p *Proxy) Stats() Stats {
	p.mu.Lock()
	active := len(p.conns)
	listen := ""
	if p.ln != nil {
		listen = p.ln.Addr().String()
	}
	state := p.state
	p.mu.Unlock()
	p.errMu.Lock()
	lastErr := p.lastErr
	p.errMu.Unlock()
	return Stats{
		Connections:       p.connections.Load(),
		ActiveConnections: active,
		Requests:          p.requests.Load(),
		Reads:             p.reads.Load(),
		ReadsDenied:       p.readsDenied.Load(),
		WritesAllowed:     p.writesAllowed.Load(),
		WritesDenied:      p.writesDenied.Load(),
		Unsupported:       p.unsupported.Load(),
		ParserErrors:      p.parserErrors.Load(),
		UpstreamErrors:    p.upstreamErrors.Load(),
		LastError:         lastErr,
		ListenAddress:     listen,
		State:             state,
	}
}

// Close stops the listener and all active connections. It is idempotent.
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.ln == nil {
		p.mu.Unlock()
		return nil
	}
	cancel := p.cancel
	ln := p.ln
	p.ln = nil
	p.state = "stopped"
	for conn := range p.conns {
		_ = conn.Close()
	}
	conns := len(p.conns)
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if ln != nil {
		_ = ln.Close()
	}
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		p.recordError(fmt.Sprintf("shutdown timeout with %d active connection(s)", conns))
	}
	return nil
}

// acceptLoop accepts client connections until the listener is closed.
func (p *Proxy) acceptLoop(ctx context.Context, ln net.Listener) {
	defer p.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.recordError("accept: " + err.Error())
			select {
			case <-time.After(50 * time.Millisecond):
				continue
			case <-ctx.Done():
				return
			}
		}
		if !p.trackConn(conn) {
			p.recordError("connection limit reached")
			_ = conn.Close()
			continue
		}
		p.connections.Add(1)
		p.wg.Add(1)
		go func(c net.Conn) {
			defer p.wg.Done()
			defer p.untrackConn(c)
			defer func() { _ = c.Close() }()
			defer func() {
				if recovered := recover(); recovered != nil {
					p.recordError(fmt.Sprintf("connection panic: %v", recovered))
				}
			}()
			p.handleConn(ctx, c)
		}(conn)
	}
}

// trackConn adds a connection if the configured limit is not exceeded.
func (p *Proxy) trackConn(conn net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != "running" {
		return false
	}
	if len(p.conns) >= p.cfg.MaxConnections {
		return false
	}
	p.conns[conn] = struct{}{}
	return true
}

func (p *Proxy) untrackConn(conn net.Conn) {
	p.mu.Lock()
	delete(p.conns, conn)
	p.mu.Unlock()
}

// unitAllowed reports whether the client unit id is explicitly allowlisted.
func (p *Proxy) unitAllowed(unit uint8) bool {
	for _, allowed := range p.cfg.AllowedUnitIDs {
		if allowed == unit {
			return true
		}
	}
	return false
}

func (p *Proxy) recordError(message string) {
	if len(message) > 240 {
		message = message[:240]
	}
	p.errMu.Lock()
	p.lastErr = message
	p.errMu.Unlock()
}
