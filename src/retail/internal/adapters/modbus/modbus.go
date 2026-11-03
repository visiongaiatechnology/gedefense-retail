// Package modbus implements the read-only Modbus/TCP collector.
//
// Two modes exist:
//
//   - mode=tap (default): the adapter listens on a local TCP feed (a SPAN/TAP
//     shim) and parses the passive MBAP byte stream. It never connects to a
//     controller and never sends a frame. Observed write function codes
//     (5/6/15/16) are reported as domain.EventWriteAttempt, never executed.
//   - mode=poll: a strictly read-only poller (function codes 3/4 only) against
//     an explicitly approved target. A register spec that names FC 5/6/15/16
//     aborts startup with guard.ErrWriteDenied.
//
// The package deliberately contains no encoder for a write PDU: a write
// capability cannot be reached from the adapter surface (see the safety tests
// in internal/adapters/safety_test.go).
package modbus

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/netx"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Mode names accepted in Options["mode"].
const (
	ModeTap  = "tap"
	ModePoll = "poll"
)

// Adapter version reported through ports.Info.
const adapterVersion = "1"

// Option keys owned by the adapter (documented in docs/retail/deployment-guide.md).
const (
	optMode           = "mode"
	optListen         = "listen"
	optTarget         = "target"
	optUnit           = "unit"
	optInterval       = "interval"
	optTimeout        = "timeout"
	optRegisters      = "registers"
	optDeviceIP       = "device_ip"
	optFlowInterval   = "flow_interval"
	optMaxConnections = "max_connections"
)

// Defaults. They are conservative: a slow poll interval protects the plant.
const (
	defaultInterval       = 5 * time.Second
	defaultTimeout        = 2 * time.Second
	defaultFlowInterval   = 60 * time.Second
	defaultMaxConnections = 8
	minInterval           = time.Second
	minTimeout            = 100 * time.Millisecond
	maxPollQuantity       = 100
)

// Adapter is the Modbus/TCP collector. It implements ports.Collector and is
// read-only by construction.
type Adapter struct {
	cfg  collect.AdapterConfig
	mode string
	meta collect.Meta

	// tap
	listen    string
	deviceIP  string
	maxConns  int
	registers []RegisterSpec
	tapRegs   map[uint8]map[uint16]RegisterSpec

	// poll
	target       string
	unit         uint8
	interval     time.Duration
	timeout      time.Duration
	flowInterval time.Duration
	pollGroups   []pollGroup

	counters collect.Counters
}

// New creates a Modbus adapter from its collector configuration. A writable
// register spec or an unknown mode is a startup error.
func New(cfg collect.AdapterConfig) (ports.Collector, error) {
	site, err := cfg.ResolveSite()
	if err != nil {
		return nil, err
	}
	a := &Adapter{
		cfg:       cfg,
		mode:      cfg.Option(optMode),
		deviceIP:  cfg.Option(optDeviceIP),
		maxConns:  defaultMaxConnections,
		interval:  defaultInterval,
		timeout:   defaultTimeout,
		registers: nil,
	}
	if a.mode == "" {
		a.mode = ModeTap
	}
	if a.deviceIP != "" {
		addr, err := netParseIP(a.deviceIP)
		if err != nil {
			return nil, fmt.Errorf("modbus %q: option %s: %w", cfg.AdapterID, optDeviceIP, err)
		}
		a.deviceIP = addr
	}
	registers, err := ParseRegisterSpec(cfg.Option(optRegisters))
	if err != nil {
		return nil, fmt.Errorf("modbus %q: %w", cfg.AdapterID, err)
	}
	a.registers = registers
	a.tapRegs = indexRegisters(registers)

	interval, err := parseDurationOption(cfg, optInterval, a.interval, a.intervalFloor())
	if err != nil {
		return nil, err
	}
	a.interval = interval
	timeout, err := parseDurationOption(cfg, optTimeout, a.timeout, minTimeout)
	if err != nil {
		return nil, err
	}
	a.timeout = timeout
	flowInterval, err := parseDurationOption(cfg, optFlowInterval, defaultFlowInterval, time.Second)
	if err != nil {
		return nil, err
	}
	a.flowInterval = flowInterval

	switch a.mode {
	case ModeTap:
		a.listen = cfg.Option(optListen)
		if a.listen == "" {
			return nil, fmt.Errorf("modbus %q: option %s is required in tap mode", cfg.AdapterID, optListen)
		}
		if _, _, err := net.SplitHostPort(a.listen); err != nil {
			return nil, fmt.Errorf("modbus %q: option %s %q: %w", cfg.AdapterID, optListen, a.listen, err)
		}
		if raw := cfg.Option(optMaxConnections); raw != "" {
			var n int
			if _, err := fmt.Sscanf(raw, "%d", &n); err != nil || n < 1 || n > 64 {
				return nil, fmt.Errorf("modbus %q: option %s must be 1..64", cfg.AdapterID, optMaxConnections)
			}
			a.maxConns = n
		}
	case ModePoll:
		a.target = cfg.Option(optTarget)
		if a.target == "" {
			return nil, fmt.Errorf("modbus %q: option %s is required in poll mode", cfg.AdapterID, optTarget)
		}
		if _, _, err := net.SplitHostPort(a.target); err != nil {
			return nil, fmt.Errorf("modbus %q: option %s %q: %w", cfg.AdapterID, optTarget, a.target, err)
		}
		unit := cfg.Option(optUnit)
		if unit != "" {
			var u int
			if _, err := fmt.Sscanf(unit, "%d", &u); err != nil || u < 0 || u > 255 {
				return nil, fmt.Errorf("modbus %q: option %s must be 0..255", cfg.AdapterID, optUnit)
			}
			a.unit = uint8(u)
		}
		if len(a.registers) == 0 {
			return nil, fmt.Errorf("modbus %q: poll mode requires option %s", cfg.AdapterID, optRegisters)
		}
		a.pollGroups = buildPollGroups(a.registers)
		if len(a.pollGroups) == 0 {
			return nil, fmt.Errorf("modbus %q: no readable register group", cfg.AdapterID)
		}
	default:
		return nil, fmt.Errorf("modbus %q: unknown mode %q (want %q or %q)", cfg.AdapterID, a.mode, ModeTap, ModePoll)
	}

	collection := collect.CollectionPassiveTap
	if a.mode == ModePoll {
		collection = collect.CollectionReadOnlyPoll
	}
	a.meta = collect.Meta{
		SiteID:     site,
		ZoneID:     cfg.ZoneID,
		Source:     cfg.AdapterID,
		Collection: collection,
		Protocol:   "modbus_tcp",
		Clock:      cfg.Clock,
	}
	if err := a.meta.Validate(); err != nil {
		return nil, fmt.Errorf("modbus %q: %w", cfg.AdapterID, err)
	}
	return a, nil
}

// intervalFloor protects productive plants from aggressive polling. Loopback
// targets are test/simulator devices, so a much shorter interval is allowed.
func (a *Adapter) intervalFloor() time.Duration {
	target := a.target
	if target == "" {
		target = a.cfg.Option(optTarget)
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil || !netx.IsLoopback(host) {
		return minInterval
	}
	return 50 * time.Millisecond
}

// Info implements ports.Collector.
func (a *Adapter) Info() ports.Info {
	collection := collect.CollectionPassiveTap
	description := "Passive Modbus/TCP MBAP stream parser (tap feed); observed write function codes are reported, never executed."
	if a.mode == ModePoll {
		collection = collect.CollectionReadOnlyPoll
		description = "Read-only Modbus/TCP poller (FC3/FC4 only); no write function code can be configured."
	}
	return ports.Info{
		AdapterID:   a.cfg.AdapterID,
		Version:     adapterVersion,
		Protocols:   []string{"modbus_tcp"},
		Collection:  collection,
		ReadOnly:    true,
		Description: description,
	}
}

// Start implements ports.Collector. It blocks until ctx is cancelled.
func (a *Adapter) Start(ctx context.Context, sink ports.Sink) error {
	if ctx == nil {
		return errors.New("modbus: nil context")
	}
	if sink == nil {
		return errors.New("modbus: nil sink")
	}
	if a.mode == ModePoll {
		return a.runPoll(ctx, sink)
	}
	return a.runTap(ctx, sink)
}

// HealthCounters implements collect.Instrumented via the embedded counter block.
func (a *Adapter) HealthCounters() collect.CounterSnapshot { return a.counters.HealthCounters() }

func (a *Adapter) now() time.Time {
	if a.cfg.Clock != nil {
		return a.cfg.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func parseDurationOption(cfg collect.AdapterConfig, key string, def, min time.Duration) (time.Duration, error) {
	raw := cfg.Option(key)
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("modbus %q: option %s %q: %w", cfg.AdapterID, key, raw, err)
	}
	if d < min {
		return 0, fmt.Errorf("modbus %q: option %s must be >= %s", cfg.AdapterID, key, min)
	}
	return d, nil
}

func netParseIP(value string) (string, error) {
	addr, err := netx.ParseAddr(value)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}
