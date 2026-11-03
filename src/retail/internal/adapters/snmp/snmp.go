// Package snmp implements the read-only SNMP v1/v2c GET collector.
//
// Only GET requests are encoded; there is no SET/GETBULK/WALK path (see
// internal/adapters/safety_test.go). The community string is read from the
// operator configuration, is never logged, never stored in events and never
// returned by Health().
//
// SNMPv3 is NOT implemented in this MVP. It is documented and surfaced instead
// of being faked: configuring version=3 makes New fail with
// ErrSNMPv3NotImplemented, and the health state of a running v1/v2c adapter is
// "degraded" with an explicit plaintext-community warning.
package snmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/netx"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

const adapterVersion = "1"

// SNMPv3Supported documents the MVP boundary in code.
const SNMPv3Supported = false

// HealthWarning is surfaced in the collector health when no hard error exists.
const HealthWarning = "snmp v1/v2c community is transmitted in plaintext; SNMPv3 is not implemented in MVP"

// ErrSNMPv3NotImplemented is returned for an explicitly requested v3 config.
var ErrSNMPv3NotImplemented = errors.New("snmp: SNMPv3 is not implemented in the MVP (v1/v2c GET only)")

// Option keys owned by the adapter.
const (
	optTargets   = "targets"
	optCommunity = "community"
	optVersion   = "version"
	optOIDs      = "oids"
	optInterval  = "interval"
	optTimeout   = "timeout"
)

const (
	defaultInterval = 30 * time.Second
	defaultTimeout  = 3 * time.Second
	minInterval     = time.Second
	minTimeout      = 200 * time.Millisecond
	defaultPort     = 161
	maxTargets      = 32
	maxOIDs         = 64
)

// OIDMapping maps one numeric OID to a normalized sensor/metric/unit.
type OIDMapping struct {
	OID      string
	SensorID domain.SensorID
	AssetID  domain.AssetID
	Metric   string
	Unit     domain.Unit
}

// Adapter is the read-only SNMP collector.
type Adapter struct {
	cfg       collect.AdapterConfig
	meta      collect.Meta
	targets   []string
	community string
	version   int
	oids      []string
	mappings  map[string]OIDMapping
	interval  time.Duration
	timeout   time.Duration
	requestID atomic.Int32
	counters  collect.Counters
}

// New validates the configuration. It never dials during construction.
func New(cfg collect.AdapterConfig) (ports.Collector, error) {
	site, err := cfg.ResolveSite()
	if err != nil {
		return nil, err
	}
	a := &Adapter{
		cfg:      cfg,
		interval: defaultInterval,
		timeout:  defaultTimeout,
		mappings: make(map[string]OIDMapping),
	}
	version := cfg.Option(optVersion)
	switch version {
	case "", "1", "v1", "2", "2c", "v2c":
	default:
		return nil, fmt.Errorf("snmp %q: %w (requested %q)", cfg.AdapterID, ErrSNMPv3NotImplemented, version)
	}
	a.version = 1 // v2c wire version 1
	if version == "1" || version == "v1" {
		a.version = 0
	}
	a.community = cfg.Option(optCommunity)
	if a.community == "" {
		return nil, fmt.Errorf("snmp %q: option %s is required", cfg.AdapterID, optCommunity)
	}
	if len(a.community) > 128 {
		return nil, fmt.Errorf("snmp %q: option %s is too long", cfg.AdapterID, optCommunity)
	}
	targets := splitList(cfg.Option(optTargets))
	if len(targets) == 0 {
		return nil, fmt.Errorf("snmp %q: option %s is required", cfg.AdapterID, optTargets)
	}
	if len(targets) > maxTargets {
		return nil, fmt.Errorf("snmp %q: at most %d targets", cfg.AdapterID, maxTargets)
	}
	for _, raw := range targets {
		host, port, err := netx.ParseAddrPort(raw, defaultPort)
		if err != nil {
			return nil, fmt.Errorf("snmp %q: target %q: %w", cfg.AdapterID, raw, err)
		}
		a.targets = append(a.targets, netx.FormatEndpoint(host, port))
	}
	mappings, err := ParseOIDMappings(cfg.Option(optOIDs))
	if err != nil {
		return nil, fmt.Errorf("snmp %q: %w", cfg.AdapterID, err)
	}
	if len(mappings) == 0 {
		return nil, fmt.Errorf("snmp %q: option %s is required", cfg.AdapterID, optOIDs)
	}
	if len(mappings) > maxOIDs {
		return nil, fmt.Errorf("snmp %q: at most %d OIDs", cfg.AdapterID, maxOIDs)
	}
	a.oids = make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		a.oids = append(a.oids, mapping.OID)
		a.mappings[mapping.OID] = mapping
	}
	if raw := cfg.Option(optInterval); raw != "" {
		floor := minInterval
		if loopbackTargets(a.targets) {
			floor = 50 * time.Millisecond
		}
		d, err := time.ParseDuration(raw)
		if err != nil || d < floor {
			return nil, fmt.Errorf("snmp %q: option %s must be a duration >= %s", cfg.AdapterID, optInterval, floor)
		}
		a.interval = d
	}
	if raw := cfg.Option(optTimeout); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < minTimeout || d > time.Minute {
			return nil, fmt.Errorf("snmp %q: option %s must be %s..1m", cfg.AdapterID, optTimeout, minTimeout)
		}
		a.timeout = d
	}
	a.meta = collect.Meta{
		SiteID:     site,
		ZoneID:     cfg.ZoneID,
		Source:     cfg.AdapterID,
		Collection: collect.CollectionReadOnlyPoll,
		Protocol:   "snmp",
		Clock:      cfg.Clock,
	}
	if err := a.meta.Validate(); err != nil {
		return nil, fmt.Errorf("snmp %q: %w", cfg.AdapterID, err)
	}
	return a, nil
}

// Info implements ports.Collector.
func (a *Adapter) Info() ports.Info {
	return ports.Info{
		AdapterID:   a.cfg.AdapterID,
		Version:     adapterVersion,
		Protocols:   []string{"snmp"},
		Collection:  collect.CollectionReadOnlyPoll,
		ReadOnly:    true,
		Description: "Read-only SNMP v1/v2c GET poller; SNMPv3 is not implemented in the MVP, no SET/walk path exists.",
	}
}

// Start implements ports.Collector. It blocks until ctx is cancelled.
func (a *Adapter) Start(ctx context.Context, sink ports.Sink) error {
	if ctx == nil {
		return errors.New("snmp: nil context")
	}
	if sink == nil {
		return errors.New("snmp: nil sink")
	}
	for _, target := range a.targets {
		host, _, err := net.SplitHostPort(target)
		if err != nil {
			continue
		}
		ev, err := a.meta.AssetSeenEvent(domain.DeviceMeta{IP: host}, 0.5, a.now())
		if err != nil {
			continue
		}
		if err := collect.EmitAll(ctx, sink, []domain.Event{ev}); err != nil {
			a.counters.IncError(err.Error())
			return nil
		}
	}

	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		a.pollAll(ctx, sink)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// HealthCounters implements collect.Instrumented.
func (a *Adapter) HealthCounters() collect.CounterSnapshot { return a.counters.HealthCounters() }

// HealthState implements collect.HealthState: SNMP v1/v2c is degraded by
// design in the MVP (plaintext community, no v3 support).
func (a *Adapter) HealthState() (string, string) {
	return "degraded", HealthWarning
}

func (a *Adapter) now() time.Time {
	if a.cfg.Clock != nil {
		return a.cfg.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

// loopbackTargets reports whether all targets are loopback (test/simulator
// devices), which allows a shorter poll interval.
func loopbackTargets(targets []string) bool {
	if len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		host, _, err := net.SplitHostPort(target)
		if err != nil || !netx.IsLoopback(host) {
			return false
		}
	}
	return true
}

func (a *Adapter) pollAll(ctx context.Context, sink ports.Sink) {
	for _, target := range a.targets {
		if ctx.Err() != nil {
			return
		}
		if err := a.pollTarget(ctx, target, sink); err != nil {
			a.counters.IncError(fmt.Sprintf("%s: %v", target, err))
		}
	}
}

// pollTarget performs one GET request/response round trip. The only encoded
// request PDU is a GetRequest (0xA0).
func (a *Adapter) pollTarget(ctx context.Context, target string, sink ports.Sink) error {
	dialer := net.Dialer{Timeout: a.timeout}
	conn, err := dialer.DialContext(ctx, "udp", target)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	requestID := a.requestID.Add(1)
	request, err := buildGetRequest(a.version, a.community, requestID, a.oids)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(a.timeout)); err != nil {
		return err
	}
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("send get: %w", err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	response, err := parseResponse(buf[:n])
	if err != nil {
		return err
	}
	if response.version != a.version {
		return fmt.Errorf("response version %d, want %d", response.version, a.version)
	}
	if response.requestID != requestID {
		return fmt.Errorf("response request-id mismatch")
	}
	if response.errorStatus != 0 {
		return fmt.Errorf("agent error status %d at index %d", response.errorStatus, response.errorIndex)
	}
	now := a.now()
	events := make([]domain.Event, 0, len(response.varbinds))
	for _, varbind := range response.varbinds {
		mapping, ok := a.mappings[varbind.OID]
		if !ok {
			a.counters.IncUnsupported()
			continue
		}
		if !varbind.numeric {
			a.counters.IncUnsupported()
			continue
		}
		meas := domain.Measurement{
			Value:      varbind.value,
			Unit:       mapping.Unit,
			Quality:    domain.QualityGood,
			Metric:     mapping.Metric,
			ObservedAt: now,
		}
		ev, err := a.meta.TelemetryEvent(mapping.SensorID, mapping.AssetID, meas, 0.8, now)
		if err != nil {
			a.counters.IncError(err.Error())
			continue
		}
		events = append(events, ev)
	}
	if err := collect.EmitAll(ctx, sink, events); err != nil {
		return err
	}
	return nil
}

// ParseOIDMappings parses "oid|sensor_id|metric|unit;next[;...]".
func ParseOIDMappings(value string) ([]OIDMapping, error) {
	entries := splitList(value)
	out := make([]OIDMapping, 0, len(entries))
	for _, entry := range entries {
		parts := splitPipe(entry)
		if len(parts) != 4 {
			return nil, fmt.Errorf("snmp: oid mapping %q needs oid|sensor_id|metric|unit", entry)
		}
		oid, err := normalizeOID(parts[0])
		if err != nil {
			return nil, fmt.Errorf("snmp: oid mapping %q: %w", entry, err)
		}
		sensor := domain.SensorID(trimSpace(parts[1]))
		if err := sensor.Validate(); err != nil {
			return nil, fmt.Errorf("snmp: oid mapping %q: sensor: %v", entry, err)
		}
		metric := trimSpace(parts[2])
		if metric == "" || len(metric) > 64 {
			return nil, fmt.Errorf("snmp: oid mapping %q: metric is required", entry)
		}
		unit := domain.Unit(trimSpace(parts[3]))
		if !unit.Valid() {
			return nil, fmt.Errorf("snmp: oid mapping %q: invalid unit %q", entry, parts[3])
		}
		out = append(out, OIDMapping{OID: oid, SensorID: sensor, Metric: metric, Unit: unit})
	}
	return out, nil
}

// normalizeOID validates a numeric dotted OID.
func normalizeOID(raw string) (string, error) {
	raw = trimSpace(raw)
	if raw == "" || len(raw) > 128 {
		return "", fmt.Errorf("invalid oid")
	}
	arcs := splitDot(raw)
	if len(arcs) < 2 {
		return "", fmt.Errorf("invalid oid %q", raw)
	}
	for _, arc := range arcs {
		if arc == "" {
			return "", fmt.Errorf("invalid oid %q", raw)
		}
		value, err := strconv.ParseUint(arc, 10, 32)
		if err != nil {
			return "", fmt.Errorf("invalid oid arc %q", arc)
		}
		if value > 0xffffffff {
			return "", fmt.Errorf("oid arc out of range")
		}
	}
	return raw, nil
}

func splitList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := trimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func splitPipe(entry string) []string {
	out := make([]string, 0, 4)
	current := make([]byte, 0, 32)
	for i := 0; i < len(entry); i++ {
		if entry[i] == '|' {
			out = append(out, trimSpace(string(current)))
			current = current[:0]
			continue
		}
		current = append(current, entry[i])
	}
	out = append(out, trimSpace(string(current)))
	return out
}

func splitDot(raw string) []string {
	out := make([]string, 0, 8)
	current := make([]byte, 0, 8)
	for i := 0; i < len(raw); i++ {
		if raw[i] == '.' {
			out = append(out, string(current))
			current = current[:0]
			continue
		}
		current = append(current, raw[i])
	}
	out = append(out, string(current))
	return out
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}
