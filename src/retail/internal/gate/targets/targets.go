// Package targets is the Access Gate target registry: it turns the validated
// gate configuration into running Modbus/HTTP enforcement listeners and exposes
// their health.
package targets

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/httpproxy"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/modbusproxy"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Protocol labels of the gate targets.
const (
	ProtocolModbusTCP = "modbus_tcp"
	ProtocolHTTP      = "http"
)

// Spec is one gate target (already normalized from gate.json by the lead's
// config package).
type Spec struct {
	TargetID domain.TargetID
	AssetID  domain.AssetID
	Protocol string
	Listen   string
	Upstream string

	// Modbus options
	UnitID         uint8
	AllowedUnitIDs []uint8
	ReadRegisters  *modbusproxy.RegisterRange
	ReadCoils      *modbusproxy.RegisterRange
	ReadOnlyMode   bool
	TimeoutS       int

	// HTTP options
	URLAllowlist       []string
	ParameterAllowlist []string
	AllowCGIWrites     bool
	CAFile             string
	CertPins           []string
	RequireCertPin     bool
}

// Options holds the gate-core seams and the global limits.
type Options struct {
	Clock             ports.Clock
	ModbusSessions    modbusproxy.SessionLookup
	HTTPSessions      httpproxy.SessionLookup
	HTTPAuth          httpproxy.Authenticator
	SourceCIDRs       []string
	HTTPSecureCookies bool
	HTTPBodyLimit     int64
}

// Health is the operator-facing runtime state of one target.
type Health struct {
	TargetID      domain.TargetID `json:"target_id"`
	AssetID       domain.AssetID  `json:"asset_id,omitempty"`
	Protocol      string          `json:"protocol"`
	Listen        string          `json:"listen"`
	Upstream      string          `json:"upstream"`
	State         string          `json:"state"`
	Requests      uint64          `json:"requests"`
	Reads         uint64          `json:"reads"`
	WritesAllowed uint64          `json:"writes_allowed"`
	WritesDenied  uint64          `json:"writes_denied"`
	Errors        uint64          `json:"errors"`
	LastError     string          `json:"last_error,omitempty"`
	Warning       string          `json:"warning,omitempty"`
}

// Registry owns all target listeners.
type Registry struct {
	opts    Options
	cidrs   []netip.Prefix
	mu      sync.Mutex
	entries []*entry
	started bool
}

type entry struct {
	spec   Spec
	modbus *modbusproxy.Proxy
	http   *httpproxy.Proxy
}

// New validates the global options.
func New(opts Options) (*Registry, error) {
	if len(opts.SourceCIDRs) == 0 {
		return nil, errors.New("targets: source_cidrs is required (fail-closed)")
	}
	cidrs := make([]netip.Prefix, 0, len(opts.SourceCIDRs))
	for _, raw := range opts.SourceCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("targets: invalid source CIDR %q: %w", raw, err)
		}
		cidrs = append(cidrs, prefix)
	}
	return &Registry{opts: opts, cidrs: cidrs}, nil
}

// Add validates and registers one target. Duplicate ids are rejected.
func (r *Registry) Add(spec Spec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return errors.New("targets: registry already started")
	}
	if err := spec.TargetID.Validate(); err != nil {
		return fmt.Errorf("targets: %w", err)
	}
	for _, existing := range r.entries {
		if existing.spec.TargetID == spec.TargetID {
			return fmt.Errorf("targets: duplicate target_id %q", spec.TargetID)
		}
	}
	switch spec.Protocol {
	case ProtocolModbusTCP:
		if r.opts.ModbusSessions == nil {
			return errors.New("targets: modbus session lookup is required")
		}
	case ProtocolHTTP:
		if r.opts.HTTPSessions == nil || r.opts.HTTPAuth == nil {
			return errors.New("targets: http session lookup and authenticator are required")
		}
	default:
		return fmt.Errorf("targets: unsupported protocol %q", spec.Protocol)
	}
	if spec.Listen == "" || spec.Upstream == "" {
		return fmt.Errorf("targets: target %q needs listen and upstream", spec.TargetID)
	}
	r.entries = append(r.entries, &entry{spec: spec})
	return nil
}

// Start creates and starts every listener. Configuration errors are
// transactional: nothing is left running when a target fails to start.
func (r *Registry) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("targets: nil context")
	}
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return errors.New("targets: already started")
	}
	entries := make([]*entry, len(r.entries))
	copy(entries, r.entries)
	r.mu.Unlock()

	started := make([]*entry, 0, len(entries))
	fail := func(err error) error {
		for _, entry := range started {
			stopEntry(entry)
		}
		return err
	}
	for _, entry := range entries {
		switch entry.spec.Protocol {
		case ProtocolModbusTCP:
			cfg := modbusproxy.Config{
				TargetID:       entry.spec.TargetID,
				Listen:         entry.spec.Listen,
				Upstream:       entry.spec.Upstream,
				UnitID:         entry.spec.UnitID,
				Timeout:        timeoutFromSeconds(entry.spec.TimeoutS),
				ReadRegisters:  entry.spec.ReadRegisters,
				ReadCoils:      entry.spec.ReadCoils,
				ReadOnlyMode:   entry.spec.ReadOnlyMode,
				AllowedUnitIDs: entry.spec.AllowedUnitIDs,
				SourceCIDRs:    r.cidrs,
				Clock:          r.opts.Clock,
			}
			proxy, err := modbusproxy.New(cfg, r.opts.ModbusSessions)
			if err != nil {
				return fail(fmt.Errorf("targets %q: %w", entry.spec.TargetID, err))
			}
			entry.modbus = proxy
		case ProtocolHTTP:
			cfg := httpproxy.Config{
				TargetID:           entry.spec.TargetID,
				Listen:             entry.spec.Listen,
				Upstream:           entry.spec.Upstream,
				CAFile:             entry.spec.CAFile,
				CertPins:           entry.spec.CertPins,
				RequireCertPin:     entry.spec.RequireCertPin,
				URLAllowlist:       entry.spec.URLAllowlist,
				ParameterAllowlist: entry.spec.ParameterAllowlist,
				AllowCGIWrites:     entry.spec.AllowCGIWrites,
				Timeout:            timeoutFromSeconds(entry.spec.TimeoutS),
				BodyLimit:          r.opts.HTTPBodyLimit,
				SecureCookies:      r.opts.HTTPSecureCookies,
				SourceCIDRs:        r.cidrs,
				Clock:              r.opts.Clock,
			}
			proxy, err := httpproxy.New(cfg, r.opts.HTTPSessions, r.opts.HTTPAuth)
			if err != nil {
				return fail(fmt.Errorf("targets %q: %w", entry.spec.TargetID, err))
			}
			entry.http = proxy
		default:
			return fail(fmt.Errorf("targets %q: unsupported protocol", entry.spec.TargetID))
		}
		if err := startEntry(entry, ctx); err != nil {
			return fail(fmt.Errorf("targets %q: %w", entry.spec.TargetID, err))
		}
		started = append(started, entry)
	}
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	return nil
}

func startEntry(entry *entry, ctx context.Context) error {
	switch {
	case entry.modbus != nil:
		return entry.modbus.Start(ctx)
	case entry.http != nil:
		return entry.http.Start(ctx)
	default:
		return errors.New("targets: empty entry")
	}
}

func stopEntry(entry *entry) {
	if entry.modbus != nil {
		_ = entry.modbus.Close()
	}
	if entry.http != nil {
		_ = entry.http.Close()
	}
}

// Stop closes every listener idempotently.
func (r *Registry) Stop() {
	r.mu.Lock()
	entries := append([]*entry{}, r.entries...)
	r.started = false
	r.mu.Unlock()
	for _, entry := range entries {
		stopEntry(entry)
	}
}

// Health returns one deterministic snapshot per target.
func (r *Registry) Health() []Health {
	r.mu.Lock()
	entries := append([]*entry{}, r.entries...)
	r.mu.Unlock()
	out := make([]Health, 0, len(entries))
	for _, entry := range entries {
		out = append(out, healthFor(entry))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TargetID < out[j].TargetID })
	return out
}

func healthFor(entry *entry) Health {
	health := Health{
		TargetID: entry.spec.TargetID,
		AssetID:  entry.spec.AssetID,
		Protocol: entry.spec.Protocol,
		Listen:   entry.spec.Listen,
		Upstream: entry.spec.Upstream,
		State:    "stopped",
	}
	switch {
	case entry.modbus != nil:
		stats := entry.modbus.Stats()
		health.Listen = firstNonEmpty(stats.ListenAddress, entry.spec.Listen)
		health.State = stats.State
		health.Requests = stats.Requests
		health.Reads = stats.Reads
		health.WritesAllowed = stats.WritesAllowed
		health.WritesDenied = stats.WritesDenied
		health.Errors = stats.ParserErrors + stats.UpstreamErrors
		health.LastError = stats.LastError
	case entry.http != nil:
		stats := entry.http.Stats()
		health.Listen = firstNonEmpty(stats.ListenAddress, entry.spec.Listen)
		health.State = stats.State
		health.Requests = stats.Requests
		health.Reads = stats.ReadRequests
		health.WritesAllowed = stats.WritesAllowed
		health.WritesDenied = stats.WritesDenied
		health.Errors = stats.UpstreamErrors + stats.AuthFailures + stats.SourceDenied
		health.LastError = stats.LastError
	}
	if entry.spec.Protocol == ProtocolHTTP && len(entry.spec.CertPins) == 0 && stringsFromScheme(entry.spec.Upstream) {
		health.Warning = "device TLS certificate is not pinned (cert_pin/require_cert_pin recommended)"
	}
	return health
}

// stringsFromScheme reports whether the upstream uses HTTPS (inline helper to
// avoid importing net/url only for a warning).
func stringsFromScheme(upstream string) bool {
	return len(upstream) >= 8 && upstream[:8] == "https://"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func timeoutFromSeconds(seconds int) time.Duration {
	if seconds <= 0 {
		return 5 * time.Second
	}
	if seconds > 60 {
		seconds = 60
	}
	return time.Duration(seconds) * time.Second
}
