// Package collect implements the passive collector framework.
//
// It owns everything that must be identical for every protocol adapter:
// factory registration, isolated execution (one goroutine per adapter with a
// recover at the boundary), health/counter accounting, the counting sink
// wrapper and graceful shutdown.
//
// Design invariants (engineering contract §2, §5.7):
//   - a collector is started only when Info.ReadOnly is true; there is no
//     writable variant in this product,
//   - an adapter failure, panic or parser error is counted and contained; it
//     never stops the process or another adapter,
//   - Stop is idempotent and joins every adapter goroutine.
//
// Adapters implement ports.Collector. Adapter constructors receive an
// AdapterConfig and return (ports.Collector, error); the registry injects the
// clock and (when configured) the site scope before calling the factory.
package collect

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Collection method labels from ports.Info. They are duplicated here as
// constants so adapters do not have to import ports just for a string.
const (
	CollectionPassiveTap     = "passive_tap"
	CollectionReadOnlyPoll   = "read_only_poll"
	CollectionOperatorExport = "operator_export"
)

// Errors returned by the registry. Callers use errors.Is.
var (
	ErrUnknownAdapter    = errors.New("collect: unknown adapter type")
	ErrDuplicateAdapter  = errors.New("collect: adapter id already registered")
	ErrDuplicateInstance = errors.New("collect: duplicate adapter instance id")
	ErrNotReadOnly       = errors.New("collect: adapter is not read-only")
	ErrInvalidFactory    = errors.New("collect: invalid factory")
	ErrAlreadyStarted    = errors.New("collect: registry already started")
	ErrMissingSite       = errors.New("collect: adapter has no site_id")
	ErrInvalidSink       = errors.New("collect: sink is nil")
)

// AdapterConfig is the per-instance configuration of one collector.
//
// SiteID and Clock are normally injected by the composition root / registry.
// For operator-authored configuration the site may also be provided through
// Options["site_id"]; the registry keeps both paths working.
type AdapterConfig struct {
	AdapterID string
	SiteID    domain.SiteID
	ZoneID    domain.ZoneID
	Options   map[string]string
	Clock     ports.Clock
}

// Option returns a trimmed option value, or "" when unset.
func (c AdapterConfig) Option(key string) string {
	if c.Options == nil {
		return ""
	}
	return trimSpace(c.Options[key])
}

// Now returns the current UTC time from the injected clock (system clock when
// no fake clock is configured). Adapters must use this for received_at.
func (c AdapterConfig) Now() time.Time {
	if c.Clock != nil {
		return c.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

// ResolveSite returns the site scope of the adapter. Events are site-scoped and
// the pipeline rejects events without a valid site, so a missing site is a
// startup error instead of a silent fake scope.
func (c AdapterConfig) ResolveSite() (domain.SiteID, error) {
	candidates := []string{string(c.SiteID), c.Option("site_id")}
	for _, raw := range candidates {
		raw = trimSpace(raw)
		if raw == "" {
			continue
		}
		id := domain.SiteID(raw)
		if err := id.Validate(); err != nil {
			return "", fmt.Errorf("adapter %q: site_id: %w", c.AdapterID, err)
		}
		return id, nil
	}
	return "", fmt.Errorf("%w: adapter %q (set AdapterConfig.SiteID or option \"site_id\")", ErrMissingSite, c.AdapterID)
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// Factory registers one adapter type. AdapterID is the type/kind (for example
// "modbus"); instance ids such as "modbus.pool1" are resolved to a factory by
// exact match first, then by the part before the first '.'.
type Factory struct {
	AdapterID string
	New       func(cfg AdapterConfig) (ports.Collector, error)
}

// Instrumented is implemented by adapters that maintain their own
// parser/unsupported counters. Adapters can satisfy it by embedding Counters.
type Instrumented interface {
	HealthCounters() CounterSnapshot
}

// HealthState is implemented by adapters that need to surface a degraded state
// or an operator warning (for example plaintext SNMP community usage). The MVP
// CollectorHealth type has no dedicated warning field, so Registry.Health puts
// the warning into LastError when there is no hard error and uses the state
// string from this interface.
type HealthState interface {
	HealthState() (state, warning string)
}

// CounterSnapshot is an immutable snapshot of an adapter's counters.
type CounterSnapshot struct {
	Errors       uint64
	ParserErrors uint64
	Unsupported  uint64
	LastError    string
}

// Merge adds another snapshot. The newest LastError wins.
func (s CounterSnapshot) Merge(other CounterSnapshot) CounterSnapshot {
	s.Errors += other.Errors
	s.ParserErrors += other.ParserErrors
	s.Unsupported += other.Unsupported
	if other.LastError != "" {
		s.LastError = other.LastError
	}
	return s
}

// IsZero reports whether no counter and no error text is set.
func (s CounterSnapshot) IsZero() bool {
	return s.Errors == 0 && s.ParserErrors == 0 && s.Unsupported == 0 && s.LastError == ""
}

// Counters is a thread-safe counter block adapters embed to report parser and
// unsupported-message metrics. The promoted HealthCounters method satisfies
// Instrumented.
type Counters struct {
	errors       atomic.Uint64
	parserErrors atomic.Uint64
	unsupported  atomic.Uint64

	mu      sync.Mutex
	lastErr string
}

// IncError counts an adapter-level error. Sink errors are counted by the
// framework wrapper and must not be counted twice.
func (c *Counters) IncError(msg string) {
	c.errors.Add(1)
	c.SetLastError(msg)
}

// IncErrorCount counts an error without storing a message.
func (c *Counters) IncErrorCount() { c.errors.Add(1) }

// IncParserError counts a malformed frame and stores the short reason.
func (c *Counters) IncParserError(msg string) {
	c.parserErrors.Add(1)
	c.SetLastError(msg)
}

// IncUnsupported counts a structurally valid frame that the adapter does not
// interpret (for example an unknown Modbus function code).
func (c *Counters) IncUnsupported() { c.unsupported.Add(1) }

// SetLastError stores the most recent error/warning text. Text is truncated to
// keep the health payload bounded.
func (c *Counters) SetLastError(msg string) {
	if msg == "" {
		return
	}
	if len(msg) > 240 {
		msg = msg[:240]
	}
	c.mu.Lock()
	c.lastErr = msg
	c.mu.Unlock()
}

// Merge adds a decoder snapshot to the counter block.
func (c *Counters) Merge(s CounterSnapshot) {
	c.errors.Add(s.Errors)
	c.parserErrors.Add(s.ParserErrors)
	c.unsupported.Add(s.Unsupported)
	if s.LastError != "" {
		c.SetLastError(s.LastError)
	}
}

// HealthCounters returns the current snapshot (implements Instrumented).
func (c *Counters) HealthCounters() CounterSnapshot {
	c.mu.Lock()
	last := c.lastErr
	c.mu.Unlock()
	return CounterSnapshot{
		Errors:       c.errors.Load(),
		ParserErrors: c.parserErrors.Load(),
		Unsupported:  c.unsupported.Load(),
		LastError:    last,
	}
}

// NewEventID creates a cryptographically random event identifier with the
// product-wide evt_ prefix (16 random bytes, hex encoded).
func NewEventID() (domain.EventID, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("collect: generate event id: %w", err)
	}
	return domain.EventID("evt_" + hex.EncodeToString(raw[:])), nil
}

// ValidCollection reports whether s is one of the supported collection method
// labels. The pipeline and the API rely on this closed set.
func ValidCollection(s string) bool {
	switch s {
	case CollectionPassiveTap, CollectionReadOnlyPoll, CollectionOperatorExport:
		return true
	}
	return false
}
