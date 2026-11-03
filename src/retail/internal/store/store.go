// Package store implements the persistent local state of a GeDefense Retail
// gateway: the append-only event log, the alert state store, the hash-chained
// audit log and the bounded store-and-forward spool.
//
// Layout. Every store owns a subdirectory below Options.Dir:
//
//	<dir>/events/events-<utcdate>[-<n>].jsonl   append-only event stream
//	<dir>/alerts/alerts.json                     atomic alert state (temp+rename)
//	<dir>/audit/audit-<utcdate>[-<n>].jsonl      hash-chained audit trail
//	<dir>/spool/<seq>.json                       store-and-forward queue
//
// All files are created 0600 and all directories 0700. Symlinked state files are
// rejected instead of followed so that an attacker who can write into the data
// directory cannot redirect the audit trail. State reads and appends verify the
// opened descriptor against the path (verifyOpenedFile) to close the
// classic symlink TOCTOU window.
//
// Residual risk: the data directory itself and its parents are only protected by
// the 0700 permission; a local attacker who can replace a whole parent directory
// is outside the threat model of the MVP.
package store

import (
	"errors"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Options configures a single store instance. MaxMB and RetentionDays are
// interpreted by the store that owns the data (see each Open function).
type Options struct {
	// Dir is the base data directory of the gateway.
	Dir string
	// MaxMB is the size budget for the store's data in mebibytes (0 = default).
	MaxMB int64
	// RetentionDays is the local retention in days (0 = default / unlimited).
	RetentionDays int
	// Clock provides the wall clock; nil uses the system UTC clock.
	Clock ports.Clock
	// Forwarder is only used by the spool. Drain forwards a batch through it and
	// removes the batch only after Forward returned nil.
	Forwarder ports.Forwarder
	// SpoolCapacityBytes overrides the spool capacity in bytes (0 = use MaxMB).
	// It exists so small test spools do not need to fill megabytes.
	SpoolCapacityBytes int64
}

// Sentinel errors. Callers branch on these with errors.Is; never on strings.
var (
	// ErrClosed is returned by every method called after Close.
	ErrClosed = errors.New("store is closed")
	// ErrSpoolFull is returned when the bounded spool cannot accept an event.
	ErrSpoolFull = errors.New("spool is full")
	// ErrNoForwarder is returned by Spool.Drain when no forwarder is configured.
	// Draining without forwarding would delete undelivered events.
	ErrNoForwarder = errors.New("spool has no forwarder configured")
	// ErrCorruptState is returned when persisted state cannot be trusted.
	ErrCorruptState = errors.New("persisted state is corrupt")
	// ErrChainBroken is returned when the audit hash chain does not verify.
	ErrChainBroken = errors.New("audit hash chain is broken")
	// ErrInvalidQuery is returned for malformed time filters.
	ErrInvalidQuery = errors.New("invalid query")
	// ErrNotFound is returned when a persisted object does not exist.
	ErrNotFound = errors.New("not found")
)

const (
	defaultEventMaxMB         = 2048
	defaultSpoolMaxMB         = 512
	defaultEventRetentionDays = 30

	// flushEveryWrites bounds how many lines may be buffered before an
	// explicit flush+fsync. Small enough to lose at most a fraction of a second
	// of telemetry, large enough to keep the append hot path cheap.
	flushEveryWrites = 128

	maxQueryLimit     = 1000
	defaultQueryLimit = 100

	// maxLineBytes bounds one JSONL record. Events carry metadata only, so a
	// record above 4 MiB is corrupt or hostile.
	maxLineBytes = 4 << 20

	// zeroHash is the prev_hash of the first audit entry (the chain seed).
	zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

// wallClock is the default ports.Clock implementation.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

// clockOr returns c or the system UTC clock when c is nil.
func clockOr(c ports.Clock) ports.Clock {
	if c == nil {
		return wallClock{}
	}
	return c
}

// normalizeOptions validates Options and fills in the documented defaults.
func normalizeOptions(opts Options, defaultMaxMB int64) (Options, error) {
	if opts.Dir == "" {
		return Options{}, fmt.Errorf("store: options: Dir is required")
	}
	if opts.MaxMB < 0 {
		return Options{}, fmt.Errorf("store: options: MaxMB must not be negative")
	}
	if opts.RetentionDays < 0 {
		return Options{}, fmt.Errorf("store: options: RetentionDays must not be negative")
	}
	if opts.MaxMB == 0 {
		opts.MaxMB = defaultMaxMB
	}
	opts.Clock = clockOr(opts.Clock)
	return opts, nil
}

// clampLimit applies the query defaults used by every read path.
func clampLimit(limit int) int {
	if limit <= 0 {
		return defaultQueryLimit
	}
	if limit > maxQueryLimit {
		return maxQueryLimit
	}
	return limit
}
