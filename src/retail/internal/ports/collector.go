// Package ports defines the seams between the composition root, the passive
// collectors, the detection engine and the storage layer.
//
// Go idiom prefers consumer-side interfaces. This package is a deliberate,
// documented exception: the collector framework, the adapters and the storage
// implementation are developed and tested as isolated units, and the hidden
// dependency of a struct-carrying interface (domain types are the only shared
// vocabulary) would otherwise force every package to duplicate the same
// definitions. All interfaces here are small (<= 6 methods) and satisfied
// implicitly, so any concrete type in any package can implement them without
// importing this package.
package ports

import (
	"context"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Info is the static identity of a collector/adapter. ReadOnly MUST be true for
// every adapter in this product; there is no writable adapter variant.
type Info struct {
	AdapterID   string   `json:"adapter_id"`
	Version     string   `json:"version"`
	Protocols   []string `json:"protocols"`
	Collection  string   `json:"collection_method"` // passive_tap | read_only_poll | operator_export
	ReadOnly    bool     `json:"read_only"`
	Description string   `json:"description"`
}

// Sink receives normalized events. Implementations MUST be safe for concurrent
// use and MUST apply backpressure instead of dropping silently.
type Sink interface {
	Emit(ctx context.Context, ev domain.Event) error
}

// SinkFunc adapts a function to Sink (used by tests and the simulator).
type SinkFunc func(ctx context.Context, ev domain.Event) error

// Emit implements Sink.
func (f SinkFunc) Emit(ctx context.Context, ev domain.Event) error { return f(ctx, ev) }

// Collector is one isolated passive data source. Implementations MUST:
//   - never write to any OT device,
//   - respect ctx cancellation promptly,
//   - isolate their own failures (a parser error must not stop the process),
//   - expose health counters through Health().
type Collector interface {
	Info() Info
	Start(ctx context.Context, sink Sink) error
}

// CollectorHealth is the runtime state surfaced in the dashboard and the API.
type CollectorHealth struct {
	AdapterID    string `json:"adapter_id"`
	State        string `json:"state"` // running, degraded, stopped, failed
	LastEventAt  string `json:"last_event_at,omitempty"`
	Events       uint64 `json:"events"`
	Errors       uint64 `json:"errors"`
	ParserErrors uint64 `json:"parser_errors"`
	Unsupported  uint64 `json:"unsupported"`
	LastError    string `json:"last_error,omitempty"`
}

// EventStore persists the normalized event stream and answers read queries.
type EventStore interface {
	Append(ctx context.Context, ev domain.Event) error
	Recent(ctx context.Context, q EventQuery) ([]domain.Event, error)
	Count() int64
	Close() error
}

// EventQuery selects a bounded slice of the event stream.
type EventQuery struct {
	SiteID   domain.SiteID
	Kind     domain.EventKind
	AssetID  domain.AssetID
	SensorID domain.SensorID
	Since    string // RFC3339, inclusive
	Until    string // RFC3339, exclusive
	Limit    int    // hard default enforced by the implementation
}

// AlertStore keeps the current alert state and its audit history.
type AlertStore interface {
	Upsert(ctx context.Context, alert domain.Alert) error
	Get(ctx context.Context, id domain.AlertID) (domain.Alert, bool, error)
	List(ctx context.Context, q AlertQuery) ([]domain.Alert, error)
	Close() error
}

// AlertQuery selects alerts for the API/dashboard.
type AlertQuery struct {
	SiteID   domain.SiteID
	Status   domain.AlertStatus
	Severity domain.Severity
	Category domain.Category
	Limit    int
}

// AuditStore is the append-only, hash-chained audit log.
type AuditStore interface {
	Append(ctx context.Context, entry domain.AuditEntry) (domain.AuditEntry, error)
	List(ctx context.Context, limit int) ([]domain.AuditEntry, error)
	Verify(ctx context.Context) (bool, uint64, error)
	Close() error
}

// Spool is the bounded store-and-forward queue for the optional central
// connection. It MUST never block the detection loop: Enqueue returns an error
// when the spool is full so the caller can count and surface the loss.
type Spool interface {
	Enqueue(ctx context.Context, ev domain.Event) error
	Drain(ctx context.Context, max int) ([]domain.Event, error)
	Len() int
}

// Forwarder delivers a batch to the central management plane.
type Forwarder interface {
	Forward(ctx context.Context, events []domain.Event) error
}

// Notifier delivers local alerts (webhook, syslog, log sink).
type Notifier interface {
	Notify(ctx context.Context, alert domain.Alert) error
}

// Clock decouples detection rules from wall time for deterministic tests.
type Clock interface {
	Now() time.Time
}
