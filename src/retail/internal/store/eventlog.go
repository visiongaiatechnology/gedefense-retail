package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

const eventFilePrefix = "events"

// EventLog is the append-only JSONL event stream. It rotates by UTC day and by
// size, prunes expired files according to the retention window and answers
// bounded recent-event queries by scanning the newest file backwards.
type EventLog struct {
	dir           string
	maxBytes      int64
	retentionDays int
	clock         ports.Clock

	mu     sync.Mutex
	file   *rotatingFile
	closed bool

	total   atomic.Int64
	corrupt atomic.Int64
}

// OpenEventLog opens (and if necessary creates) the event log below opts.Dir.
func OpenEventLog(opts Options) (*EventLog, error) {
	norm, err := normalizeOptions(opts, defaultEventMaxMB)
	if err != nil {
		return nil, err
	}
	dir := joinDataPath(norm.Dir, "events")
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	log := &EventLog{
		dir:           dir,
		maxBytes:      norm.MaxMB << 20,
		retentionDays: norm.RetentionDays,
		clock:         norm.Clock,
	}
	if log.retentionDays == 0 {
		log.retentionDays = defaultEventRetentionDays
	}
	log.file = newRotatingFile(dir, eventFilePrefix, log.maxBytes, log.clock)
	log.file.onRotate = func(now time.Time, _ string) error {
		// The rotated file is closed at this point, so pruning may remove it.
		removed, perr := pruneByRetention(dir, eventFilePrefix, now, log.retentionDays, "")
		if perr != nil {
			return perr
		}
		alsoRemoved, perr := pruneBySize(dir, eventFilePrefix, log.maxBytes, "")
		if perr != nil {
			return perr
		}
		log.forgetEvents(append(removed, alsoRemoved...))
		return nil
	}
	now := log.clock.Now()
	if _, err := pruneByRetention(dir, eventFilePrefix, now, log.retentionDays, ""); err != nil {
		return nil, err
	}
	if _, err := pruneBySize(dir, eventFilePrefix, log.maxBytes, ""); err != nil {
		return nil, err
	}

	files, err := listDayFiles(dir, eventFilePrefix)
	if err != nil {
		return nil, err
	}
	var total int64
	for _, f := range files {
		n, cerr := countLines(f.path)
		if cerr != nil {
			return nil, cerr
		}
		total += n
	}
	log.total.Store(total)
	return log, nil
}

// Append validates and appends one event. The validation is defensive: the
// pipeline validates before it reaches the store, but the store must never
// persist an event it cannot vouch for.
func (l *EventLog) Append(ctx context.Context, ev domain.Event) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("store: append event: %w", err)
	}
	if err := ev.Validate(); err != nil {
		return fmt.Errorf("store: append event: %w", err)
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("store: marshal event %q: %w", ev.EventID, err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if err := l.file.write(line); err != nil {
		return fmt.Errorf("store: append event %q: %w", ev.EventID, err)
	}
	l.total.Add(1)
	return nil
}

// Recent returns up to q.Limit events in reverse append order (newest first),
// scanning only as many files as needed.
func (l *EventLog) Recent(ctx context.Context, q ports.EventQuery) ([]domain.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("store: recent events: %w", err)
	}
	limit := clampLimit(q.Limit)
	since, until, err := parseTimeRange(q.Since, q.Until)
	if err != nil {
		return nil, err
	}

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, ErrClosed
	}
	// Queries must observe events that are still in the write buffer.
	if err := l.file.flush(); err != nil {
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()
	files, err := listDayFiles(l.dir, eventFilePrefix)
	if err != nil {
		return nil, err
	}

	out := make([]domain.Event, 0, limit)
	for i := len(files) - 1; i >= 0 && len(out) < limit; i-- {
		ferr := forEachLineReverse(files[i].path, func(line []byte) (bool, error) {
			var ev domain.Event
			if uerr := json.Unmarshal(line, &ev); uerr != nil {
				l.corrupt.Add(1)
				return false, nil
			}
			if !eventMatches(ev, q, since, until) {
				return false, nil
			}
			out = append(out, ev)
			return len(out) >= limit, nil
		})
		if ferr != nil {
			return nil, ferr
		}
	}
	return out, nil
}

// Count returns the number of persisted events (including previous runs and
// excluding files removed by retention).
func (l *EventLog) Count() int64 { return l.total.Load() }

// forgetEvents subtracts the records of pruned files from the persisted count.
func (l *EventLog) forgetEvents(files []prunedFile) {
	var dropped int64
	for _, f := range files {
		dropped += f.lines
	}
	if dropped > 0 {
		l.total.Add(-dropped)
	}
}

// CorruptLines reports JSONL records that could not be decoded. A non-zero
// value is an operational alarm: the on-disk stream was modified or truncated.
func (l *EventLog) CorruptLines() int64 { return l.corrupt.Load() }

// Close flushes and closes the current file. It is idempotent.
func (l *EventLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.file.close()
}

// eventMatches applies an EventQuery to one event.
func eventMatches(ev domain.Event, q ports.EventQuery, since, until time.Time) bool {
	if q.SiteID != "" && ev.SiteID != q.SiteID {
		return false
	}
	if q.Kind != "" && ev.Kind != q.Kind {
		return false
	}
	if q.AssetID != "" && ev.AssetID != q.AssetID {
		return false
	}
	if q.SensorID != "" && ev.SensorID != q.SensorID {
		return false
	}
	if !since.IsZero() && ev.ObservedAt.Before(since) {
		return false
	}
	if !until.IsZero() && !ev.ObservedAt.Before(until) {
		return false
	}
	return true
}

// parseTimeRange parses the RFC 3339 bounds of a query. Empty bounds are open.
func parseTimeRange(since, until string) (time.Time, time.Time, error) {
	var s, u time.Time
	if since != "" {
		parsed, err := time.Parse(time.RFC3339, since)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("%w: since must be RFC 3339: %w", ErrInvalidQuery, err)
		}
		s = parsed
	}
	if until != "" {
		parsed, err := time.Parse(time.RFC3339, until)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("%w: until must be RFC 3339: %w", ErrInvalidQuery, err)
		}
		u = parsed
	}
	if !s.IsZero() && !u.IsZero() && u.Before(s) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: until is before since", ErrInvalidQuery)
	}
	return s, u, nil
}

// joinDataPath joins a data directory with a subdirectory name.
func joinDataPath(dir, child string) string { return filepath.Join(dir, child) }
