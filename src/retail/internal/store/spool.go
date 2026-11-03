package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

const (
	spoolFileSuffix = ".json"
	spoolSeqDigits  = 20
	spoolDrainMax   = 1000
)

// spoolEntry is one queued event. The event is kept in memory as well as on
// disk so that Drain does not need to re-read the queue on the hot path.
type spoolEntry struct {
	seq   int64
	size  int64
	event domain.Event
	path  string
}

// Spool is the bounded store-and-forward queue for the optional central
// connection. The capacity is a hard byte budget; Enqueue returns ErrSpoolFull
// instead of blocking the detection pipeline.
type Spool struct {
	dir       string
	capacity  int64
	clock     ports.Clock
	forwarder ports.Forwarder

	mu      sync.Mutex
	drainMu sync.Mutex
	entries []spoolEntry
	dedupe  map[string]struct{}
	bytes   int64
	nextSeq int64
	closed  bool
}

// OpenSpool rebuilds the spool index from disk: order, size accounting and the
// dedup set. A queue that cannot be reconstructed is a hard error.
func OpenSpool(opts Options) (*Spool, error) {
	norm, err := normalizeOptions(opts, defaultSpoolMaxMB)
	if err != nil {
		return nil, err
	}
	dir := joinDataPath(norm.Dir, "spool")
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	s := &Spool{
		dir:       dir,
		capacity:  norm.MaxMB << 20,
		clock:     norm.Clock,
		forwarder: opts.Forwarder,
		dedupe:    make(map[string]struct{}, 64),
		nextSeq:   1,
	}
	if opts.SpoolCapacityBytes > 0 {
		s.capacity = opts.SpoolCapacityBytes
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("store: read spool directory: %w", err)
	}
	loaded := make([]spoolEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		seq, ok := parseSpoolFileName(entry.Name())
		if !ok {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, rerr := readPrivateFile(path)
		if rerr != nil {
			return nil, fmt.Errorf("store: %w: spool entry %q: %v", ErrCorruptState, entry.Name(), rerr)
		}
		var ev domain.Event
		if uerr := json.Unmarshal(raw, &ev); uerr != nil {
			return nil, fmt.Errorf("store: %w: spool entry %q: %v", ErrCorruptState, entry.Name(), uerr)
		}
		if verr := ev.Validate(); verr != nil {
			return nil, fmt.Errorf("store: %w: spool entry %q: %v", ErrCorruptState, entry.Name(), verr)
		}
		key := ev.DedupKey()
		if _, dup := s.dedupe[key]; dup {
			return nil, fmt.Errorf("store: %w: duplicate spool dedup key %q", ErrCorruptState, key)
		}
		s.dedupe[key] = struct{}{}
		s.bytes += int64(len(raw))
		loaded = append(loaded, spoolEntry{seq: seq, size: int64(len(raw)), event: ev, path: path})
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].seq < loaded[j].seq })
	s.entries = loaded
	if len(loaded) > 0 {
		s.nextSeq = loaded[len(loaded)-1].seq + 1
	}
	return s, nil
}

// Enqueue stores one event. A duplicate dedup key is accepted as a no-op
// (at-least-once delivery), a full spool returns ErrSpoolFull.
func (s *Spool) Enqueue(ctx context.Context, ev domain.Event) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("store: enqueue spool event: %w", err)
	}
	if err := ev.Validate(); err != nil {
		return fmt.Errorf("store: enqueue spool event: %w", err)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("store: marshal spool event %q: %w", ev.EventID, err)
	}
	raw = append(raw, '\n')
	key := ev.DedupKey()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if _, dup := s.dedupe[key]; dup {
		return nil
	}
	size := int64(len(raw))
	if s.bytes+size > s.capacity {
		return fmt.Errorf("%w: %d of %d bytes used, event needs %d", ErrSpoolFull, s.bytes, s.capacity, size)
	}
	seq := s.nextSeq
	path := filepath.Join(s.dir, fmt.Sprintf("%0*d%s", spoolSeqDigits, seq, spoolFileSuffix))
	if err := writeFileAtomic(path, raw); err != nil {
		return err
	}
	s.nextSeq++
	s.entries = append(s.entries, spoolEntry{seq: seq, size: size, event: ev, path: path})
	s.dedupe[key] = struct{}{}
	s.bytes += size
	return nil
}

// Drain forwards the oldest up to max events through the configured forwarder
// and removes them from the queue only after a successful delivery. Without a
// forwarder it fails with ErrNoForwarder: deleting undelivered events would be
// silent data loss.
func (s *Spool) Drain(ctx context.Context, max int) ([]domain.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("store: drain spool: %w", err)
	}
	limit := clampLimit(max)
	s.drainMu.Lock()
	defer s.drainMu.Unlock()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	if s.forwarder == nil {
		s.mu.Unlock()
		return nil, ErrNoForwarder
	}
	count := len(s.entries)
	if count > limit {
		count = limit
	}
	batch := make([]domain.Event, 0, count)
	seqs := make([]int64, 0, count)
	for _, entry := range s.entries[:count] {
		batch = append(batch, entry.event)
		seqs = append(seqs, entry.seq)
	}
	forwarder := s.forwarder
	s.mu.Unlock()

	if len(batch) == 0 {
		return batch, nil
	}
	if err := forwarder.Forward(ctx, batch); err != nil {
		return nil, fmt.Errorf("store: forward spool batch: %w", err)
	}
	if err := s.remove(seqs); err != nil {
		return nil, err
	}
	return batch, nil
}

// Peek returns the oldest up to max queued events without removing them. It is
// the read-only counterpart for forwarders that manage acknowledgement
// themselves (see Ack).
func (s *Spool) Peek(ctx context.Context, max int) ([]domain.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("store: peek spool: %w", err)
	}
	limit := clampLimit(max)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	count := len(s.entries)
	if count > limit {
		count = limit
	}
	out := make([]domain.Event, 0, count)
	for _, entry := range s.entries[:count] {
		out = append(out, entry.event)
	}
	return out, nil
}

// Ack removes previously peeked events after a successful external delivery.
func (s *Spool) Ack(ctx context.Context, events []domain.Event) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("store: ack spool: %w", err)
	}
	if len(events) == 0 {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	keys := make([]string, 0, len(events))
	for _, ev := range events {
		keys = append(keys, ev.DedupKey())
	}
	s.mu.Unlock()
	return s.removeByKeys(keys)
}

// Len returns the number of queued events.
func (s *Spool) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Bytes returns the number of bytes currently held by the queue.
func (s *Spool) Bytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}

// Close marks the spool closed. Persisted entries stay on disk for the next
// start; nothing is dropped on shutdown.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// remove deletes the entries with the given sequence numbers.
func (s *Spool) remove(seqs []int64) error {
	want := make(map[int64]struct{}, len(seqs))
	for _, seq := range seqs {
		want[seq] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return s.removeLocked(func(entry spoolEntry) bool {
		_, ok := want[entry.seq]
		return ok
	})
}

// removeByKeys deletes entries whose dedup key is in keys.
func (s *Spool) removeByKeys(keys []string) error {
	want := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		want[key] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return s.removeLocked(func(entry spoolEntry) bool {
		_, ok := want[entry.event.DedupKey()]
		return ok
	})
}

// removeLocked drops every matching entry from memory and disk.
func (s *Spool) removeLocked(match func(spoolEntry) bool) error {
	kept := make([]spoolEntry, 0, len(s.entries))
	var firstErr error
	for _, entry := range s.entries {
		if !match(entry) {
			kept = append(kept, entry)
			continue
		}
		if rerr := os.Remove(entry.path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) && firstErr == nil {
			firstErr = fmt.Errorf("store: remove spool entry %q: %w", filepath.Base(entry.path), rerr)
			kept = append(kept, entry)
			continue
		}
		delete(s.dedupe, entry.event.DedupKey())
		s.bytes -= entry.size
	}
	s.entries = kept
	return firstErr
}

// parseSpoolFileName parses "<20 digits>.json" into its sequence number.
func parseSpoolFileName(name string) (int64, bool) {
	if !strings.HasSuffix(name, spoolFileSuffix) {
		return 0, false
	}
	base := strings.TrimSuffix(name, spoolFileSuffix)
	if len(base) != spoolSeqDigits {
		return 0, false
	}
	seq, err := strconv.ParseInt(base, 10, 64)
	if err != nil || seq < 1 {
		return 0, false
	}
	return seq, true
}
