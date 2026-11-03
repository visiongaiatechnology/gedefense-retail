package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// recordingForwarder captures delivered batches and can be configured to fail.
type recordingForwarder struct {
	mu        sync.Mutex
	delivered [][]domain.Event
	failWith  error
}

func (f *recordingForwarder) Forward(_ context.Context, events []domain.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return f.failWith
	}
	f.delivered = append(f.delivered, append([]domain.Event(nil), events...))
	return nil
}

func (f *recordingForwarder) batchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.delivered)
}

func mustOpenSpool(t *testing.T, dir string, clock ports.Clock, capacity int64, forwarder ports.Forwarder) *Spool {
	t.Helper()
	spool, err := OpenSpool(Options{Dir: dir, Clock: clock, SpoolCapacityBytes: capacity, Forwarder: forwarder})
	if err != nil {
		t.Fatalf("OpenSpool: %v", err)
	}
	t.Cleanup(func() {
		if cerr := spool.Close(); cerr != nil {
			t.Errorf("Spool.Close: %v", cerr)
		}
	})
	return spool
}

func TestSpoolEnqueuePersistsAndDedupes(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	ctx := context.Background()
	spool := mustOpenSpool(t, dir, clock, 1<<20, nil)

	if err := spool.Enqueue(ctx, testEvent("evt-1", baseTime)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := spool.Enqueue(ctx, testEvent("evt-2", baseTime)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := spool.Enqueue(ctx, testEvent("evt-1", baseTime)); err != nil {
		t.Fatalf("duplicate Enqueue: %v", err)
	}
	if got := spool.Len(); got != 2 {
		t.Errorf("Len = %d, want 2", got)
	}
	if spool.Bytes() <= 0 {
		t.Errorf("Bytes = %d, want > 0", spool.Bytes())
	}

	if cerr := spool.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	reopened := mustOpenSpool(t, dir, clock, 1<<20, nil)
	if got := reopened.Len(); got != 2 {
		t.Fatalf("Len after reopen = %d, want 2", got)
	}
	// The dedup set must be reconstructed from disk.
	if err := reopened.Enqueue(ctx, testEvent("evt-2", baseTime)); err != nil {
		t.Fatalf("duplicate after reopen: %v", err)
	}
	if got := reopened.Len(); got != 2 {
		t.Errorf("Len after duplicate = %d, want 2", got)
	}
	peeked, err := reopened.Peek(ctx, 10)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if len(peeked) != 2 || peeked[0].EventID != "evt-1" || peeked[1].EventID != "evt-2" {
		t.Errorf("Peek order = %+v", peeked)
	}
}

func TestSpoolFull(t *testing.T) {
	ctx := context.Background()
	line, err := jsonMarshalEvent(testEvent("evt-000", baseTime))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	capacity := int64(len(line)+1) * 2
	spool := mustOpenSpool(t, t.TempDir(), newFakeClock(baseTime), capacity, nil)

	accepted := 0
	var fullErr error
	for i := 0; i < 10; i++ {
		if err := spool.Enqueue(ctx, testEvent(fmt.Sprintf("evt-%03d", i), baseTime)); err != nil {
			fullErr = err
			break
		}
		accepted++
	}
	if fullErr == nil {
		t.Fatal("expected ErrSpoolFull")
	}
	if !errors.Is(fullErr, ErrSpoolFull) {
		t.Fatalf("err = %v, want ErrSpoolFull", fullErr)
	}
	if accepted != 2 {
		t.Errorf("accepted = %d, want 2", accepted)
	}
	if got := spool.Len(); got != 2 {
		t.Errorf("Len = %d, want 2", got)
	}
}

func TestSpoolDrainRequiresForwarder(t *testing.T) {
	ctx := context.Background()
	spool := mustOpenSpool(t, t.TempDir(), newFakeClock(baseTime), 1<<20, nil)
	if err := spool.Enqueue(ctx, testEvent("evt-1", baseTime)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := spool.Drain(ctx, 10); !errors.Is(err, ErrNoForwarder) {
		t.Fatalf("Drain without forwarder = %v, want ErrNoForwarder", err)
	}
	if got := spool.Len(); got != 1 {
		t.Errorf("Len after failed drain = %d, want 1", got)
	}
}

func TestSpoolDrainDeletesOnlyAfterSuccess(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	forwarder := &recordingForwarder{}
	spool := mustOpenSpool(t, dir, newFakeClock(baseTime), 1<<20, forwarder)
	for i := 0; i < 3; i++ {
		if err := spool.Enqueue(ctx, testEvent(fmt.Sprintf("evt-%d", i+1), baseTime)); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	// A failing forward must keep every entry.
	forwarder.failWith = errors.New("central unavailable")
	if _, err := spool.Drain(ctx, 10); err == nil {
		t.Fatal("expected forward error")
	}
	if got := spool.Len(); got != 3 {
		t.Errorf("Len after failed forward = %d, want 3", got)
	}

	// A successful forward removes exactly the delivered batch.
	forwarder.failWith = nil
	batch, err := spool.Drain(ctx, 2)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(batch) != 2 {
		t.Errorf("batch size = %d, want 2", len(batch))
	}
	if got := spool.Len(); got != 1 {
		t.Errorf("Len after drain = %d, want 1", got)
	}
	remaining, err := spool.Peek(ctx, 10)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if len(remaining) != 1 || remaining[0].EventID != "evt-3" {
		t.Errorf("remaining = %+v", remaining)
	}
	if forwarder.batchCount() != 1 {
		t.Errorf("forwarder batches = %d, want 1", forwarder.batchCount())
	}

	// Files of delivered events are gone from disk.
	entries, err := os.ReadDir(filepath.Join(dir, "spool"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("spool files on disk = %d, want 1", len(entries))
	}
}

func TestSpoolAckRemovesPeekedEvents(t *testing.T) {
	ctx := context.Background()
	spool := mustOpenSpool(t, t.TempDir(), newFakeClock(baseTime), 1<<20, nil)
	for i := 0; i < 2; i++ {
		if err := spool.Enqueue(ctx, testEvent(fmt.Sprintf("evt-%d", i+1), baseTime)); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
	batch, err := spool.Peek(ctx, 1)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if err := spool.Ack(ctx, batch); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if got := spool.Len(); got != 1 {
		t.Errorf("Len after Ack = %d, want 1", got)
	}
	// Acknowledging an unknown event is a no-op.
	if err := spool.Ack(ctx, []domain.Event{testEvent("evt-unknown", baseTime)}); err != nil {
		t.Fatalf("Ack unknown: %v", err)
	}
}

func TestSpoolRejectsCorruptEntry(t *testing.T) {
	dir := t.TempDir()
	spoolDir := filepath.Join(dir, "spool")
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(spoolDir, fmt.Sprintf("%0*d.json", spoolSeqDigits, 1))
	if err := os.WriteFile(path, []byte("{not an event}\n"), 0o600); err != nil {
		t.Fatalf("write corrupt spool entry: %v", err)
	}
	if _, err := OpenSpool(Options{Dir: dir, Clock: newFakeClock(baseTime)}); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("Open on corrupt spool = %v, want ErrCorruptState", err)
	}
}

func TestSpoolRejectsInvalidEvent(t *testing.T) {
	spool := mustOpenSpool(t, t.TempDir(), newFakeClock(baseTime), 1<<20, nil)
	ev := testEvent("evt-bad", baseTime)
	ev.SiteID = ""
	if err := spool.Enqueue(context.Background(), ev); err == nil {
		t.Fatal("expected validation error")
	}
	if spool.Len() != 0 {
		t.Errorf("Len = %d, want 0", spool.Len())
	}
}

func jsonMarshalEvent(ev domain.Event) ([]byte, error) { return json.Marshal(ev) }
