package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

func TestEventLogAppendAndRecent(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	log := mustOpenEventLog(t, dir, clock, 0, 0)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		at := baseTime.Add(time.Duration(i) * time.Minute)
		ev := testEvent(fmt.Sprintf("evt-%d", i+1), at)
		if err := log.Append(ctx, ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if got := log.Count(); got != 5 {
		t.Errorf("Count = %d, want 5", got)
	}

	recent, err := log.Recent(ctx, ports.EventQuery{Limit: 2})
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(recent) != 2 {
		t.Fatalf("Recent returned %d events, want 2", len(recent))
	}
	if recent[0].EventID != "evt-5" || recent[1].EventID != "evt-4" {
		t.Errorf("Recent order = %q, %q; want newest first", recent[0].EventID, recent[1].EventID)
	}

	filtered, err := log.Recent(ctx, ports.EventQuery{Since: baseTime.Add(2 * time.Minute).Format(time.RFC3339), Limit: 10})
	if err != nil {
		t.Fatalf("Recent since: %v", err)
	}
	if len(filtered) != 3 {
		t.Errorf("Recent since returned %d events, want 3", len(filtered))
	}

	none, err := log.Recent(ctx, ports.EventQuery{Kind: domain.EventFlow, Limit: 10})
	if err != nil {
		t.Fatalf("Recent kind: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("Recent kind returned %d events, want 0", len(none))
	}

	bySite, err := log.Recent(ctx, ports.EventQuery{SiteID: "filiale-999", Limit: 10})
	if err != nil {
		t.Fatalf("Recent site: %v", err)
	}
	if len(bySite) != 0 {
		t.Errorf("Recent site returned %d events, want 0", len(bySite))
	}
}

func TestEventLogPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	ctx := context.Background()

	log, err := OpenEventLog(Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := log.Append(ctx, testEvent(fmt.Sprintf("evt-%d", i+1), baseTime)); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("second Close must be idempotent: %v", err)
	}
	if err := log.Append(ctx, testEvent("evt-9", baseTime)); !errors.Is(err, ErrClosed) {
		t.Errorf("Append after Close = %v, want ErrClosed", err)
	}

	reopened := mustOpenEventLog(t, dir, clock, 0, 0)
	if got := reopened.Count(); got != 3 {
		t.Errorf("Count after reopen = %d, want 3", got)
	}
	recent, err := reopened.Recent(ctx, ports.EventQuery{Limit: 10})
	if err != nil {
		t.Fatalf("Recent after reopen: %v", err)
	}
	if len(recent) != 3 {
		t.Fatalf("Recent after reopen returned %d, want 3", len(recent))
	}
}

func TestEventLogRejectsInvalidEvent(t *testing.T) {
	log := mustOpenEventLog(t, t.TempDir(), newFakeClock(baseTime), 0, 0)
	ev := testEvent("evt-bad", baseTime)
	ev.Measurement = nil // telemetry without measurement is invalid
	if err := log.Append(context.Background(), ev); err == nil {
		t.Fatal("expected validation error")
	}
	if log.Count() != 0 {
		t.Errorf("Count = %d, want 0", log.Count())
	}
}

func TestEventLogRejectsInvalidTimeRange(t *testing.T) {
	log := mustOpenEventLog(t, t.TempDir(), newFakeClock(baseTime), 0, 0)
	_, err := log.Recent(context.Background(), ports.EventQuery{Since: "yesterday"})
	if err == nil || !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("err = %v, want ErrInvalidQuery", err)
	}
}

func TestEventLogRotatesBySize(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	log := mustOpenEventLog(t, dir, clock, 1, 30) // 1 MiB budget
	ctx := context.Background()

	line, err := json.Marshal(testEvent("evt-000001", baseTime))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	count := (1<<20)/(len(line)+1) + 5
	for i := 0; i < count; i++ {
		ev := testEvent(fmt.Sprintf("evt-%06d", i), baseTime)
		if err := log.Append(ctx, ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	files, err := listDayFiles(filepath.Join(dir, "events"), eventFilePrefix)
	if err != nil {
		t.Fatalf("listDayFiles: %v", err)
	}
	if len(files) < 2 {
		t.Fatalf("expected rotation into at least 2 files, got %d", len(files))
	}
	if files[0].idx != 1 || files[1].idx != 2 {
		t.Errorf("rotation indices = %d, %d; want 1, 2", files[0].idx, files[1].idx)
	}
	if got := log.Count(); got != int64(count) {
		t.Errorf("Count = %d, want %d", got, count)
	}
}

func TestEventLogRetentionPrunesOldDays(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	log := mustOpenEventLog(t, dir, clock, 0, 1)
	ctx := context.Background()

	if err := log.Append(ctx, testEvent("evt-day1", baseTime)); err != nil {
		t.Fatalf("Append day1: %v", err)
	}
	if got := log.Count(); got != 1 {
		t.Fatalf("Count = %d, want 1", got)
	}

	clock.Advance(4 * 24 * time.Hour)
	if err := log.Append(ctx, testEvent("evt-day5", clock.Now())); err != nil {
		t.Fatalf("Append day5: %v", err)
	}
	files, err := listDayFiles(filepath.Join(dir, "events"), eventFilePrefix)
	if err != nil {
		t.Fatalf("listDayFiles: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected only the current day file, got %d", len(files))
	}
	if !files[0].day.Equal(utcDay(clock.Now())) {
		t.Errorf("remaining file day = %v, want %v", files[0].day, utcDay(clock.Now()))
	}
	if got := log.Count(); got != 1 {
		t.Errorf("Count after retention = %d, want 1", got)
	}
}

func TestEventLogCountsCorruptLines(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	ctx := context.Background()

	log, err := OpenEventLog(Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	if err := log.Append(ctx, testEvent("evt-1", baseTime)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	path := filepath.Join(dir, "events", dayFileName(eventFilePrefix, baseTime, 1))
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for corruption: %v", err)
	}
	if _, werr := file.WriteString("{not json}\n"); werr != nil {
		t.Fatalf("write corruption: %v", werr)
	}
	if cerr := file.Close(); cerr != nil {
		t.Fatalf("close corruption file: %v", cerr)
	}

	reopened := mustOpenEventLog(t, dir, clock, 0, 0)
	recent, err := reopened.Recent(ctx, ports.EventQuery{Limit: 10})
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(recent) != 1 {
		t.Errorf("Recent returned %d events, want 1", len(recent))
	}
	if got := reopened.CorruptLines(); got != 1 {
		t.Errorf("CorruptLines = %d, want 1", got)
	}
}
