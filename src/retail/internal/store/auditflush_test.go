package store

import (
	"context"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// TestAuditFlushPersistsBufferedEntries covers FIND-010: a clean shutdown calls
// Flush so the last (<128) entries reach disk.
func TestAuditFlushPersistsBufferedEntries(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	log, err := OpenAuditLog(Options{Dir: dir, Clock: fixedClock{at: now}})
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	defer func() { _ = log.Close() }()
	for i := 0; i < 5; i++ {
		entry := domain.AuditEntry{
			At: now, Actor: "admin", Role: "admin", Action: "test.flush",
			ObjectType: "setup", ObjectID: "first-run", Reason: "flush-test",
		}
		if _, err := log.Append(context.Background(), entry); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := log.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	entries, err := readAuditEntries(dir + "/audit")
	if err != nil {
		t.Fatalf("readAuditEntries: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("persisted audit entries = %d, want 5", len(entries))
	}
}
