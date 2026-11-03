package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func jsonMarshal(entry domain.AuditEntry) ([]byte, error) { return json.Marshal(entry) }

func TestAuditLogChainsEntries(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	log, err := OpenAuditLog(Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	ctx := context.Background()

	var appended []domain.AuditEntry
	for i := 0; i < 3; i++ {
		entry := testAuditEntry("policy.update", "policy-filiale-001", baseTime.Add(time.Duration(i)*time.Minute))
		entry.Actor = fmt.Sprintf("admin-%d", i+1)
		stored, aerr := log.Append(ctx, entry)
		if aerr != nil {
			t.Fatalf("Append %d: %v", i, aerr)
		}
		if stored.Seq != uint64(i+1) {
			t.Errorf("seq = %d, want %d", stored.Seq, i+1)
		}
		appended = append(appended, stored)
	}
	for i := 1; i < len(appended); i++ {
		if appended[i].PrevHash != appended[i-1].Hash {
			t.Errorf("entry %d prev_hash does not link to entry %d", i, i-1)
		}
	}
	if appended[0].PrevHash != zeroHash {
		t.Errorf("first prev_hash = %q, want zero hash", appended[0].PrevHash)
	}

	ok, badSeq, err := log.Verify(ctx)
	if err != nil || !ok || badSeq != 0 {
		t.Fatalf("Verify = %v, %d, %v", ok, badSeq, err)
	}
	if log.FirstSeq() != 1 || log.Count() != 3 {
		t.Errorf("FirstSeq=%d Count=%d", log.FirstSeq(), log.Count())
	}

	listed, err := log.List(ctx, 2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 2 || listed[0].Seq != 2 || listed[1].Seq != 3 {
		t.Errorf("List = %+v", listed)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestAuditLogResumesAfterReopen(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	ctx := context.Background()

	log, err := OpenAuditLog(Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	if _, aerr := log.Append(ctx, testAuditEntry("window.create", "win-1", baseTime)); aerr != nil {
		t.Fatalf("Append: %v", aerr)
	}
	if cerr := log.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	reopened, err := OpenAuditLog(Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	next, aerr := reopened.Append(ctx, testAuditEntry("window.close", "win-1", baseTime.Add(time.Minute)))
	if aerr != nil {
		t.Fatalf("Append after reopen: %v", aerr)
	}
	if next.Seq != 2 {
		t.Errorf("seq after reopen = %d, want 2", next.Seq)
	}
	if ok, _, verr := reopened.Verify(ctx); verr != nil || !ok {
		t.Fatalf("Verify after reopen = %v, %v", ok, verr)
	}
	if cerr := reopened.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}
}

func TestAuditLogDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	ctx := context.Background()

	log, err := OpenAuditLog(Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	for i := 0; i < 3; i++ {
		entry := testAuditEntry("policy.update", "policy-filiale-001", baseTime.Add(time.Duration(i)*time.Minute))
		entry.Actor = fmt.Sprintf("admin-%d", i+1)
		if _, aerr := log.Append(ctx, entry); aerr != nil {
			t.Fatalf("Append %d: %v", i, aerr)
		}
	}

	// Persist and close before tampering with the on-disk record.
	if cerr := log.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}
	path := filepath.Join(dir, "audit", dayFileName(auditFilePrefix, baseTime, 1))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	tampered := bytes.Replace(raw, []byte(`"admin-2"`), []byte(`"admin-X"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("tamper replacement did not apply")
	}
	if werr := os.WriteFile(path, tampered, 0o600); werr != nil {
		t.Fatalf("write tampered file: %v", werr)
	}

	ok, badSeq, verr := log.Verify(ctx)
	if verr != nil {
		t.Fatalf("Verify: %v", verr)
	}
	if ok {
		t.Fatal("Verify accepted a tampered chain")
	}
	if badSeq != 2 {
		t.Errorf("badSeq = %d, want 2", badSeq)
	}

	if _, oerr := OpenAuditLog(Options{Dir: dir, Clock: clock}); !errors.Is(oerr, ErrChainBroken) {
		t.Fatalf("Open on tampered chain = %v, want ErrChainBroken", oerr)
	}
}

func TestAuditLogEmptyAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	ctx := context.Background()

	log, err := OpenAuditLog(Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	ok, badSeq, verr := log.Verify(ctx)
	if verr != nil || !ok || badSeq != 0 {
		t.Fatalf("empty Verify = %v, %d, %v", ok, badSeq, verr)
	}
	if log.FirstSeq() != 0 || log.Count() != 0 {
		t.Errorf("empty FirstSeq=%d Count=%d", log.FirstSeq(), log.Count())
	}
	if cerr := log.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	auditDir := filepath.Join(dir, "audit")
	if merr := os.MkdirAll(auditDir, 0o700); merr != nil {
		t.Fatalf("MkdirAll: %v", merr)
	}
	badFile := filepath.Join(auditDir, dayFileName(auditFilePrefix, baseTime, 1))
	if werr := os.WriteFile(badFile, []byte("{broken\n"), 0o600); werr != nil {
		t.Fatalf("write corrupt audit file: %v", werr)
	}
	if _, oerr := OpenAuditLog(Options{Dir: dir, Clock: clock}); !errors.Is(oerr, ErrCorruptState) {
		t.Fatalf("Open on corrupt audit file = %v, want ErrCorruptState", oerr)
	}
}

func TestAuditLogRejectsGapInSequence(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	ctx := context.Background()
	log, err := OpenAuditLog(Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	if _, aerr := log.Append(ctx, testAuditEntry("a", "obj-1", baseTime)); aerr != nil {
		t.Fatalf("Append: %v", aerr)
	}
	if cerr := log.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	path := filepath.Join(dir, "audit", dayFileName(auditFilePrefix, baseTime, 1))
	first := readEntriesForTest(t, path)[0]
	// A forged entry whose hash and prev-hash link are internally consistent,
	// but whose sequence skips a number: only the gap check can catch it.
	forged, ferr := domain.NewAuditEntry(domain.AuditEntry{
		Seq: 5, At: baseTime.Add(time.Minute), Actor: "admin", Role: "admin",
		Action: "b", ObjectType: "policy", ObjectID: "obj-1", PrevHash: first.Hash,
	})
	if ferr != nil {
		t.Fatalf("NewAuditEntry: %v", ferr)
	}
	line, merr := jsonMarshal(forged)
	if merr != nil {
		t.Fatalf("marshal: %v", merr)
	}
	file, oerr := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if oerr != nil {
		t.Fatalf("open audit file: %v", oerr)
	}
	if _, werr := file.Write(append(line, '\n')); werr != nil {
		t.Fatalf("write forged entry: %v", werr)
	}
	if cerr := file.Close(); cerr != nil {
		t.Fatalf("close: %v", cerr)
	}

	if _, oerr := OpenAuditLog(Options{Dir: dir, Clock: clock}); !errors.Is(oerr, ErrChainBroken) {
		t.Fatalf("Open with seq gap = %v, want ErrChainBroken", oerr)
	}
}

// readEntriesForTest decodes the JSONL audit file at path.
func readEntriesForTest(t *testing.T, path string) []domain.AuditEntry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	var entries []domain.AuditEntry
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var entry domain.AuditEntry
		if uerr := json.Unmarshal(line, &entry); uerr != nil {
			t.Fatalf("unmarshal: %v", uerr)
		}
		entries = append(entries, entry)
	}
	return entries
}
