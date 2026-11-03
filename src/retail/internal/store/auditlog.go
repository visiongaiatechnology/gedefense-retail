package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

const auditFilePrefix = "audit"

// AuditLog is the append-only, hash-chained audit trail. Every entry is linked
// to its predecessor (domain.VerifyAuditChain) and the sequence is gap-free.
//
// The audit log is deliberately NOT pruned by the retention window: deleting a
// prefix would break the chain. Operator retention for audit data is an
// archival process (move whole files to WORM storage), not a delete.
type AuditLog struct {
	dir   string
	clock ports.Clock

	mu       sync.Mutex
	file     *rotatingFile
	lastSeq  uint64
	lastHash string
	firstSeq uint64
	count    int
	closed   bool
}

// OpenAuditLog opens the audit log below opts.Dir and verifies the whole chain
// before the gateway is allowed to append to it.
func OpenAuditLog(opts Options) (*AuditLog, error) {
	norm, err := normalizeOptions(opts, defaultEventMaxMB)
	if err != nil {
		return nil, err
	}
	dir := joinDataPath(norm.Dir, "audit")
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	log := &AuditLog{dir: dir, clock: norm.Clock}
	entries, err := readAuditEntries(dir)
	if err != nil {
		return nil, err
	}
	if ok, badSeq := verifyAuditEntries(entries); !ok {
		return nil, fmt.Errorf("store: %w: first failing seq %d", ErrChainBroken, badSeq)
	}
	if len(entries) > 0 {
		log.count = len(entries)
		log.firstSeq = entries[0].Seq
		last := entries[len(entries)-1]
		log.lastSeq = last.Seq
		log.lastHash = last.Hash
	}
	log.file = newRotatingFile(dir, auditFilePrefix, norm.MaxMB<<20, norm.Clock)
	return log, nil
}

// Append chains and persists one audit entry. The store owns Seq, At and
// PrevHash; any caller supplied values are overwritten.
func (l *AuditLog) Append(ctx context.Context, entry domain.AuditEntry) (domain.AuditEntry, error) {
	if err := ctx.Err(); err != nil {
		return domain.AuditEntry{}, fmt.Errorf("store: append audit entry: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return domain.AuditEntry{}, ErrClosed
	}

	entry.Seq = l.lastSeq + 1
	if entry.At.IsZero() {
		entry.At = l.clock.Now()
	}
	entry.PrevHash = l.lastHash
	if entry.PrevHash == "" {
		entry.PrevHash = zeroHash
	}
	hashed, err := domain.NewAuditEntry(entry)
	if err != nil {
		return domain.AuditEntry{}, fmt.Errorf("store: build audit entry: %w", err)
	}
	line, err := json.Marshal(hashed)
	if err != nil {
		return domain.AuditEntry{}, fmt.Errorf("store: marshal audit entry: %w", err)
	}
	line = append(line, '\n')
	if err := l.file.write(line); err != nil {
		return domain.AuditEntry{}, fmt.Errorf("store: append audit entry: %w", err)
	}
	if l.firstSeq == 0 {
		l.firstSeq = hashed.Seq
	}
	l.lastSeq = hashed.Seq
	l.lastHash = hashed.Hash
	l.count++
	return hashed, nil
}

// List returns the newest limit entries in ascending sequence order.
func (l *AuditLog) List(ctx context.Context, limit int) ([]domain.AuditEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("store: list audit entries: %w", err)
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, ErrClosed
	}
	// A read must include entries that are still in the write buffer.
	if err := l.flushLocked(); err != nil {
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()
	entries, err := readAuditEntries(l.dir)
	if err != nil {
		return nil, err
	}
	n := clampLimit(limit)
	if len(entries) > n {
		entries = entries[len(entries)-n:]
	}
	return entries, nil
}

// Verify re-reads the chain from disk and reports the first failing sequence.
func (l *AuditLog) Verify(ctx context.Context) (bool, uint64, error) {
	if err := ctx.Err(); err != nil {
		return false, 0, fmt.Errorf("store: verify audit chain: %w", err)
	}
	l.mu.Lock()
	if !l.closed {
		if err := l.flushLocked(); err != nil {
			l.mu.Unlock()
			return false, 0, err
		}
	}
	l.mu.Unlock()
	entries, err := readAuditEntries(l.dir)
	if err != nil {
		return false, 0, err
	}
	ok, badSeq := verifyAuditEntries(entries)
	return ok, badSeq, nil
}

// flushLocked flushes the write buffer so that readers see the full log.
func (l *AuditLog) flushLocked() error {
	if l.file == nil {
		return nil
	}
	return l.file.flush()
}

// Flush forces buffered audit entries to disk (fsync). It is called on a clean
// shutdown (FIND-010) so that a stop signal cannot lose the last entries.
func (l *AuditLog) Flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("store: flush audit log: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	return l.flushLocked()
}

// FirstSeq returns the sequence number of the oldest persisted entry (0 when
// the log is empty).
func (l *AuditLog) FirstSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.firstSeq
}

// Count returns the number of persisted entries.
func (l *AuditLog) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

// Close flushes and closes the current file. It is idempotent.
func (l *AuditLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.file.close()
}

// readAuditEntries streams every audit record from disk in file order.
func readAuditEntries(dir string) ([]domain.AuditEntry, error) {
	files, err := listDayFiles(dir, auditFilePrefix)
	if err != nil {
		return nil, err
	}
	entries := make([]domain.AuditEntry, 0, 64)
	for _, f := range files {
		if err := forEachLine(f.path, func(line []byte) error {
			var entry domain.AuditEntry
			if uerr := json.Unmarshal(line, &entry); uerr != nil {
				return fmt.Errorf("store: %w: undecodable audit record in %q", ErrCorruptState, f.name)
			}
			entries = append(entries, entry)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// verifyAuditEntries checks the hash chain and gap-free sequence.
func verifyAuditEntries(entries []domain.AuditEntry) (bool, uint64) {
	if ok, badSeq := domain.VerifyAuditChain(entries); !ok {
		return false, badSeq
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].Seq != entries[i-1].Seq+1 {
			return false, entries[i].Seq
		}
	}
	return true, 0
}
