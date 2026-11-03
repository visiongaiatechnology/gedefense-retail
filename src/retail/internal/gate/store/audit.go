package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

const (
	zeroHash          = "0000000000000000000000000000000000000000000000000000000000000000"
	maxAuditFileBytes = 64 << 20
	defaultAuditLimit = 100
	maxAuditLimit     = 500
)

// auditChain is the gate's tamper-evident audit trail. It uses exactly the 0.1
// structure (domain.AuditEntry + NewAuditEntry/VerifyAuditChain): there is no
// second audit format.
type auditChain struct {
	mu       sync.Mutex
	dir      string
	clock    ports.Clock
	lastSeq  uint64
	lastHash string
	firstSeq uint64
	count    int
	closed   bool
}

// openAuditChain loads and verifies the complete chain. A broken chain aborts
// startup (fail-closed).
func openAuditChain(dir string, clock ports.Clock) (*auditChain, error) {
	chain := &auditChain{dir: dir, clock: clock, lastHash: zeroHash}
	entries, err := chain.readAll()
	if err != nil {
		return nil, err
	}
	if ok, badSeq := verifyAuditEntries(entries); !ok {
		return nil, fmt.Errorf("%w: audit chain broken at seq %d", ErrCorruptState, badSeq)
	}
	if len(entries) > 0 {
		chain.firstSeq = entries[0].Seq
		last := entries[len(entries)-1]
		chain.lastSeq = last.Seq
		chain.lastHash = last.Hash
		chain.count = len(entries)
	}
	return chain, nil
}

// Append chains and persists one audit entry. The store owns Seq, At and PrevHash.
func (c *auditChain) Append(ctx context.Context, entry domain.AuditEntry) (domain.AuditEntry, error) {
	if err := ctx.Err(); err != nil {
		return domain.AuditEntry{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return domain.AuditEntry{}, ErrClosed
	}
	entry.Seq = c.lastSeq + 1
	if entry.At.IsZero() {
		entry.At = c.clock.Now().UTC()
	}
	entry.PrevHash = c.lastHash
	hashed, err := domain.NewAuditEntry(entry)
	if err != nil {
		return domain.AuditEntry{}, fmt.Errorf("gate store: build audit entry: %w", err)
	}
	line, err := json.Marshal(hashed)
	if err != nil {
		return domain.AuditEntry{}, fmt.Errorf("gate store: marshal audit entry: %w", err)
	}
	path, err := c.currentPathLocked(hashed.At, int64(len(line))+1)
	if err != nil {
		return domain.AuditEntry{}, err
	}
	file, err := openAppendPrivate(path)
	if err != nil {
		return domain.AuditEntry{}, err
	}
	if _, werr := file.Write(append(line, '\n')); werr != nil {
		closeErr := file.Close()
		return domain.AuditEntry{}, fmt.Errorf("gate store: append audit entry: %w", errors.Join(werr, closeErr))
	}
	if serr := file.Sync(); serr != nil {
		closeErr := file.Close()
		return domain.AuditEntry{}, fmt.Errorf("gate store: sync audit entry: %w", errors.Join(serr, closeErr))
	}
	if cerr := file.Close(); cerr != nil {
		return domain.AuditEntry{}, fmt.Errorf("gate store: close audit file: %w", cerr)
	}
	if c.firstSeq == 0 {
		c.firstSeq = hashed.Seq
	}
	c.lastSeq = hashed.Seq
	c.lastHash = hashed.Hash
	c.count++
	return hashed, nil
}

// List returns the newest limit entries in ascending sequence order.
func (c *auditChain) List(ctx context.Context, limit int) ([]domain.AuditEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := c.readAll()
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = defaultAuditLimit
	}
	if limit > maxAuditLimit {
		limit = maxAuditLimit
	}
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	return entries, nil
}

// Verify re-reads and verifies the chain.
func (c *auditChain) Verify(ctx context.Context) (bool, uint64, error) {
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	entries, err := c.readAll()
	if err != nil {
		return false, 0, err
	}
	ok, badSeq := verifyAuditEntries(entries)
	return ok, badSeq, nil
}

// Count returns the number of persisted audit entries.
func (c *auditChain) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// FirstSeq returns the oldest persisted sequence number.
func (c *auditChain) FirstSeq() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.firstSeq
}

// Close marks the chain closed; appended entries are already durable.
func (c *auditChain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

// currentPathLocked chooses the append target for the day, rotating by size.
func (c *auditChain) currentPathLocked(at time.Time, addBytes int64) (string, error) {
	day := utcDayOf(at)
	files, err := listAuditFiles(c.dir)
	if err != nil {
		return "", err
	}
	idx := 1
	if len(files) > 0 {
		lastName := filepath.Base(files[len(files)-1])
		if lastDay, lastIdx, ok := parseAuditDay(lastName); ok && lastDay.Equal(day) {
			info, serr := os.Stat(files[len(files)-1])
			if serr != nil {
				return "", fmt.Errorf("gate store: stat audit file: %w", serr)
			}
			idx = lastIdx
			if info.Size() > 0 && info.Size()+addBytes > maxAuditFileBytes {
				idx++
			}
		}
	}
	return filepath.Join(c.dir, auditFileName(day, idx)), nil
}

// readAll streams every audit record in file order.
func (c *auditChain) readAll() ([]domain.AuditEntry, error) {
	files, err := listAuditFiles(c.dir)
	if err != nil {
		return nil, err
	}
	entries := make([]domain.AuditEntry, 0, 64)
	for _, file := range files {
		if ferr := forEachAuditLine(file, func(line []byte) error {
			var entry domain.AuditEntry
			if derr := decodeStrict(line, &entry); derr != nil {
				return fmt.Errorf("%w: undecodable audit record in %q", ErrCorruptState, filepath.Base(file))
			}
			entries = append(entries, entry)
			return nil
		}); ferr != nil {
			return nil, ferr
		}
	}
	return entries, nil
}

// verifyAuditEntries checks the hash chain and a gap-free sequence.
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

// utcDayOf truncates a timestamp to its UTC calendar day.
func utcDayOf(at time.Time) time.Time {
	year, month, day := at.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// openAppendPrivate opens a state file for appending after verifying it is not a
// symlink and is the regular file currently named by the path.
func openAppendPrivate(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("gate store: open %q for append: %w", filepath.Base(path), err)
	}
	if verr := verifyOpenedFile(file, path); verr != nil {
		closeErr := file.Close()
		return nil, errors.Join(verr, closeErr)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		closeErr := file.Close()
		return nil, fmt.Errorf("gate store: restrict %q: %w", filepath.Base(path), errors.Join(err, closeErr))
	}
	return file, nil
}
