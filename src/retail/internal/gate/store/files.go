// Package store persists the Access Gate state: write plans, one-time tokens,
// write sessions, denial evidence and the hash-chained audit log.
//
// Every document is written atomically (temporary file + rename, 0600) and read
// through a verified descriptor (open, Lstat, SameFile) so a symlink swap cannot
// redirect the gate state. The audit chain is verified at startup; a broken chain
// prevents the gate from starting (fail-closed).
package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxPlanDocBytes    = 1 << 20
	maxSessionDocBytes = 256 << 10
	maxTokenDocBytes   = 64 << 10
	maxDenyDocBytes    = 64 << 10
	maxStateDocBytes   = 1 << 20
	chunkBytes         = 64 << 10
	auditChunkBytes    = 64 << 10
	maxAuditLineBytes  = 4 << 20
)

// wallClock is the default ports.Clock implementation.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

// ensureDir creates a private directory (0700) and rejects a symlinked target.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("gate store: create %q: %w", filepath.Base(dir), err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("gate store: stat %q: %w", filepath.Base(dir), err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("gate store: %q is a symlink", filepath.Base(dir))
	}
	if !info.IsDir() {
		return fmt.Errorf("gate store: %q is not a directory", filepath.Base(dir))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("gate store: restrict %q: %w", filepath.Base(dir), err)
	}
	return nil
}

// safeName rejects anything that could escape the store directory.
func safeName(name string) error {
	if name == "" || len(name) > 160 {
		return fmt.Errorf("gate store: invalid document name length")
	}
	if strings.ContainsAny(name, `/\:`) || name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return fmt.Errorf("gate store: invalid document name %q", name)
	}
	return nil
}

// verifyOpenedFile rejects a path that no longer names the opened regular file.
func verifyOpenedFile(file *os.File, path string) error {
	openInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("gate store: stat opened %q: %w", filepath.Base(path), err)
	}
	if !openInfo.Mode().IsRegular() {
		return fmt.Errorf("gate store: %q is not a regular file", filepath.Base(path))
	}
	pathInfo, lerr := os.Lstat(path)
	if lerr != nil {
		if errors.Is(lerr, fs.ErrNotExist) {
			return nil // unlinked while open: the descriptor is still our file
		}
		return fmt.Errorf("gate store: stat %q: %w", filepath.Base(path), lerr)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("gate store: %q is a symlink", filepath.Base(path))
	}
	if !os.SameFile(openInfo, pathInfo) {
		return fmt.Errorf("gate store: %q changed while it was being opened", filepath.Base(path))
	}
	return nil
}

// writeFileAtomic replaces path with data through a 0600 temporary file.
func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-gate-*")
	if err != nil {
		return fmt.Errorf("gate store: create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if rerr := os.Remove(tmpName); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("gate store: remove temporary file: %w", rerr))
		}
	}()
	if cerr := tmp.Chmod(0o600); cerr != nil {
		closeErr := tmp.Close()
		return fmt.Errorf("gate store: chmod temporary file: %w", errors.Join(cerr, closeErr))
	}
	if _, werr := tmp.Write(data); werr != nil {
		closeErr := tmp.Close()
		return fmt.Errorf("gate store: write temporary file: %w", errors.Join(werr, closeErr))
	}
	if serr := tmp.Sync(); serr != nil {
		closeErr := tmp.Close()
		return fmt.Errorf("gate store: sync temporary file: %w", errors.Join(serr, closeErr))
	}
	if cerr := tmp.Close(); cerr != nil {
		return fmt.Errorf("gate store: close temporary file: %w", cerr)
	}
	if rerr := os.Rename(tmpName, path); rerr != nil {
		return fmt.Errorf("gate store: replace %q: %w", filepath.Base(path), rerr)
	}
	return nil
}

// readDocument reads a bounded JSON document through a verified descriptor.
func readDocument(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			// A read-only close error cannot modify data; it is reported by the
			// caller only through the (already returned) content.
			_ = cerr
		}
	}()
	if verr := verifyOpenedFile(file, path); verr != nil {
		return nil, verr
	}
	raw, rerr := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if rerr != nil {
		return nil, fmt.Errorf("gate store: read %q: %w", filepath.Base(path), rerr)
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("gate store: %q exceeds %d bytes", filepath.Base(path), maxBytes)
	}
	return raw, nil
}

// saveDocument validates the name, marshals the document and writes it atomically.
func saveDocument(dir, name string, document any) error {
	if err := safeName(name); err != nil {
		return err
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("gate store: marshal %q: %w", name, err)
	}
	if err := writeFileAtomic(filepath.Join(dir, name), append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

// listDocumentFiles returns the sorted *.json document paths of a directory,
// ignoring temporary files.
func listDocumentFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("gate store: read %q: %w", filepath.Base(dir), err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	paths := make([]string, len(names))
	for i, name := range names {
		paths[i] = filepath.Join(dir, name)
	}
	return paths, nil
}

// decodeStrict decodes exactly one JSON object with unknown fields rejected.
func decodeStrict(raw []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("gate store: decode: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("gate store: trailing content after document")
	}
	return nil
}

// readDocFile reads and strictly decodes one document file.
func readDocFile(path string, maxBytes int64, dst any) (bool, error) {
	raw, err := readDocument(path, maxBytes)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if derr := decodeStrict(raw, dst); derr != nil {
		return false, fmt.Errorf("%w: %q: %v", ErrCorruptState, filepath.Base(path), derr)
	}
	return true, nil
}

// removeDocument deletes one document file.
func removeDocument(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("gate store: remove %q: %w", filepath.Base(path), err)
	}
	return nil
}

// parseDay derives the UTC day of an audit file name "audit-YYYY-MM-DD[-n].jsonl".
func parseAuditDay(name string) (time.Time, int, bool) {
	if !strings.HasPrefix(name, "audit-") || !strings.HasSuffix(name, ".jsonl") {
		return time.Time{}, 0, false
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(name, "audit-"), ".jsonl")
	if len(rest) < 10 {
		return time.Time{}, 0, false
	}
	day, err := time.Parse("2006-01-02", rest[:10])
	if err != nil {
		return time.Time{}, 0, false
	}
	idx := 1
	if len(rest) > 10 {
		if rest[10] != '-' {
			return time.Time{}, 0, false
		}
		n, nerr := strconv.Atoi(rest[11:])
		if nerr != nil || n < 2 {
			return time.Time{}, 0, false
		}
		idx = n
	}
	return day, idx, true
}

// listAuditFiles returns audit files ordered chronologically.
func listAuditFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("gate store: read audit dir: %w", err)
	}
	type auditFile struct {
		name string
		day  time.Time
		idx  int
	}
	files := make([]auditFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		day, idx, ok := parseAuditDay(entry.Name())
		if !ok {
			continue
		}
		files = append(files, auditFile{name: entry.Name(), day: day, idx: idx})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].day.Equal(files[j].day) {
			return files[i].idx < files[j].idx
		}
		return files[i].day.Before(files[j].day)
	})
	out := make([]string, len(files))
	for i, file := range files {
		out[i] = filepath.Join(dir, file.name)
	}
	return out, nil
}

// auditFileName builds the rotated audit file name for a UTC day.
func auditFileName(day time.Time, idx int) string {
	base := "audit-" + day.UTC().Format("2006-01-02")
	if idx <= 1 {
		return base + ".jsonl"
	}
	return base + "-" + strconv.Itoa(idx) + ".jsonl"
}

// forEachAuditLine calls fn for every record of an audit file (forward order).
func forEachAuditLine(path string, fn func(line []byte) error) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("gate store: open %q: %w", filepath.Base(path), err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("gate store: close %q: %w", filepath.Base(path), cerr)
		}
	}()
	if verr := verifyOpenedFile(file, path); verr != nil {
		return verr
	}
	reader := bufio.NewReaderSize(file, auditChunkBytes)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimSuffix(line, []byte{'\n'})
			line = bytes.TrimSuffix(line, []byte{'\r'})
			if len(line) > maxAuditLineBytes {
				return fmt.Errorf("gate store: %w: audit record in %q too large", ErrCorruptState, filepath.Base(path))
			}
			if len(line) > 0 {
				if ferr := fn(line); ferr != nil {
					return ferr
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return fmt.Errorf("gate store: read %q: %w", filepath.Base(path), readErr)
		}
	}
}
