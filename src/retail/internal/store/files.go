package store

import (
	"bufio"
	"bytes"
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

// chunkBytes is the read granularity of the forward and backward line scanners.
const chunkBytes = 64 << 10

const dayLayout = "2006-01-02"

// ensurePrivateDir creates dir (0700) if needed and rejects a symlinked or
// non-directory target instead of following it.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: create directory %q: %w", filepath.Base(dir), err)
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("store: stat directory %q: %w", filepath.Base(dir), err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("store: %q is a symlink, refusing to use it as a data directory", filepath.Base(dir))
	}
	if !st.IsDir() {
		return fmt.Errorf("store: %q is not a directory", filepath.Base(dir))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("store: restrict permissions of %q: %w", filepath.Base(dir), err)
	}
	return nil
}

// writeFileAtomic writes data to path through a temporary file in the same
// directory followed by a rename. Existing content is replaced atomically.
func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("store: create temporary file in %q: %w", filepath.Base(dir), err)
	}
	tmpName := tmp.Name()
	defer func() {
		if rerr := os.Remove(tmpName); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("store: remove temporary file: %w", rerr))
		}
	}()

	if cerr := tmp.Chmod(0o600); cerr != nil {
		closeErr := tmp.Close()
		return fmt.Errorf("store: set permissions of temporary file: %w", errors.Join(cerr, closeErr))
	}
	if _, werr := tmp.Write(data); werr != nil {
		closeErr := tmp.Close()
		return fmt.Errorf("store: write temporary file: %w", errors.Join(werr, closeErr))
	}
	if serr := tmp.Sync(); serr != nil {
		closeErr := tmp.Close()
		return fmt.Errorf("store: sync temporary file: %w", errors.Join(serr, closeErr))
	}
	if cerr := tmp.Close(); cerr != nil {
		return fmt.Errorf("store: close temporary file: %w", cerr)
	}
	if rerr := os.Rename(tmpName, path); rerr != nil {
		return fmt.Errorf("store: replace %q: %w", filepath.Base(path), rerr)
	}
	return nil
}

// maxStateFileBytes bounds an in-memory read of a persisted state document.
const maxStateFileBytes = 64 << 20

// verifyOpenedFile closes the TOCTOU window between path resolution and use: an
// opened descriptor is only trusted when the path still names exactly that regular
// file. A symlink swap (or a replace between open and check) is rejected. The
// descriptor itself is always used afterwards, so a later swap cannot redirect the
// operation.
func verifyOpenedFile(file *os.File, path string) error {
	openInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("store: stat opened %q: %w", filepath.Base(path), err)
	}
	if !openInfo.Mode().IsRegular() {
		return fmt.Errorf("store: %q is not a regular file", filepath.Base(path))
	}
	pathInfo, lerr := os.Lstat(path)
	if lerr != nil {
		if errors.Is(lerr, fs.ErrNotExist) {
			// The name was unlinked while we hold the descriptor: the open handle
			// still identifies the file we opened and validated.
			return nil
		}
		return fmt.Errorf("store: stat %q: %w", filepath.Base(path), lerr)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("store: %q is a symlink, refusing to use it", filepath.Base(path))
	}
	if !os.SameFile(openInfo, pathInfo) {
		return fmt.Errorf("store: %w: %q changed while it was being opened", ErrCorruptState, filepath.Base(path))
	}
	return nil
}

// readPrivateFile opens a persisted state file and reads it after verifying the
// descriptor (see verifyOpenedFile). Size is bounded to protect against a hostile
// or truncated file.
func readPrivateFile(path string) (data []byte, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("store: open %q: %w", filepath.Base(path), err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("store: close %q: %w", filepath.Base(path), cerr)
		}
	}()
	if verr := verifyOpenedFile(file, path); verr != nil {
		return nil, verr
	}
	limited := io.LimitReader(file, maxStateFileBytes+1)
	data, rerr := io.ReadAll(limited)
	if rerr != nil {
		return nil, fmt.Errorf("store: read %q: %w", filepath.Base(path), rerr)
	}
	if len(data) > maxStateFileBytes {
		return nil, fmt.Errorf("store: %q exceeds %d bytes", filepath.Base(path), maxStateFileBytes)
	}
	return data, nil
}

// openPrivateAppend opens path for appending, rejecting symlinks and anything
// that is not a regular file. Missing files are created with 0600.
func openPrivateAppend(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: open %q for append: %w", filepath.Base(path), err)
	}
	if verr := verifyOpenedFile(file, path); verr != nil {
		closeErr := file.Close()
		return nil, errors.Join(verr, closeErr)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		closeErr := file.Close()
		return nil, fmt.Errorf("store: restrict permissions of %q: %w", filepath.Base(path), errors.Join(err, closeErr))
	}
	return file, nil
}

// forEachLine calls fn for every newline terminated record of path. The line
// slice is only valid during the call.
func forEachLine(path string, fn func(line []byte) error) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("store: open %q: %w", filepath.Base(path), err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("store: close %q: %w", filepath.Base(path), cerr)
		}
	}()

	if verr := verifyOpenedFile(file, path); verr != nil {
		return verr
	}
	reader := bufio.NewReaderSize(file, chunkBytes)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimSuffix(line, []byte{'\n'})
			line = bytes.TrimSuffix(line, []byte{'\r'})
			if len(line) > maxLineBytes {
				return fmt.Errorf("store: %w: record in %q exceeds %d bytes", ErrCorruptState, filepath.Base(path), maxLineBytes)
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
			return fmt.Errorf("store: read %q: %w", filepath.Base(path), readErr)
		}
	}
}

// forEachLineReverse calls fn for every record of path from the last to the
// first one. Returning stop=true ends the scan without an error. The line slice
// is only valid during the call.
func forEachLineReverse(path string, fn func(line []byte) (stop bool, err error)) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("store: open %q: %w", filepath.Base(path), err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("store: close %q: %w", filepath.Base(path), cerr)
		}
	}()
	if verr := verifyOpenedFile(file, path); verr != nil {
		return verr
	}
	st, err := file.Stat()
	if err != nil {
		return fmt.Errorf("store: stat %q: %w", filepath.Base(path), err)
	}

	buf := make([]byte, chunkBytes)
	var carry []byte
	pos := st.Size()
	for pos > 0 {
		n := int64(len(buf))
		if pos < n {
			n = pos
		}
		pos -= n
		chunk := buf[:n]
		if _, rerr := file.ReadAt(chunk, pos); rerr != nil && !errors.Is(rerr, io.EOF) {
			return fmt.Errorf("store: read %q: %w", filepath.Base(path), rerr)
		}
		combined := make([]byte, 0, int(n)+len(carry))
		combined = append(combined, chunk...)
		combined = append(combined, carry...)
		if len(combined) > maxLineBytes && bytes.IndexByte(combined, '\n') < 0 {
			return fmt.Errorf("store: %w: record in %q exceeds %d bytes", ErrCorruptState, filepath.Base(path), maxLineBytes)
		}

		var remainder, segment []byte
		if pos > 0 {
			i := bytes.IndexByte(combined, '\n')
			if i < 0 {
				carry = combined
				continue
			}
			remainder = combined[:i]
			segment = combined[i+1:]
		} else {
			segment = combined
		}

		for len(segment) > 0 {
			j := bytes.LastIndexByte(segment, '\n')
			var line []byte
			if j < 0 {
				line = segment
				segment = nil
			} else {
				line = segment[j+1:]
				segment = segment[:j]
			}
			line = bytes.TrimSuffix(line, []byte{'\r'})
			if len(line) > 0 {
				stop, ferr := fn(line)
				if ferr != nil {
					return ferr
				}
				if stop {
					return nil
				}
			}
		}
		carry = remainder
	}
	return nil
}

// countLines counts the records of a JSONL file without decoding it.
func countLines(path string) (n int64, err error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("store: open %q: %w", filepath.Base(path), err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("store: close %q: %w", filepath.Base(path), cerr)
		}
	}()
	buf := make([]byte, chunkBytes)
	var last byte
	for {
		read, rerr := file.Read(buf)
		for i := 0; i < read; i++ {
			if buf[i] == '\n' {
				n++
			}
		}
		if read > 0 {
			last = buf[read-1]
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				if last != 0 && last != '\n' {
					n++ // final record without a trailing newline
				}
				return n, nil
			}
			return n, fmt.Errorf("store: read %q: %w", filepath.Base(path), rerr)
		}
	}
}

// dayFile is one rotated JSONL file of a store.
type dayFile struct {
	name string
	path string
	day  time.Time
	idx  int
}

// listDayFiles returns every <prefix>-<date>[-<n>].jsonl file in dir ordered
// chronologically (oldest first).
func listDayFiles(dir, prefix string) ([]dayFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: read directory %q: %w", filepath.Base(dir), err)
	}
	files := make([]dayFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		day, idx, ok := parseDayFileName(prefix, entry.Name())
		if !ok {
			continue
		}
		files = append(files, dayFile{
			name: entry.Name(),
			path: filepath.Join(dir, entry.Name()),
			day:  day,
			idx:  idx,
		})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].day.Equal(files[j].day) {
			return files[i].idx < files[j].idx
		}
		return files[i].day.Before(files[j].day)
	})
	return files, nil
}

// utcDay truncates t to the UTC calendar day.
func utcDay(t time.Time) time.Time {
	year, month, day := t.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// dayFileName builds the rotated file name for prefix, day and rotation index.
func dayFileName(prefix string, day time.Time, idx int) string {
	base := prefix + "-" + utcDay(day).Format(dayLayout)
	if idx <= 1 {
		return base + ".jsonl"
	}
	return base + "-" + strconv.Itoa(idx) + ".jsonl"
}

// parseDayFileName parses "<prefix>-<YYYY-MM-DD>[-<n>].jsonl".
func parseDayFileName(prefix, name string) (day time.Time, idx int, ok bool) {
	if !strings.HasSuffix(name, ".jsonl") {
		return time.Time{}, 0, false
	}
	rest := strings.TrimSuffix(name, ".jsonl")
	if !strings.HasPrefix(rest, prefix+"-") {
		return time.Time{}, 0, false
	}
	rest = strings.TrimPrefix(rest, prefix+"-")
	if len(rest) < len(dayLayout) {
		return time.Time{}, 0, false
	}
	parsed, err := time.Parse(dayLayout, rest[:len(dayLayout)])
	if err != nil {
		return time.Time{}, 0, false
	}
	if len(rest) == len(dayLayout) {
		return parsed, 1, true
	}
	if rest[len(dayLayout)] != '-' || len(rest) == len(dayLayout)+1 {
		return time.Time{}, 0, false
	}
	n, err := strconv.Atoi(rest[len(dayLayout)+1:])
	if err != nil || n < 2 {
		return time.Time{}, 0, false
	}
	return parsed, n, true
}

// pruneByRetention removes day files older than the retention window. The file
// currently being written is never removed.
// prunedFile describes a file that a prune operation removed.
type prunedFile struct {
	dayFile
	lines int64
}

func pruneByRetention(dir, prefix string, now time.Time, days int, keepPath string) ([]prunedFile, error) {
	if days <= 0 {
		return nil, nil
	}
	cutoff := utcDay(now).AddDate(0, 0, -days)
	files, err := listDayFiles(dir, prefix)
	if err != nil {
		return nil, err
	}
	var removed []prunedFile
	for _, f := range files {
		if f.path == keepPath || !f.day.Before(cutoff) {
			continue
		}
		lines, _ := countLines(f.path) // metrics only; a read error must not block retention
		if rerr := os.Remove(f.path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			return removed, fmt.Errorf("store: remove expired %q: %w", f.name, rerr)
		}
		removed = append(removed, prunedFile{dayFile: f, lines: lines})
	}
	return removed, nil
}

// pruneBySize removes the oldest day files until the total size fits maxBytes.
func pruneBySize(dir, prefix string, maxBytes int64, keepPath string) ([]prunedFile, error) {
	if maxBytes <= 0 {
		return nil, nil
	}
	files, err := listDayFiles(dir, prefix)
	if err != nil {
		return nil, err
	}
	sizes := make([]int64, len(files))
	var total int64
	for i, f := range files {
		st, serr := os.Stat(f.path)
		if serr != nil {
			return nil, fmt.Errorf("store: stat %q: %w", f.name, serr)
		}
		sizes[i] = st.Size()
		total += st.Size()
	}
	var removed []prunedFile
	for i := range files {
		if total <= maxBytes {
			break
		}
		if files[i].path == keepPath {
			continue
		}
		lines, _ := countLines(files[i].path)
		if rerr := os.Remove(files[i].path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			return removed, fmt.Errorf("store: remove oversized %q: %w", files[i].name, rerr)
		}
		total -= sizes[i]
		removed = append(removed, prunedFile{dayFile: files[i], lines: lines})
	}
	return removed, nil
}
