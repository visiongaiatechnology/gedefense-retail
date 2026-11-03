package store

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// rotatingFile is the shared JSONL writer used by the event log and the audit
// log: append-only, 0600, rotated by UTC day and by size, flushed periodically.
// It is not safe for concurrent use; the owning store serialises access.
type rotatingFile struct {
	dir      string
	prefix   string
	maxBytes int64
	clock    ports.Clock

	file    *os.File
	writer  *bufio.Writer
	curPath string
	curDay  time.Time
	curIdx  int
	curSize int64
	pending int
	// onRotate is invoked after a rotation closed the file, with the path of the
	// just-closed file, so the owner can apply retention/size pruning.
	onRotate func(now time.Time, closedPath string) error
}

func newRotatingFile(dir, prefix string, maxBytes int64, clock ports.Clock) *rotatingFile {
	return &rotatingFile{dir: dir, prefix: prefix, maxBytes: maxBytes, clock: clock}
}

// ensureWritable makes sure the current file can accept one more record.
func (r *rotatingFile) ensureWritable(addBytes int64) error {
	now := r.clock.Now()
	switch {
	case r.file == nil:
		return r.openDay(now, addBytes)
	case !utcDay(now).Equal(r.curDay):
		if err := r.rotate(now); err != nil {
			return err
		}
		return r.openDay(now, addBytes)
	case r.curSize > 0 && r.curSize+addBytes > r.maxBytes:
		if err := r.rotate(now); err != nil {
			return err
		}
		return r.openDay(now, addBytes)
	}
	return nil
}

// openDay opens the newest existing file of day or creates the next rotation.
func (r *rotatingFile) openDay(day time.Time, addBytes int64) error {
	day = utcDay(day)
	files, err := listDayFiles(r.dir, r.prefix)
	if err != nil {
		return err
	}
	idx := 1
	var size int64
	if len(files) > 0 {
		last := files[len(files)-1]
		if last.day.Equal(day) {
			info, serr := os.Stat(last.path)
			if serr != nil {
				return fmt.Errorf("store: stat %q: %w", last.name, serr)
			}
			size = info.Size()
			idx = last.idx
			if size > 0 && size+addBytes > r.maxBytes {
				idx++
				size = 0
			}
		}
	}
	path := filepath.Join(r.dir, dayFileName(r.prefix, day, idx))
	file, err := openPrivateAppend(path)
	if err != nil {
		return err
	}
	r.file = file
	r.writer = bufio.NewWriterSize(file, 64<<10)
	r.curPath = path
	r.curDay = day
	r.curIdx = idx
	r.curSize = size
	return nil
}

// rotate closes the current file and prunes expired and oversized files.
func (r *rotatingFile) rotate(now time.Time) error {
	if err := r.flush(); err != nil {
		return err
	}
	closedPath := r.curPath
	if r.file != nil {
		if err := r.file.Close(); err != nil {
			return fmt.Errorf("store: close rotated file %q: %w", filepath.Base(r.curPath), err)
		}
		r.file = nil
		r.writer = nil
	}
	if r.onRotate != nil {
		return r.onRotate(now, closedPath)
	}
	return nil
}

// write appends one already-serialised record (including the trailing newline).
func (r *rotatingFile) write(line []byte) error {
	if err := r.ensureWritable(int64(len(line))); err != nil {
		return err
	}
	if _, err := r.writer.Write(line); err != nil {
		return fmt.Errorf("store: write %q: %w", filepath.Base(r.curPath), err)
	}
	r.curSize += int64(len(line))
	r.pending++
	if r.pending >= flushEveryWrites {
		return r.flush()
	}
	return nil
}

// flush flushes the buffer and fsyncs the file.
func (r *rotatingFile) flush() error {
	if r.writer != nil {
		if err := r.writer.Flush(); err != nil {
			return fmt.Errorf("store: flush %q: %w", filepath.Base(r.curPath), err)
		}
	}
	if r.file != nil {
		if err := r.file.Sync(); err != nil {
			return fmt.Errorf("store: sync %q: %w", filepath.Base(r.curPath), err)
		}
	}
	r.pending = 0
	return nil
}

// close flushes and closes the current file.
func (r *rotatingFile) close() error {
	if err := r.flush(); err != nil {
		return err
	}
	if r.file == nil {
		return nil
	}
	if err := r.file.Close(); err != nil {
		return fmt.Errorf("store: close %q: %w", filepath.Base(r.curPath), err)
	}
	r.file = nil
	r.writer = nil
	return nil
}

// path returns the path of the currently open file ("" when none is open).
func (r *rotatingFile) path() string { return r.curPath }
