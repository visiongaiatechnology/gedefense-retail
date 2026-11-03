package policy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ensurePrivateDir creates dir (0700) and rejects symlinked targets.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("policy: create directory %q: %w", filepath.Base(dir), err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("policy: stat directory %q: %w", filepath.Base(dir), err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("policy: %q is a symlink, refusing to use it as a data directory", filepath.Base(dir))
	}
	if !info.IsDir() {
		return fmt.Errorf("policy: %q is not a directory", filepath.Base(dir))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("policy: restrict permissions of %q: %w", filepath.Base(dir), err)
	}
	return nil
}

// writeFileAtomic replaces path with data through a 0600 temporary file and a
// rename, so a crash can never leave a half-written policy behind.
func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-policy-*")
	if err != nil {
		return fmt.Errorf("policy: create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if rerr := os.Remove(tmpName); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("policy: remove temporary file: %w", rerr))
		}
	}()

	if cerr := tmp.Chmod(0o600); cerr != nil {
		closeErr := tmp.Close()
		return fmt.Errorf("policy: set permissions of temporary file: %w", errors.Join(cerr, closeErr))
	}
	if _, werr := tmp.Write(data); werr != nil {
		closeErr := tmp.Close()
		return fmt.Errorf("policy: write temporary file: %w", errors.Join(werr, closeErr))
	}
	if serr := tmp.Sync(); serr != nil {
		closeErr := tmp.Close()
		return fmt.Errorf("policy: sync temporary file: %w", errors.Join(serr, closeErr))
	}
	if cerr := tmp.Close(); cerr != nil {
		return fmt.Errorf("policy: close temporary file: %w", cerr)
	}
	if rerr := os.Rename(tmpName, path); rerr != nil {
		return fmt.Errorf("policy: replace %q: %w", filepath.Base(path), rerr)
	}
	return nil
}

// maxPolicyFileBytes bounds an in-memory read of a policy document.
const maxPolicyFileBytes = 4 << 20

// verifyOpenedFile rejects a path that no longer names the regular file behind an
// opened descriptor (symlink swap / replace between open and check). The descriptor
// is used afterwards, so a later swap cannot redirect the operation.
func verifyOpenedFile(file *os.File, path string) error {
	openInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("policy: stat opened %q: %w", filepath.Base(path), err)
	}
	if !openInfo.Mode().IsRegular() {
		return fmt.Errorf("policy: %q is not a regular file", filepath.Base(path))
	}
	pathInfo, lerr := os.Lstat(path)
	if lerr != nil {
		if errors.Is(lerr, os.ErrNotExist) {
			return nil // unlinked while open: the descriptor still identifies our file
		}
		return fmt.Errorf("policy: stat %q: %w", filepath.Base(path), lerr)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("policy: %q is a symlink", filepath.Base(path))
	}
	if !os.SameFile(openInfo, pathInfo) {
		return fmt.Errorf("policy: %q changed while it was being opened", filepath.Base(path))
	}
	return nil
}

// readFile reads a regular, non-symlinked file through a verified descriptor.
func readFile(path string) (data []byte, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("policy: close %q: %w", filepath.Base(path), cerr)
		}
	}()
	if verr := verifyOpenedFile(file, path); verr != nil {
		return nil, verr
	}
	limited := io.LimitReader(file, maxPolicyFileBytes+1)
	data, rerr := io.ReadAll(limited)
	if rerr != nil {
		return nil, fmt.Errorf("policy: read %q: %w", filepath.Base(path), rerr)
	}
	if len(data) > maxPolicyFileBytes {
		return nil, fmt.Errorf("policy: %q exceeds %d bytes", filepath.Base(path), maxPolicyFileBytes)
	}
	return data, nil
}

// appendLine appends one already-serialised JSONL record to path.
func appendLine(path string, line []byte) (err error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("policy: open %q for append: %w", filepath.Base(path), err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("policy: close %q: %w", filepath.Base(path), cerr)
		}
	}()
	if verr := verifyOpenedFile(file, path); verr != nil {
		return verr
	}
	if _, werr := file.Write(line); werr != nil {
		return fmt.Errorf("policy: append %q: %w", filepath.Base(path), werr)
	}
	if serr := file.Sync(); serr != nil {
		return fmt.Errorf("policy: sync %q: %w", filepath.Base(path), serr)
	}
	return nil
}
