package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// errFileMissing marks a state file that does not exist. It is mapped onto the
// package-specific "missing" sentinel by the loaders.
var errFileMissing = errors.New("gate config: file does not exist")

// readStrictFile reads a bounded regular file through a verified descriptor:
// the path must still name the regular file that was opened (symlink TOCTOU).
func readStrictFile(path string, maxBytes int64) (data []byte, err error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errFileMissing
		}
		return nil, err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close %q: %w", filepath.Base(path), cerr)
		}
	}()
	if verr := verifyOpenedFile(file, path); verr != nil {
		return nil, verr
	}
	data, rerr := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if rerr != nil {
		return nil, fmt.Errorf("read %q: %w", filepath.Base(path), rerr)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%q exceeds %d bytes", filepath.Base(path), maxBytes)
	}
	return data, nil
}

// verifyOpenedFile rejects a path that no longer names the opened regular file.
func verifyOpenedFile(file *os.File, path string) error {
	openInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat opened %q: %w", filepath.Base(path), err)
	}
	if !openInfo.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", filepath.Base(path))
	}
	pathInfo, lerr := os.Lstat(path)
	if lerr != nil {
		if errors.Is(lerr, fs.ErrNotExist) {
			return nil // unlinked while open: the descriptor is still our file
		}
		return fmt.Errorf("stat %q: %w", filepath.Base(path), lerr)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%q is a symlink", filepath.Base(path))
	}
	if !os.SameFile(openInfo, pathInfo) {
		return fmt.Errorf("%q changed while it was being opened", filepath.Base(path))
	}
	return nil
}
