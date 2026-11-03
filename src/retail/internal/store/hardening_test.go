package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// requireSymlink creates a symlink or skips the test on platforms where that
// needs privileges (plain Windows without developer mode).
func requireSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}
}

func TestVerifyOpenedFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	requireSymlink(t, target, link)

	file, err := os.Open(link) // follows the link: exactly the attacker scenario
	if err != nil {
		t.Fatalf("open link: %v", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			t.Errorf("close link: %v", cerr)
		}
	}()
	if err := verifyOpenedFile(file, link); err == nil {
		t.Fatal("verifyOpenedFile accepted a symlinked path")
	}

	regular := filepath.Join(dir, "regular.json")
	if err := os.WriteFile(regular, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write regular: %v", err)
	}
	regularFile, err := os.Open(regular)
	if err != nil {
		t.Fatalf("open regular: %v", err)
	}
	defer func() {
		if cerr := regularFile.Close(); cerr != nil {
			t.Errorf("close regular: %v", cerr)
		}
	}()
	if err := verifyOpenedFile(regularFile, regular); err != nil {
		t.Fatalf("verifyOpenedFile rejected a regular file: %v", err)
	}
}

func TestReadPrivateFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside.json")
	if err := os.WriteFile(target, []byte(`{"schema":1,"alerts":[]}`), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "state.json")
	requireSymlink(t, target, link)
	if _, err := readPrivateFile(link); err == nil {
		t.Fatal("readPrivateFile followed a symlink")
	}
}

func TestEventLogRejectsSymlinkedDayFile(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	eventsDir := filepath.Join(dir, "events")
	if err := os.MkdirAll(eventsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	outside := filepath.Join(dir, "outside.jsonl")
	if err := os.WriteFile(outside, []byte(""), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	dayPath := filepath.Join(eventsDir, dayFileName(eventFilePrefix, baseTime, 1))
	requireSymlink(t, outside, dayPath)

	log, err := OpenEventLog(Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	defer func() {
		if cerr := log.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	}()
	if err := log.Append(context.Background(), testEvent("evt-1", baseTime)); err == nil {
		t.Fatal("Append accepted a symlinked day file")
	}
}

func TestSpoolRejectsSymlinkedEntry(t *testing.T) {
	dir := t.TempDir()
	spoolDir := filepath.Join(dir, "spool")
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	outside := filepath.Join(dir, "outside.json")
	if err := os.WriteFile(outside, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	link := filepath.Join(spoolDir, "00000000000000000001.json")
	requireSymlink(t, outside, link)

	if _, err := OpenSpool(Options{Dir: dir, Clock: newFakeClock(baseTime)}); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("OpenSpool on symlinked entry = %v, want ErrCorruptState", err)
	}
}

func TestOpenPrivateAppendRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.jsonl")
	if err := os.WriteFile(target, []byte(""), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.jsonl")
	requireSymlink(t, target, link)
	if _, err := openPrivateAppend(link); err == nil {
		t.Fatal("openPrivateAppend followed a symlink")
	}
	if data, err := os.ReadFile(target); err != nil || len(data) != 0 {
		t.Errorf("target was modified through the symlink: %q, %v", data, err)
	}
}
