package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// requireSymlink creates a symlink or skips on hosts without symlink support.
func requireSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}
}

func TestReloadRejectsSymlinkedPolicyFile(t *testing.T) {
	dir := t.TempDir()
	manager, _ := newManager(t, dir, newFakeClock(baseTime), nil)

	policyDir := filepath.Join(dir, "policy")
	path := filepath.Join(policyDir, currentFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy.json: %v", err)
	}
	outside := filepath.Join(dir, "outside-policy.json")
	if err := os.WriteFile(outside, raw, 0o600); err != nil {
		t.Fatalf("write outside policy: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove policy.json: %v", err)
	}
	requireSymlink(t, outside, path)

	if _, err := manager.Reload(); err == nil {
		t.Fatal("Reload followed a symlinked policy.json")
	}
	if got := manager.Count(); got != 1 {
		t.Errorf("version count after rejected reload = %d, want 1", got)
	}
}

func TestUpdateRejectsSymlinkedVersionHistory(t *testing.T) {
	dir := t.TempDir()
	manager, _ := newManager(t, dir, newFakeClock(baseTime), nil)

	policyDir := filepath.Join(dir, "policy")
	versionsPath := filepath.Join(policyDir, versionsFileName)
	outside := filepath.Join(dir, "outside-versions.jsonl")
	if err := os.WriteFile(outside, []byte(""), 0o600); err != nil {
		t.Fatalf("write outside versions: %v", err)
	}
	if err := os.Remove(versionsPath); err != nil {
		t.Fatalf("remove version history: %v", err)
	}
	requireSymlink(t, outside, versionsPath)

	current := manager.Current()
	if _, err := manager.Update(current, "admin", "admin", "should fail"); err == nil {
		t.Fatal("Update appended through a symlinked version history")
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("read outside versions: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("symlink target was written through: %d bytes", len(data))
	}
}
