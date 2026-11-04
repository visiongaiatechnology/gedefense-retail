package vendorcatalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// assertNoPathLeak fails when a warning contains the catalog directory, the
// temporary directory or a Windows drive/UNC fragment. The warnings are served
// to API viewers, so filesystem/environment details must never appear (F-A8-06).
func assertNoPathLeak(t *testing.T, warnings []string, forbidden ...string) {
	t.Helper()
	joined := strings.Join(warnings, "\n")
	for _, value := range append(forbidden, os.TempDir(), filepath.ToSlash(os.TempDir())) {
		if value != "" && strings.Contains(joined, value) {
			t.Fatalf("warning leaks path %q: %v", value, warnings)
		}
	}
	if strings.Contains(joined, `:\`) || strings.Contains(joined, ":/") || strings.HasPrefix(joined, "/") {
		t.Fatalf("warning looks like an absolute path: %v", warnings)
	}
}

func TestWarningsDoNotLeakCatalogPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cases := []struct {
		name    string
		path    string
		content string
	}{
		{"missing", filepath.Join(dir, "no-such-dir", VendorsFileName), ""},
		{"corrupt", filepath.Join(dir, "corrupt", VendorsFileName), "{ not json"},
		{"oversized", filepath.Join(dir, "oversized", VendorsFileName), string(make([]byte, MaxFileBytes+1))},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.content != "" {
				if err := os.MkdirAll(filepath.Dir(tc.path), 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(tc.path, []byte(tc.content), 0o600); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
			}
			catalog := Load(tc.path)
			if len(catalog.Warnings()) == 0 {
				t.Fatal("expected a warning")
			}
			assertNoPathLeak(t, catalog.Warnings(), dir, filepath.Dir(tc.path))
		})
	}
}

func TestPartialCatalogWarningsDoNotLeakPath(t *testing.T) {
	t.Parallel()
	dir := writeFixture(t, "", "missing", "missing")
	catalog := Load(dir)
	if len(catalog.Warnings()) == 0 {
		t.Fatal("expected warnings for the missing sibling documents")
	}
	assertNoPathLeak(t, catalog.Warnings(), dir)
}

func TestSymlinkCatalogFileRejected(t *testing.T) {
	t.Parallel()
	realDir := t.TempDir()
	realPath := filepath.Join(realDir, "real-vendors.json")
	if err := os.WriteFile(realPath, []byte(fixtureVendors), 0o600); err != nil {
		t.Fatalf("write real catalog: %v", err)
	}
	dir := t.TempDir()
	if err := os.Symlink(realPath, filepath.Join(dir, VendorsFileName)); err != nil {
		t.Skipf("symlinks not available in this environment: %v", err)
	}
	catalog := Load(dir)
	if catalog.Enabled() {
		t.Fatal("symlinked vendors.json must disable the catalog")
	}
	joined := strings.Join(catalog.Warnings(), " ")
	if !strings.Contains(joined, "Symlink nicht erlaubt") {
		t.Fatalf("warnings = %v", catalog.Warnings())
	}
	assertNoPathLeak(t, catalog.Warnings(), dir, realDir, realPath)
}

func TestSymlinkSiblingRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, VendorsFileName), []byte(fixtureVendors), 0o600); err != nil {
		t.Fatalf("write vendors: %v", err)
	}
	realSurface := filepath.Join(t.TempDir(), "real-write-surface.json")
	if err := os.WriteFile(realSurface, []byte(fixtureSurfaces), 0o600); err != nil {
		t.Fatalf("write surfaces: %v", err)
	}
	if err := os.Symlink(realSurface, filepath.Join(dir, WriteSurfaceFileName)); err != nil {
		t.Skipf("symlinks not available in this environment: %v", err)
	}
	catalog := Load(dir)
	if !catalog.Enabled() {
		t.Fatalf("vendors.json itself is valid: %v", catalog.Warnings())
	}
	if catalog.HasWriteSurfaces() {
		t.Fatal("symlinked write-surface.json must be rejected")
	}
	joined := strings.Join(catalog.Warnings(), " ")
	if !strings.Contains(joined, "Symlink nicht erlaubt") {
		t.Fatalf("warnings = %v", catalog.Warnings())
	}
	assertNoPathLeak(t, catalog.Warnings(), dir, realSurface)
}
