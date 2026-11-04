package vendorcatalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture documents one small but schema-complete catalog.
const (
	fixtureVendors = `{
	  "schema_version": "1.0",
	  "vendors": [
	    {"id": "danfoss", "name": "Danfoss", "legal_name": "Danfoss A/S", "confidence": "high", "verification": "fulltext_fetched"},
	    {"id": "carel", "name": "Carel", "confidence": "medium", "verification": "secondary_reported"}
	  ],
	  "protocols": [
	    {"id": "http_https_management", "name": "HTTP/HTTPS management", "transport": "tcp", "default_port": 443},
	    {"id": "modbus_tcp", "name": "Modbus TCP", "transport": "tcp", "default_port": 502}
	  ],
	  "device_families": [
	    {"id": "danfoss_ak_sm_800", "vendor_id": "danfoss", "name": "AK-SM 800", "category": "store_supervisor",
	     "protocols": ["http_https_management"], "management_interface": "StoreView web UI", "lifecycle": "eol_2021_05",
	     "confidence": "high", "verification": "fulltext_fetched"},
	    {"id": "danfoss_ak_sm_800a", "vendor_id": "danfoss", "name": "AK-SM 800A", "category": "store_supervisor",
	     "protocols": ["http_https_management"], "management_interface": "AK-SM 800A web UI", "lifecycle": "current",
	     "confidence": "medium", "verification": "secondary_reported"},
	    {"id": "carel_pco", "vendor_id": "carel", "name": "pCO platform", "category": "controller_platform",
	     "lifecycle": "current"}
	  ],
	  "oui_prefixes": [{"prefix": "02:00:00", "vendor_id": "danfoss"}]
	}`

	fixtureSurfaces = `{
	  "schema_version": "1.0",
	  "change_classes": [
	    {"id": "C-01", "name": "Setpoints", "criticality": "critical",
	     "evidence": {"source_url": "https://example.invalid/c01", "confidence": "high", "verification": "fulltext_fetched"}}
	  ],
	  "write_surfaces": [
	    {"id": "ws_http_danfoss", "scope": "device_family", "device_family_id": "danfoss_ak_sm_800a",
	     "protocol": "http_https_management", "transport": "tcp", "enforcement": "gate",
	     "operations": [{"kind": "write", "name": "Set threshold", "decision": "deny_by_default"}],
	     "critical_change_classes": ["C-01"],
	     "evidence": {"source_url": "https://example.invalid/ws", "confidence": "high", "verification": "fulltext_fetched"}},
	    {"id": "ws_modbus_write", "scope": "protocol_generic", "protocol": "modbus_tcp",
	     "operations": [{"kind": "read", "name": "Read holding registers", "decision": "allow"}],
	     "evidence": {"source_url": "https://example.invalid/modbus", "confidence": "high", "verification": "fulltext_fetched"}},
	    {"id": "ws_modbus_low", "scope": "protocol_generic", "protocol": "modbus_tcp",
	     "operations": [{"kind": "write", "name": "Write register", "decision": "deny_by_default"}],
	     "evidence": {"source_url": "https://example.invalid/modbus-low", "confidence": "low", "verification": "search_result_only"}}
	  ]
	}`

	fixtureRegulatory = `{
	  "schema_version": "1.0",
	  "product_boundary_summary": ["GeDefense does not replace HACCP."],
	  "frameworks": [
	    {"id": "nis2", "name": "NIS2", "reference": "(EU) 2022/2555", "jurisdiction": "EU", "status": "in_force",
	     "product_role": "evidence support", "product_constraints": "not a compliance tool",
	     "confidence": "high", "verification": "fulltext_fetched"}
	  ]
	}`
)

// writeFixture creates a catalog directory; an empty document value removes the
// file, a non-empty value replaces the default document.
func writeFixture(t *testing.T, vendors, surfaces, regulatory string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		VendorsFileName:           vendors,
		WriteSurfaceFileName:      surfaces,
		RegulatoryContextFileName: regulatory,
	}
	defaults := map[string]string{
		VendorsFileName:           fixtureVendors,
		WriteSurfaceFileName:      fixtureSurfaces,
		RegulatoryContextFileName: fixtureRegulatory,
	}
	for name, fallback := range defaults {
		content := files[name]
		if content == "" {
			content = fallback
		}
		if content == "missing" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	return dir
}

func TestLoadValidCatalog(t *testing.T) {
	t.Parallel()
	dir := writeFixture(t, "", "", "")
	catalog := Load(dir)
	if !catalog.Enabled() {
		t.Fatalf("catalog disabled, warnings: %v", catalog.Warnings())
	}
	if len(catalog.Warnings()) != 0 {
		t.Fatalf("unexpected warnings: %v", catalog.Warnings())
	}
	if !catalog.HasWriteSurfaces() || !catalog.HasRegulatoryContext() {
		t.Fatal("sibling documents were not loaded")
	}
	if got := len(catalog.Vendors()); got != 2 {
		t.Fatalf("vendors = %d", got)
	}
	if family, ok := catalog.Family("danfoss_ak_sm_800"); !ok || family.Name != "AK-SM 800" {
		t.Fatalf("family lookup = %+v / %v", family, ok)
	}
	if got := catalog.WriteSurfacesForFamily("danfoss_ak_sm_800a"); len(got) != 1 || got[0].ID != "ws_http_danfoss" {
		t.Fatalf("surfaces for family = %+v", got)
	}
	count, highest := catalog.SurfaceSummary("danfoss_ak_sm_800a")
	if count != 1 || highest != "high" {
		t.Fatalf("surface summary = %d / %q", count, highest)
	}
	regulatory := catalog.RegulatoryContext()
	if len(regulatory.Frameworks) != 1 || regulatory.Frameworks[0].ID != "nis2" {
		t.Fatalf("regulatory = %+v", regulatory)
	}
	if class, ok := catalog.ChangeClass("C-01"); !ok || class.Name != "Setpoints" {
		t.Fatalf("change class = %+v / %v", class, ok)
	}
}

func TestLoadMissingCatalog(t *testing.T) {
	t.Parallel()
	catalog := Load(filepath.Join(t.TempDir(), "no-such-dir", VendorsFileName))
	if catalog.Enabled() || catalog.HasWriteSurfaces() || catalog.HasRegulatoryContext() {
		t.Fatal("missing catalog must be disabled")
	}
	if len(catalog.Warnings()) == 0 {
		t.Fatal("missing catalog must warn")
	}
	if _, ok := catalog.Family("any"); ok {
		t.Fatal("missing catalog must not resolve families")
	}
}

func TestLoadCorruptCatalog(t *testing.T) {
	t.Parallel()
	dir := writeFixture(t, "{ this is not json", "", "")
	catalog := Load(dir)
	if catalog.Enabled() {
		t.Fatal("corrupt vendors.json must disable the catalog")
	}
	if !strings.Contains(strings.Join(catalog.Warnings(), " "), "kein gueltiges JSON") {
		t.Fatalf("warnings = %v", catalog.Warnings())
	}
}

func TestLoadPartialCatalog(t *testing.T) {
	t.Parallel()
	dir := writeFixture(t, "", "missing", "missing")
	catalog := Load(dir)
	if !catalog.Enabled() {
		t.Fatalf("vendors.json alone must enable the catalog: %v", catalog.Warnings())
	}
	if catalog.HasWriteSurfaces() || catalog.HasRegulatoryContext() {
		t.Fatal("missing siblings must not be reported as loaded")
	}
	warnings := strings.Join(catalog.Warnings(), " ")
	if !strings.Contains(warnings, "write-surface.json") || !strings.Contains(warnings, "regulatory-context.json") {
		t.Fatalf("warnings = %v", catalog.Warnings())
	}
}

func TestLoadInvalidReferenceDisablesOnlySurfaces(t *testing.T) {
	t.Parallel()
	badSurfaces := strings.Replace(fixtureSurfaces, `"device_family_id": "danfoss_ak_sm_800a"`, `"device_family_id": "missing_family"`, 1)
	dir := writeFixture(t, "", badSurfaces, "")
	catalog := Load(dir)
	if !catalog.Enabled() {
		t.Fatalf("vendor document must stay usable: %v", catalog.Warnings())
	}
	if catalog.HasWriteSurfaces() {
		t.Fatal("invalid write-surface document must be disabled")
	}
	if len(catalog.Warnings()) == 0 {
		t.Fatal("invalid references must warn")
	}
}

func TestLoadInvalidVendorsDisablesCatalog(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(fixtureVendors, `"vendor_id": "danfoss"`, `"vendor_id": "unknown_vendor"`, 1)
	dir := writeFixture(t, broken, "", "")
	catalog := Load(dir)
	if catalog.Enabled() {
		t.Fatal("invalid family reference must disable the catalog")
	}
}

func TestOversizeCatalogIsRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	oversized := make([]byte, MaxFileBytes+1)
	for i := range oversized {
		oversized[i] = ' '
	}
	oversized[0] = '{'
	oversized[len(oversized)-1] = '}'
	if err := os.WriteFile(filepath.Join(dir, VendorsFileName), oversized, 0o600); err != nil {
		t.Fatalf("write oversized fixture: %v", err)
	}
	catalog := Load(dir)
	if catalog.Enabled() {
		t.Fatal("oversized vendors.json must disable the catalog")
	}
}

func TestVendorForMAC(t *testing.T) {
	t.Parallel()
	catalog := Load(writeFixture(t, "", "", ""))
	if vendor, ok := catalog.VendorForMAC("02:00:00:11:22:33"); !ok || vendor != "Danfoss" {
		t.Fatalf("vendor for MAC = %q / %v", vendor, ok)
	}
	if _, ok := catalog.VendorForMAC("aa:bb:cc:11:22:33"); ok {
		t.Fatal("unknown OUI must not resolve")
	}
	if _, ok := catalog.VendorForMAC("not-a-mac"); ok {
		t.Fatal("invalid MAC must not resolve")
	}
}

func TestDisabledCatalogAccessorsAreSafe(t *testing.T) {
	t.Parallel()
	var catalog *Catalog
	if catalog.Enabled() || catalog.HasWriteSurfaces() || catalog.Path() != "" {
		t.Fatal("nil catalog must be inert")
	}
	if len(catalog.Vendors()) != 0 || len(catalog.Families()) != 0 || len(catalog.WriteSurfaces()) != 0 {
		t.Fatal("nil catalog must return empty collections")
	}
	if _, ok := catalog.Family("x"); ok {
		t.Fatal("nil catalog must not resolve families")
	}
}

// TestRealCatalog loads the catalog shipped in the repository to guarantee that
// the production documents pass validation. It is skipped when the repository
// data directory is not present (for example in an isolated module cache).
func TestRealCatalog(t *testing.T) {
	t.Parallel()
	path := findRealCatalog(t)
	if path == "" {
		t.Skip("repository OT catalog not found")
	}
	catalog := Load(path)
	if !catalog.Enabled() {
		t.Fatalf("shipped catalog disabled: %v", catalog.Warnings())
	}
	if len(catalog.Warnings()) != 0 {
		t.Fatalf("shipped catalog has warnings: %v", catalog.Warnings())
	}
	if !catalog.HasWriteSurfaces() {
		t.Fatal("shipped catalog has no write surfaces")
	}
	if !catalog.HasRegulatoryContext() {
		t.Fatal("shipped catalog has no regulatory context")
	}
	if len(catalog.Families()) < 5 || len(catalog.WriteSurfaces()) < 5 {
		t.Fatalf("shipped catalog unexpectedly small: %d families, %d surfaces",
			len(catalog.Families()), len(catalog.WriteSurfaces()))
	}
	if note, known := catalog.Advisory("modbus_tcp"); !known || note == "" {
		t.Fatalf("modbus advisory should be known: %q / %v", note, known)
	}
	if family, ok := catalog.MatchFamily("Danfoss", "", "storeview-ak-sm-800.filiale.local"); !ok || family.ID != "danfoss_ak_sm_800" {
		t.Fatalf("shipped catalog family match = %+v / %v", family, ok)
	}
}

// findRealCatalog walks up from the package directory to the repository root.
func findRealCatalog(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for depth := 0; depth < 8; depth++ {
		candidate := filepath.Join(dir, "data", "ot-catalog", VendorsFileName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
