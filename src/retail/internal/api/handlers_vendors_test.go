package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/retail/internal/vendorcatalog"
)

const (
	vendorFixtureVendors = `{
	  "vendors": [{"id": "danfoss", "name": "Danfoss"}],
	  "protocols": [{"id": "http_https_management", "name": "HTTP/HTTPS management"}],
	  "device_families": [
	    {"id": "danfoss_ak_sm_800", "vendor_id": "danfoss", "name": "AK-SM 800", "category": "store_supervisor",
	     "protocols": ["http_https_management"], "management_interface": "StoreView web UI", "lifecycle": "eol_2021_05"}
	  ]
	}`
	vendorFixtureSurfaces = `{
	  "change_classes": [
	    {"id": "C-01", "name": "Setpoints", "criticality": "critical"}
	  ],
	  "write_surfaces": [
	    {"id": "ws_http_danfoss", "scope": "device_family", "device_family_id": "danfoss_ak_sm_800",
	     "protocol": "http_https_management", "operations": [
	       {"kind": "write", "name": "Set threshold", "decision": "deny_by_default"}
	     ], "critical_change_classes": ["C-01"],
	     "evidence": {"source_url": "https://example.invalid/ws", "confidence": "high", "verification": "fulltext_fetched"},
	     "notes": "Only via the gate."}
	  ]
	}`
	vendorFixtureRegulatory = `{
	  "product_boundary_summary": ["GeDefense does not replace HACCP."],
	  "frameworks": [
	    {"id": "nis2", "name": "NIS2", "product_role": "evidence support", "product_constraints": "not a compliance tool",
	     "confidence": "high", "verification": "fulltext_fetched"}
	  ]
	}`
)

// vendorCatalogForTest builds a valid catalog from the fixture documents.
func vendorCatalogForTest(t *testing.T) *vendorcatalog.Catalog {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		vendorcatalog.VendorsFileName:           vendorFixtureVendors,
		vendorcatalog.WriteSurfaceFileName:      vendorFixtureSurfaces,
		vendorcatalog.RegulatoryContextFileName: vendorFixtureRegulatory,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write catalog fixture %s: %v", name, err)
		}
	}
	catalog := vendorcatalog.Load(dir)
	if !catalog.Enabled() {
		t.Fatalf("catalog fixture disabled: %v", catalog.Warnings())
	}
	return catalog
}

func TestVendorListEndpoint(t *testing.T) {
	harness := newAPIHarness(t, apiTestOptions{vendorCatalog: vendorCatalogForTest(t)})

	recorder := harness.do(t, http.MethodGet, "/api/v1/vendors", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control = %q", got)
	}
	response := decode[vendorsResponse](t, recorder)
	if !response.Enabled || response.Total != 1 || len(response.Items) != 1 {
		t.Fatalf("response = %+v", response)
	}
	item := response.Items[0]
	if item.VendorID != "danfoss" || item.VendorName != "Danfoss" {
		t.Fatalf("vendor = %+v", item)
	}
	if item.Family.ID != "danfoss_ak_sm_800" || item.Family.Category != "store_supervisor" || item.Family.Lifecycle != "eol_2021_05" {
		t.Fatalf("family = %+v", item.Family)
	}
	if item.WriteSurfaces != 1 || item.HighestEvidence != "high" {
		t.Fatalf("surface summary = %d / %q", item.WriteSurfaces, item.HighestEvidence)
	}
	if recorder := harness.do(t, http.MethodGet, "/api/v1/vendors", nil, operatorToken, nil); recorder.Code != http.StatusOK {
		t.Fatalf("operator status = %d", recorder.Code)
	}
	if recorder := harness.do(t, http.MethodGet, "/api/v1/vendors", nil, "", nil); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", recorder.Code)
	}
}

func TestVendorFamilyDetailEndpoint(t *testing.T) {
	harness := newAPIHarness(t, apiTestOptions{vendorCatalog: vendorCatalogForTest(t)})

	recorder := harness.do(t, http.MethodGet, "/api/v1/vendors/danfoss_ak_sm_800", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	detail := decode[vendorFamilyDetailResponse](t, recorder)
	if !detail.Enabled || detail.Family == nil || detail.Family.ID != "danfoss_ak_sm_800" {
		t.Fatalf("detail = %+v", detail)
	}
	if len(detail.WriteSurfaces) != 1 {
		t.Fatalf("write surfaces = %+v", detail.WriteSurfaces)
	}
	surface := detail.WriteSurfaces[0]
	if surface.Protocol != "http_https_management" || surface.Scope != "device_family" {
		t.Fatalf("surface = %+v", surface)
	}
	if len(surface.Operations) != 1 || surface.Operations[0].Decision != "deny_by_default" {
		t.Fatalf("operations = %+v", surface.Operations)
	}
	if len(surface.ChangeClasses) != 1 || surface.ChangeClasses[0].Name != "Setpoints" {
		t.Fatalf("change classes = %+v", surface.ChangeClasses)
	}
	if surface.Evidence.Confidence != "high" || surface.Evidence.SourceURL == "" {
		t.Fatalf("evidence = %+v", surface.Evidence)
	}
	if surface.Notes == "" {
		t.Fatal("surface notes missing")
	}

	if recorder := harness.do(t, http.MethodGet, "/api/v1/vendors/unknown_family", nil, viewerToken, nil); recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown family = %d, want 404", recorder.Code)
	}
}

func TestVendorEndpointsWithoutCatalog(t *testing.T) {
	harness := newAPIHarness(t, apiTestOptions{})
	list := harness.do(t, http.MethodGet, "/api/v1/vendors", nil, viewerToken, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list = %d", list.Code)
	}
	listResponse := decode[vendorsResponse](t, list)
	if listResponse.Enabled || listResponse.Total != 0 || len(listResponse.Items) != 0 || listResponse.Note == "" {
		t.Fatalf("disabled list = %+v", listResponse)
	}
	detail := harness.do(t, http.MethodGet, "/api/v1/vendors/danfoss_ak_sm_800", nil, viewerToken, nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("disabled detail = %d, want 200", detail.Code)
	}
	detailResponse := decode[vendorFamilyDetailResponse](t, detail)
	if detailResponse.Enabled || len(detailResponse.WriteSurfaces) != 0 || detailResponse.Note == "" {
		t.Fatalf("disabled detail = %+v", detailResponse)
	}
	regulatory := harness.do(t, http.MethodGet, "/api/v1/regulatory-context", nil, viewerToken, nil)
	if regulatory.Code != http.StatusOK {
		t.Fatalf("disabled regulatory = %d, want 200", regulatory.Code)
	}
	regulatoryResponse := decode[regulatoryContextResponse](t, regulatory)
	if regulatoryResponse.Enabled || len(regulatoryResponse.Frameworks) != 0 {
		t.Fatalf("disabled regulatory = %+v", regulatoryResponse)
	}
	if regulatoryResponse.Note == "" {
		t.Fatal("regulatory note missing")
	}
}

func TestDisabledCatalogWarningsAreGeneric(t *testing.T) {
	// F-A8-06: catalog warnings are served to viewers and must not leak
	// filesystem paths or environment values.
	missingDir := filepath.Join(t.TempDir(), "secret-catalog")
	catalog := vendorcatalog.Load(filepath.Join(missingDir, vendorcatalog.VendorsFileName))
	harness := newAPIHarness(t, apiTestOptions{vendorCatalog: catalog})

	recorder := harness.do(t, http.MethodGet, "/api/v1/vendors", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	response := decode[vendorsResponse](t, recorder)
	if response.Enabled || len(response.Warnings) == 0 {
		t.Fatalf("response = %+v", response)
	}
	for _, warning := range response.Warnings {
		if strings.Contains(warning, missingDir) || strings.Contains(warning, "secret-catalog") {
			t.Fatalf("warning leaks catalog path: %q", warning)
		}
	}
	regulatory := decode[regulatoryContextResponse](t, harness.do(t, http.MethodGet, "/api/v1/regulatory-context", nil, viewerToken, nil))
	for _, warning := range regulatory.Warnings {
		if strings.Contains(warning, missingDir) || strings.Contains(warning, "secret-catalog") {
			t.Fatalf("regulatory warning leaks catalog path: %q", warning)
		}
	}
}

func TestRegulatoryContextEndpoint(t *testing.T) {
	harness := newAPIHarness(t, apiTestOptions{vendorCatalog: vendorCatalogForTest(t)})
	recorder := harness.do(t, http.MethodGet, "/api/v1/regulatory-context", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	response := decode[regulatoryContextResponse](t, recorder)
	if !response.Enabled || len(response.Frameworks) != 1 {
		t.Fatalf("response = %+v", response)
	}
	framework := response.Frameworks[0]
	if framework.ID != "nis2" || framework.Name != "NIS2" || framework.Role == "" || framework.Notes == "" {
		t.Fatalf("framework = %+v", framework)
	}
	if response.Note == "" || response.Note == "compliance" {
		t.Fatalf("note = %q", response.Note)
	}
	if len(response.ProductBoundarySummary) != 1 {
		t.Fatalf("boundary summary = %+v", response.ProductBoundarySummary)
	}
}
