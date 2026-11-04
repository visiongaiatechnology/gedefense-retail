package discovery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// catalogDir writes a minimal valid vendors.json catalog and returns its path.
func catalogDir(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vendors.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	return dir
}

const carelCatalog = `{
  "vendors": [{"id": "carel", "name": "Carel"}],
  "protocols": [
    {"id": "bacnet_mstp", "name": "BACnet MSTP"},
    {"id": "soap_xml", "name": "SOAP/XML"},
    {"id": "http_https_management", "name": "HTTP/HTTPS management"}
  ],
  "device_families": [
    {"id": "carel_pco_platform", "vendor_id": "carel", "name": "pCO platform", "category": "controller_platform",
     "protocols": ["bacnet_mstp", "soap_xml"], "management_interface": "local terminal", "lifecycle": "current"},
    {"id": "carel_rack", "vendor_id": "carel", "name": "rack family", "category": "rack_controller",
     "lifecycle": "current"},
    {"id": "carel_cloud", "vendor_id": "carel", "name": "Carel Cloud", "category": "cloud_monitoring",
     "protocols": ["http_https_management"], "lifecycle": "current"}
  ]
}`

func TestFamilyEnrichmentAddsTypeProtocolsModelLifecycle(t *testing.T) {
	t.Parallel()
	discoverer := New(Options{VendorsPath: catalogDir(t, carelCatalog)})
	event := assetSeenEvent(t, "172.16.50.31", "pco-platform-01", "Carel", "")
	// The observed protocol must not already imply a management interface.
	event.Protocol = "modbus_tcp"
	asset, ok := discoverer.Observe(event)
	if !ok {
		t.Fatal("no hypothesis")
	}
	if asset.Type != domain.AssetRefrigerationController {
		t.Fatalf("type = %q", asset.Type)
	}
	if asset.Model != "pCO platform" {
		t.Fatalf("model = %q", asset.Model)
	}
	if asset.Lifecycle != domain.LifecycleActive {
		t.Fatalf("lifecycle = %q", asset.Lifecycle)
	}
	if asset.LifecycleSource != "ot-catalog:carel_pco_platform" {
		t.Fatalf("lifecycle source = %q", asset.LifecycleSource)
	}
	foundBACnet, foundSOAP := false, false
	for _, protocol := range asset.Protocols {
		if protocol == "BACnet MSTP" {
			foundBACnet = true
		}
		if protocol == "SOAP/XML" {
			foundSOAP = true
		}
	}
	if !foundBACnet || !foundSOAP {
		t.Fatalf("protocols = %v", asset.Protocols)
	}
	if asset.ManagementInterface {
		t.Fatal("non-HTTP family must not set the management-interface flag")
	}
	if err := asset.Validate(); err != nil {
		t.Fatalf("invalid asset: %v", err)
	}
}

func TestFamilyEnrichmentRaisesConfidenceBounded(t *testing.T) {
	t.Parallel()
	event := assetSeenEvent(t, "172.16.50.32", "pco-platform-02", "Carel", "")
	without := New(Options{VendorsPath: filepath.Join(t.TempDir(), "missing.json")})
	with := New(Options{VendorsPath: catalogDir(t, carelCatalog)})
	base, ok := without.Observe(event)
	if !ok {
		t.Fatal("baseline hypothesis missing")
	}
	enriched, ok := with.Observe(event)
	if !ok {
		t.Fatal("enriched hypothesis missing")
	}
	if enriched.Confidence <= base.Confidence {
		t.Fatalf("confidence did not increase: %v -> %v", base.Confidence, enriched.Confidence)
	}
	if enriched.Confidence > 0.9 {
		t.Fatalf("confidence exceeds clamp: %v", enriched.Confidence)
	}
}

func TestRackControllerFamilyMapsToCoolingRack(t *testing.T) {
	t.Parallel()
	discoverer := New(Options{VendorsPath: catalogDir(t, carelCatalog)})
	asset, ok := discoverer.Observe(assetSeenEvent(t, "172.16.50.33", "rack-family-01", "", ""))
	if !ok {
		t.Fatal("no hypothesis")
	}
	if asset.Type != domain.AssetCoolingRack {
		t.Fatalf("type = %q, want cooling_rack", asset.Type)
	}
}

func TestCloudMonitoringFamilyStaysUnknown(t *testing.T) {
	t.Parallel()
	discoverer := New(Options{VendorsPath: catalogDir(t, carelCatalog)})
	// The hostname matches the family token but contains no controller vendor hint,
	// so passive classification stays unknown and the family category must keep it
	// unknown while still adding the documented management interface.
	asset, ok := discoverer.Observe(assetSeenEvent(t, "172.16.50.34", "cloud-01", "", ""))
	if !ok {
		t.Fatal("no hypothesis")
	}
	if asset.Type != domain.AssetUnknown {
		t.Fatalf("type = %q, want unknown", asset.Type)
	}
	if !asset.ManagementInterface {
		t.Fatal("HTTP family should set the management-interface flag")
	}
	if asset.Model != "Carel Cloud" {
		t.Fatalf("model = %q", asset.Model)
	}
}

func TestUnmatchedDeviceIsNotEnriched(t *testing.T) {
	t.Parallel()
	discoverer := New(Options{VendorsPath: catalogDir(t, carelCatalog)})
	asset, ok := discoverer.Observe(assetSeenEvent(t, "172.16.50.35", "unknown-host-01", "", ""))
	if !ok {
		t.Fatal("no hypothesis")
	}
	if asset.LifecycleSource != "" || asset.Model != "" {
		t.Fatalf("unexpected enrichment: lifecycle source %q model %q", asset.LifecycleSource, asset.Model)
	}
	if asset.Type != domain.AssetUnknown {
		t.Fatalf("type = %q, want unknown", asset.Type)
	}
}
