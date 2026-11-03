package discovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func flowEvent(t *testing.T, protocol, src, dst string, srcPort, dstPort int) domain.Event {
	t.Helper()
	return domain.Event{
		EventID:    "evt_flow_1",
		Kind:       domain.EventFlow,
		SiteID:     "filiale-001",
		ObservedAt: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC),
		ReceivedAt: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC),
		Source:     "pcap.test",
		Collection: "operator_export",
		Protocol:   protocol,
		Confidence: 0.6,
		Flow: &domain.FlowMeta{
			SrcIP: src, DstIP: dst, SrcPort: srcPort, DstPort: dstPort, Protocol: protocol,
		},
	}
}

func assetSeenEvent(t *testing.T, ip, hostname, vendor, model string) domain.Event {
	t.Helper()
	return domain.Event{
		EventID:    "evt_asset_1",
		Kind:       domain.EventAssetSeen,
		SiteID:     "filiale-001",
		ObservedAt: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC),
		ReceivedAt: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC),
		Source:     "httpui.test",
		Collection: "passive_tap",
		Protocol:   "http",
		Confidence: 0.55,
		Device:     &domain.DeviceMeta{IP: ip, Hostname: hostname, Vendor: vendor, Model: model},
	}
}

func TestFlowPortClassification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		protocol string
		srcPort  int
		dstPort  int
		wantType domain.AssetType
		minConf  float64
		maxConf  float64
	}{
		{"modbus", "modbus_tcp", 50000, 502, domain.AssetPL, 0.3, 0.9},
		{"bacnet", "bacnet_ip", 50000, 47808, domain.AssetBMS, 0.3, 0.9},
		{"mqtt", "mqtt", 50000, 1883, domain.AssetSensorGateway, 0.3, 0.9},
		{"snmp", "snmp", 50000, 161, domain.AssetNetworkDevice, 0.3, 0.9},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			discoverer := New(Options{VendorsPath: filepath.Join(t.TempDir(), "missing.json")})
			asset, ok := discoverer.Observe(flowEvent(t, tc.protocol, "172.16.50.20", "172.16.50.10", tc.srcPort, tc.dstPort))
			if !ok {
				t.Fatal("no hypothesis")
			}
			if err := asset.Validate(); err != nil {
				t.Fatalf("invalid asset: %v", err)
			}
			if asset.Type != tc.wantType {
				t.Fatalf("type = %q, want %q", asset.Type, tc.wantType)
			}
			if asset.Confidence < tc.minConf || asset.Confidence > tc.maxConf {
				t.Fatalf("confidence %v outside [%v,%v]", asset.Confidence, tc.minConf, tc.maxConf)
			}
			if asset.Classification != domain.ClassificationAuto {
				t.Fatalf("classification = %q", asset.Classification)
			}
		})
	}
}

func TestManagementUIHintClassifiesController(t *testing.T) {
	t.Parallel()
	discoverer := New(Options{VendorsPath: filepath.Join(t.TempDir(), "missing.json")})
	asset, ok := discoverer.Observe(assetSeenEvent(t, "172.16.50.10", "storeview-ak-sm-800.filiale.local", "Danfoss", "StoreView"))
	if !ok {
		t.Fatal("no hypothesis")
	}
	if asset.Type != domain.AssetRefrigerationController {
		t.Fatalf("type = %q", asset.Type)
	}
	if asset.Confidence < 0.5 || asset.Confidence > 0.9 {
		t.Fatalf("confidence = %v", asset.Confidence)
	}
	if !asset.ManagementInterface {
		t.Fatal("management interface flag missing")
	}
	if asset.Vendor != "Danfoss" || asset.Model != "StoreView" {
		t.Fatalf("vendor/model = %q/%q", asset.Vendor, asset.Model)
	}
}

func TestUnknownStaysUnknown(t *testing.T) {
	t.Parallel()
	discoverer := New(Options{VendorsPath: filepath.Join(t.TempDir(), "missing.json")})
	// A management port without any product hint is not a proven controller.
	asset, ok := discoverer.Observe(flowEvent(t, "https", "192.168.99.50", "172.16.50.10", 50000, 443))
	if !ok {
		t.Fatal("no hypothesis")
	}
	if asset.Type != domain.AssetUnknown {
		t.Fatalf("type = %q, want unknown", asset.Type)
	}
	if asset.Vendor != "" || asset.Model != "" {
		t.Fatalf("invented vendor/model: %q/%q", asset.Vendor, asset.Model)
	}
	if asset.Confidence > 0.4 {
		t.Fatalf("unknown confidence too high: %v", asset.Confidence)
	}
	// Events without identity evidence yield no hypothesis.
	if _, ok := discoverer.Observe(domain.Event{Kind: domain.EventTelemetry, SiteID: "filiale-001"}); ok {
		t.Fatal("telemetry must not create an asset hypothesis")
	}
}

func TestCatalogOUIAndLifecycle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "vendors.json")
	content := `{
	  "vendors": [{"id":"danfoss","name":"Danfoss"}],
	  "device_families": [{"id":"danfoss_ak_sm_800","vendor_id":"danfoss","name":"AK-SM 800","lifecycle":"eol_2021_05"}],
	  "oui_prefixes": [{"prefix":"02:00:00","vendor_id":"danfoss"}]
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	discoverer := New(Options{VendorsPath: path})
	event := assetSeenEvent(t, "172.16.50.10", "storeview-ak-sm-800.filiale.local", "", "")
	event.Device.MAC = "02:00:00:11:22:33"
	asset, ok := discoverer.Observe(event)
	if !ok {
		t.Fatal("no hypothesis")
	}
	if asset.Vendor != "Danfoss" {
		t.Fatalf("vendor = %q", asset.Vendor)
	}
	if asset.Lifecycle != domain.LifecycleEOL {
		t.Fatalf("lifecycle = %q", asset.Lifecycle)
	}
	if asset.LifecycleSource == "" {
		t.Fatal("lifecycle source missing")
	}
	if asset.Model == "" {
		t.Fatal("model not derived from the catalog family")
	}
}

func TestMissingCatalogStillWorks(t *testing.T) {
	t.Parallel()
	discoverer := New(Options{VendorsPath: filepath.Join(t.TempDir(), "nope.json")})
	asset, ok := discoverer.Observe(flowEvent(t, "modbus_tcp", "172.16.50.20", "172.16.50.10", 50000, 502))
	if !ok {
		t.Fatal("discovery must work without a catalog")
	}
	if asset.Lifecycle != domain.LifecycleUnknown {
		t.Fatalf("lifecycle = %q", asset.Lifecycle)
	}
}

func TestMergeKeepsStableIdentity(t *testing.T) {
	t.Parallel()
	discoverer := New(Options{VendorsPath: filepath.Join(t.TempDir(), "missing.json")})
	first, ok := discoverer.Observe(flowEvent(t, "modbus_tcp", "172.16.50.20", "172.16.50.10", 50000, 502))
	if !ok {
		t.Fatal("first hypothesis")
	}
	secondEvent := assetSeenEvent(t, "172.16.50.10", "storeview-ak-sm-800.filiale.local", "Danfoss", "StoreView")
	secondEvent.ObservedAt = first.LastSeenAt.Add(time.Minute)
	second, ok := discoverer.Observe(secondEvent)
	if !ok {
		t.Fatal("second hypothesis")
	}
	if first.AssetID != second.AssetID {
		t.Fatalf("asset id changed: %q vs %q", first.AssetID, second.AssetID)
	}
	if second.Confidence <= 0 || second.Confidence > 0.9 {
		t.Fatalf("confidence = %v", second.Confidence)
	}
	if !second.LastSeenAt.After(first.LastSeenAt) {
		t.Fatalf("last seen not updated: %v / %v", first.LastSeenAt, second.LastSeenAt)
	}
	if len(discoverer.Assets()) != 1 {
		t.Fatalf("expected one merged asset, got %d", len(discoverer.Assets()))
	}
}
