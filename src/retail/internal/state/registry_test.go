package state

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// fakeClock is a deterministic ports.Clock for the state tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

var baseTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func testSite() domain.Site {
	return domain.Site{
		SiteID: "filiale-001",
		Name:   "Markt Nord",
		Status: domain.SiteOnline,
		Zones:  []domain.Zone{{ZoneID: "zone-ot", SiteID: "filiale-001", Name: "OT", Kind: domain.ZoneOTProcess}},
	}
}

func telemetryEvent(id string, at time.Time, sensor domain.SensorID, value float64) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(id),
		Kind:       domain.EventTelemetry,
		SiteID:     "filiale-001",
		ZoneID:     "zone-ot",
		AssetID:    "asset-1",
		SensorID:   sensor,
		ObservedAt: at,
		ReceivedAt: at,
		Source:     "modbus.pool1",
		Collection: "read_only_poll",
		Protocol:   "modbus_tcp",
		Confidence: 0.9,
		Measurement: &domain.Measurement{
			Value:      value,
			Unit:       domain.UnitCelsius,
			Quality:    domain.QualityGood,
			Metric:     "air_temperature",
			ObservedAt: at,
		},
	}
}

func assetSeenEvent(id string, at time.Time, asset domain.AssetID) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(id),
		Kind:       domain.EventAssetSeen,
		SiteID:     "filiale-001",
		ZoneID:     "zone-ot",
		AssetID:    asset,
		ObservedAt: at,
		ReceivedAt: at,
		Source:     "pcap.tap",
		Collection: "passive_tap",
		Protocol:   "modbus_tcp",
		Confidence: 0.6,
		Device:     &domain.DeviceMeta{IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:ff", Vendor: "TestVendor"},
	}
}

func flowEvent(id string, at time.Time, src, dst string) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(id),
		Kind:       domain.EventFlow,
		SiteID:     "filiale-001",
		ObservedAt: at,
		ReceivedAt: at,
		Source:     "pcap.tap",
		Collection: "passive_tap",
		Confidence: 0.7,
		Flow:       &domain.FlowMeta{SrcIP: src, DstIP: dst, SrcPort: 50000, DstPort: 502, Protocol: "modbus_tcp"},
	}
}

func accessEvent(id string, at time.Time, session string) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(id),
		Kind:       domain.EventAccess,
		SiteID:     "filiale-001",
		ObservedAt: at,
		ReceivedAt: at,
		Source:     "pcap.tap",
		Collection: "passive_tap",
		Confidence: 0.8,
		Access: &domain.AccessMeta{
			Vendor: "ServiceCo", User: "tech-1", Method: "vpn",
			TargetAsset: "asset-1", SessionID: session, InWindow: false,
		},
	}
}

func newTestRegistry(t *testing.T, clock ports.Clock) *Registry {
	t.Helper()
	return NewRegistry([]domain.Site{testSite()}, clock)
}

func TestNewRegistryAndSiteAccess(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	sites := r.Sites()
	if len(sites) != 1 || sites[0].SiteID != "filiale-001" {
		t.Fatalf("Sites = %+v", sites)
	}
	site, ok := r.Site("filiale-001")
	if !ok || site.Name != "Markt Nord" {
		t.Fatalf("Site = %+v, %v", site, ok)
	}
	if _, ok := r.Site("missing"); ok {
		t.Error("unknown site must not be found")
	}
	if got := r.Health(); got.Sites != 1 || got.Assets != 0 || got.EventsIngested != 0 {
		t.Errorf("Health = %+v", got)
	}

	// Returned values must be copies.
	sites[0].Name = "tampered"
	if again, _ := r.Site("filiale-001"); again.Name != "Markt Nord" {
		t.Error("Sites returned shared state")
	}
}

func TestApplyTelemetryCreatesSensorAndSample(t *testing.T) {
	clock := newFakeClock(baseTime)
	r := newTestRegistry(t, clock)
	ctx := context.Background()

	ev := telemetryEvent("evt-1", baseTime, "sensor-1", 4.2)
	if err := r.Apply(ctx, ev); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	sensors := r.Sensors("filiale-001")
	if len(sensors) != 1 || sensors[0].SensorID != "sensor-1" || sensors[0].Metric != "air_temperature" {
		t.Fatalf("Sensors = %+v", sensors)
	}
	samples := r.SamplesFor("sensor-1", baseTime.Add(-time.Hour))
	if len(samples) != 1 || samples[0].Value != 4.2 {
		t.Fatalf("SamplesFor = %+v", samples)
	}
	site, _ := r.Site("filiale-001")
	if site.Status != domain.SiteOnline || !site.LastSeenAt.Equal(baseTime) {
		t.Errorf("site after apply = %+v", site)
	}
	health := r.Health()
	if health.EventsIngested != 1 || health.EventsRejected != 0 || health.Sensors != 1 || health.Assets != 0 {
		t.Errorf("Health = %+v", health)
	}
	if !health.LastEventAt.Equal(baseTime) {
		t.Errorf("LastEventAt = %v", health.LastEventAt)
	}
}

func TestApplyRejectsInvalidEvent(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	ctx := context.Background()

	ev := telemetryEvent("evt-bad", baseTime, "sensor-1", 4.2)
	ev.Confidence = 2.5
	if err := r.Apply(ctx, ev); err == nil {
		t.Fatal("expected validation error")
	}
	health := r.Health()
	if health.EventsRejected != 1 || health.EventsIngested != 0 {
		t.Errorf("Health = %+v", health)
	}
	if len(r.SamplesFor("sensor-1", time.Time{})) != 0 {
		t.Error("invalid event must not be buffered")
	}
}

func TestApplyHonoursCancelledContext(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Apply(ctx, telemetryEvent("evt-1", baseTime, "sensor-1", 4.2)); err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestApplyAssetSeenCreatesProvisionalAsset(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	if err := r.Apply(context.Background(), assetSeenEvent("evt-asset", baseTime, "asset-1")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	asset, ok := r.Asset("asset-1")
	if !ok {
		t.Fatal("asset not created")
	}
	if asset.Type != domain.AssetUnknown || asset.Criticality != domain.CriticalityLow {
		t.Errorf("provisional asset = %+v", asset)
	}
	if asset.Vendor != "TestVendor" || asset.Name != "asset-1" {
		t.Errorf("asset identity = %+v", asset)
	}
	if len(asset.NetworkIDs) != 2 {
		t.Errorf("network ids = %+v", asset.NetworkIDs)
	}
	if asset.Classification != domain.ClassificationAuto {
		t.Errorf("classification = %q", asset.Classification)
	}
}

func TestUpsertAssetPreservesOperatorFields(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	operatorAsset := domain.Asset{
		AssetID: "asset-1", SiteID: "filiale-001", ZoneID: "zone-ot", Name: "Kühlregler Pool 1",
		Type: domain.AssetRefrigerationController, Criticality: domain.CriticalityCritical,
		Confidence: 0.9, Classification: domain.ClassificationManual, OperatorNotes: "verified on site",
	}
	if err := r.UpsertAsset(operatorAsset); err != nil {
		t.Fatalf("UpsertAsset: %v", err)
	}
	if err := r.Apply(context.Background(), assetSeenEvent("evt-asset", baseTime.Add(time.Minute), "asset-1")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	asset, _ := r.Asset("asset-1")
	if asset.Name != "Kühlregler Pool 1" {
		t.Errorf("operator name overwritten: %q", asset.Name)
	}
	if asset.Criticality != domain.CriticalityCritical {
		t.Errorf("operator criticality overwritten: %q", asset.Criticality)
	}
	if asset.Type != domain.AssetRefrigerationController {
		t.Errorf("operator type overwritten: %q", asset.Type)
	}
	if asset.OperatorNotes != "verified on site" {
		t.Errorf("operator notes lost: %q", asset.OperatorNotes)
	}
	if !asset.LastSeenAt.Equal(baseTime.Add(time.Minute)) {
		t.Errorf("LastSeenAt = %v", asset.LastSeenAt)
	}
	if err := r.UpsertAsset(domain.Asset{AssetID: "bad id!", SiteID: "filiale-001"}); err == nil {
		t.Error("invalid asset must be rejected")
	}
}

func TestSamplesRingBufferAndFilters(t *testing.T) {
	clock := newFakeClock(baseTime)
	r := newTestRegistry(t, clock)
	r.SetSampleLimit(3)
	r.SetSampleLimit(0) // clamped to 1, then back to 3 below
	r.SetSampleLimit(3)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		at := baseTime.Add(time.Duration(i) * time.Minute)
		if err := r.Apply(ctx, telemetryEvent(fmt.Sprintf("evt-%d", i+1), at, "sensor-1", float64(i))); err != nil {
			t.Fatalf("Apply %d: %v", i, err)
		}
	}
	samples := r.SamplesFor("sensor-1", time.Time{})
	if len(samples) != 3 {
		t.Fatalf("ring buffer holds %d samples, want 3", len(samples))
	}
	if samples[0].Value != 2 || samples[2].Value != 4 {
		t.Errorf("ring buffer kept wrong samples: %+v", samples)
	}
	recent := r.SamplesFor("sensor-1", baseTime.Add(4*time.Minute))
	if len(recent) != 1 || recent[0].Value != 4 {
		t.Errorf("since filter = %+v", recent)
	}
	if got := r.Samples("filiale-001", time.Time{}); len(got) != 3 {
		t.Errorf("Samples site = %d, want 3", len(got))
	}
	if got := r.Samples("filiale-999", time.Time{}); len(got) != 0 {
		t.Errorf("Samples other site = %d, want 0", len(got))
	}
}

func TestEventsWindowFiltersAndLimit(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		at := baseTime.Add(time.Duration(i) * time.Minute)
		if err := r.Apply(ctx, telemetryEvent(fmt.Sprintf("evt-%d", i+1), at, "sensor-1", 4.2)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	}
	if err := r.Apply(ctx, flowEvent("evt-flow", baseTime.Add(3*time.Minute), "10.0.0.5", "10.0.0.9")); err != nil {
		t.Fatalf("Apply flow: %v", err)
	}

	events := r.Events(ports.EventQuery{})
	if len(events) != 4 {
		t.Fatalf("Events = %d, want 4", len(events))
	}
	if !events[0].ObservedAt.Equal(baseTime.Add(3 * time.Minute)) {
		t.Errorf("Events not newest first: %v", events[0].ObservedAt)
	}
	if got := r.Events(ports.EventQuery{Kind: domain.EventFlow}); len(got) != 1 {
		t.Errorf("flow events = %d, want 1", len(got))
	}
	if got := r.Events(ports.EventQuery{Limit: 1}); len(got) != 1 {
		t.Errorf("limited events = %d, want 1", len(got))
	}
	if got := r.Events(ports.EventQuery{Since: baseTime.Add(2 * time.Minute).Format(time.RFC3339)}); len(got) != 2 {
		t.Errorf("since events = %d, want 2", len(got))
	}
	if got := r.Events(ports.EventQuery{Since: "not-a-time"}); got != nil {
		t.Errorf("malformed time must yield nil, got %d events", len(got))
	}
}

func TestPeerBaseline(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	if r.KnownPeer("10.0.0.5", "10.0.0.9", "modbus_tcp") {
		t.Error("peer must be unknown initially")
	}
	r.ObservePeer("10.0.0.5", "10.0.0.9", "modbus_tcp")
	if !r.KnownPeer("10.0.0.5", "10.0.0.9", "modbus_tcp") {
		t.Error("peer must be known after observation")
	}
	if r.KnownPeer("10.0.0.9", "10.0.0.5", "modbus_tcp") {
		t.Error("peer relationships are directional")
	}
	if err := r.Apply(context.Background(), flowEvent("evt-flow", baseTime, "10.0.0.5", "10.0.0.9")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := r.PeerCount(); got != 1 {
		t.Errorf("PeerCount = %d, want 1", got)
	}
	if peers := r.Peers(); len(peers) != 1 {
		t.Errorf("Peers = %v", peers)
	}
}

func TestSetSiteStatus(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	r.SetSiteStatus("filiale-001", domain.SiteOffline)
	if status, ok := r.SiteStatus("filiale-001"); !ok || status != domain.SiteOffline {
		t.Errorf("SiteStatus = %q, %v", status, ok)
	}
	site, _ := r.Site("filiale-001")
	if site.Status != domain.SiteOffline {
		t.Errorf("site status = %q", site.Status)
	}
	r.SetSiteStatus("filiale-001", "nonsense")
	if status, _ := r.SiteStatus("filiale-001"); status != domain.SiteOffline {
		t.Errorf("invalid status must be ignored, got %q", status)
	}
	r.SetSiteStatus("unknown-site", domain.SiteOnline)
}

func TestAccessSessionsDerivedFromEvents(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	if err := r.Apply(context.Background(), accessEvent("evt-access", baseTime, "ses-1")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	sessions := r.AccessSessions("filiale-001", baseTime.Add(-time.Hour))
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	if sessions[0].SessionID != "ses-1" || sessions[0].Vendor != "ServiceCo" || !sessions[0].Observed {
		t.Errorf("session = %+v", sessions[0])
	}
	if got := r.AccessSessions("filiale-001", baseTime.Add(time.Minute)); len(got) != 0 {
		t.Errorf("since filter = %d sessions, want 0", len(got))
	}
}

func TestRegistryConcurrentAccess(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	ctx := context.Background()
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				id := fmt.Sprintf("evt-%d-%d", worker, i)
				at := baseTime.Add(time.Duration(i) * time.Second)
				if err := r.Apply(ctx, telemetryEvent(id, at, "sensor-1", float64(i))); err != nil {
					t.Errorf("Apply: %v", err)
					return
				}
				if i%5 == 0 {
					r.Samples("filiale-001", time.Time{})
					r.Events(ports.EventQuery{Limit: 10})
					r.Health()
					r.Assets("filiale-001")
				}
			}
		}(worker)
	}
	wg.Wait()
	if health := r.Health(); health.EventsIngested != 8*40 {
		t.Errorf("EventsIngested = %d, want %d", health.EventsIngested, 8*40)
	}
}
