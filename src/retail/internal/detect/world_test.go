package detect_test

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// baseTime is the deterministic evaluation instant of the test suite.
var baseTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

const (
	testSite   = domain.SiteID("filiale-001")
	testZone   = domain.ZoneID("zone-kuehl-nord")
	testAsset  = domain.AssetID("asset-kuehler-1")
	testSensor = domain.SensorID("sensor-temp-1")
)

var eventSeq uint64

func nextEventID(kind domain.EventKind) domain.EventID {
	return domain.EventID(fmt.Sprintf("evt_%s_%d", kind, atomic.AddUint64(&eventSeq, 1)))
}

// fakeClock is a deterministic ports.Clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t.UTC()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeWorld implements detect.World with synthetic data.
type fakeWorld struct {
	mu      sync.Mutex
	policy  domain.Policy
	sites   []domain.Site
	assets  []domain.Asset
	sensors []domain.Sensor
	samples map[domain.SensorID][]domain.Sample
	events  []domain.Event
	windows []domain.MaintenanceWindow
	peers   map[string]bool
	now     time.Time
}

func newWorld() *fakeWorld {
	world := &fakeWorld{
		policy:  domain.DefaultPolicy(testSite, baseTime),
		samples: make(map[domain.SensorID][]domain.Sample),
		peers:   make(map[string]bool),
		now:     baseTime,
	}
	world.sites = []domain.Site{{
		SiteID: testSite,
		Name:   "Markt Nord",
		Status: domain.SiteOnline,
		Zones: []domain.Zone{
			{ZoneID: testZone, SiteID: testSite, Name: "Kühl Nord", Kind: domain.ZoneOTProcess, Critical: true},
			{ZoneID: "zone-retail-it", SiteID: testSite, Name: "Retail IT", Kind: domain.ZoneRetailIT},
			{ZoneID: "zone-management", SiteID: testSite, Name: "Management", Kind: domain.ZoneManagement},
			{ZoneID: "zone-extern", SiteID: testSite, Name: "Externer Wartungszugang", Kind: domain.ZoneExternalMaintenance},
		},
	}}
	return world
}

func (w *fakeWorld) Policy() domain.Policy {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.policy
}

func (w *fakeWorld) setPolicy(update func(*domain.Policy)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	update(&w.policy)
}

func (w *fakeWorld) Sites() []domain.Site {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]domain.Site(nil), w.sites...)
}

func (w *fakeWorld) Assets(site domain.SiteID) []domain.Asset {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]domain.Asset, 0, len(w.assets))
	for _, asset := range w.assets {
		if asset.SiteID == site {
			out = append(out, asset)
		}
	}
	return out
}

func (w *fakeWorld) Asset(id domain.AssetID) (domain.Asset, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, asset := range w.assets {
		if asset.AssetID == id {
			return asset, true
		}
	}
	return domain.Asset{}, false
}

func (w *fakeWorld) Sensors(site domain.SiteID) []domain.Sensor {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]domain.Sensor, 0, len(w.sensors))
	for _, sensor := range w.sensors {
		if sensor.SiteID == site {
			out = append(out, sensor)
		}
	}
	return out
}

func (w *fakeWorld) Samples(site domain.SiteID, since time.Time) []domain.Sample {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]domain.Sample, 0, 8)
	for _, samples := range w.samples {
		for _, sample := range samples {
			if sample.SiteID != site {
				continue
			}
			if !since.IsZero() && sample.At.Before(since) {
				continue
			}
			out = append(out, sample)
		}
	}
	return out
}

func (w *fakeWorld) SamplesFor(sensor domain.SensorID, since time.Time) []domain.Sample {
	w.mu.Lock()
	defer w.mu.Unlock()
	samples := w.samples[sensor]
	out := make([]domain.Sample, 0, len(samples))
	for _, sample := range samples {
		if !since.IsZero() && sample.At.Before(since) {
			continue
		}
		out = append(out, sample)
	}
	return out
}

func (w *fakeWorld) Events(q ports.EventQuery) []domain.Event {
	w.mu.Lock()
	defer w.mu.Unlock()
	var since, until time.Time
	if q.Since != "" {
		since, _ = time.Parse(time.RFC3339, q.Since)
	}
	if q.Until != "" {
		until, _ = time.Parse(time.RFC3339, q.Until)
	}
	out := make([]domain.Event, 0, len(w.events))
	for _, ev := range w.events {
		if q.SiteID != "" && ev.SiteID != q.SiteID {
			continue
		}
		if q.Kind != "" && ev.Kind != q.Kind {
			continue
		}
		if q.AssetID != "" && ev.AssetID != q.AssetID {
			continue
		}
		if q.SensorID != "" && ev.SensorID != q.SensorID {
			continue
		}
		if !since.IsZero() && ev.ObservedAt.Before(since) {
			continue
		}
		if !until.IsZero() && !ev.ObservedAt.Before(until) {
			continue
		}
		out = append(out, ev)
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out
}

func (w *fakeWorld) WindowsAt(site domain.SiteID, at time.Time) []domain.MaintenanceWindow {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]domain.MaintenanceWindow, 0, 2)
	for _, window := range w.windows {
		if window.SiteID == site && window.Contains(at) {
			out = append(out, window)
		}
	}
	return out
}

func peerKey(src, dst, protocol string) string {
	return src + "|" + dst + "|" + protocol
}

func (w *fakeWorld) KnownPeer(src, dst, protocol string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.peers[peerKey(src, dst, protocol)]
}

func (w *fakeWorld) ObservePeer(src, dst, protocol string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.peers[peerKey(src, dst, protocol)] = true
}

func (w *fakeWorld) Now() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.now
}

func (w *fakeWorld) addAsset(asset domain.Asset) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.assets = append(w.assets, asset)
}

func (w *fakeWorld) addSensor(sensor domain.Sensor) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sensors = append(w.sensors, sensor)
}

func (w *fakeWorld) addSample(sample domain.Sample) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.samples[sample.SensorID] = append(w.samples[sample.SensorID], sample)
}

func (w *fakeWorld) addEvent(ev domain.Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, ev)
}

func (w *fakeWorld) addWindow(window domain.MaintenanceWindow) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.windows = append(w.windows, window)
}

func newTestEngine(world *fakeWorld) *detect.Engine {
	return detect.NewEngine(world, newFakeClock(world.now))
}

func f64(value float64) *float64 { return &value }

// assetFixture is the standard OT controller of the tests.
func assetFixture() domain.Asset {
	return domain.Asset{
		AssetID:             testAsset,
		SiteID:              testSite,
		ZoneID:              testZone,
		Name:                "Kälteregler Nord",
		Type:                domain.AssetRefrigerationController,
		Vendor:              "TestVendor",
		Criticality:         domain.CriticalityCritical,
		Confidence:          0.9,
		Classification:      domain.ClassificationManual,
		ManagementInterface: true,
		Lifecycle:           domain.LifecycleActive,
		NetworkIDs: []domain.NetworkIdentifier{
			{Kind: domain.NetIDIP, Value: "10.0.0.5", Source: "test", Confidence: 0.9},
		},
	}
}

func sensorFixture() domain.Sensor {
	return domain.Sensor{
		SensorID: testSensor,
		SiteID:   testSite,
		AssetID:  testAsset,
		ZoneID:   testZone,
		Name:     "Lufttemperatur Nord",
		Metric:   "air_temperature",
		Unit:     domain.UnitCelsius,
		Critical: true,
	}
}

// temperatureLimit is a helper for operator policy fixtures.
func temperatureLimit(zone domain.ZoneID, metric string) domain.TemperatureLimit {
	return domain.TemperatureLimit{ZoneID: zone, Metric: metric}
}

// telemetry builds a valid telemetry event with good quality.
func telemetry(sensor domain.SensorID, value float64, at time.Time) domain.Event {
	return telemetryFull(sensor, testZone, testAsset, "air_temperature", value, domain.UnitCelsius, domain.QualityGood, "", nil, at)
}

func telemetryFull(sensor domain.SensorID, zone domain.ZoneID, asset domain.AssetID, metric string, value float64, unit domain.Unit, quality domain.Quality, mode string, setpoint *float64, at time.Time) domain.Event {
	return domain.Event{
		EventID:     nextEventID(domain.EventTelemetry),
		Kind:        domain.EventTelemetry,
		SiteID:      testSite,
		ZoneID:      zone,
		AssetID:     asset,
		SensorID:    sensor,
		ObservedAt:  at,
		ReceivedAt:  at,
		Source:      "test.simulator",
		Collection:  "read_only_poll",
		Protocol:    "modbus_tcp",
		Confidence:  0.9,
		Measurement: &domain.Measurement{Value: value, Unit: unit, Quality: quality, Metric: metric, Mode: mode, Setpoint: setpoint, ObservedAt: at},
	}
}

func flow(src, dst string, dstPort int, protocol string, at time.Time) domain.Event {
	return domain.Event{
		EventID:    nextEventID(domain.EventFlow),
		Kind:       domain.EventFlow,
		SiteID:     testSite,
		ObservedAt: at,
		ReceivedAt: at,
		Source:     "test.flow",
		Collection: "passive_tap",
		Protocol:   protocol,
		Confidence: 0.8,
		Flow:       &domain.FlowMeta{SrcIP: src, DstIP: dst, DstPort: dstPort, Protocol: protocol},
	}
}

func accessEvent(access domain.AccessMeta, at time.Time) domain.Event {
	return domain.Event{
		EventID:    nextEventID(domain.EventAccess),
		Kind:       domain.EventAccess,
		SiteID:     testSite,
		ObservedAt: at,
		ReceivedAt: at,
		Source:     "test.access",
		Collection: "passive_tap",
		Confidence: 0.8,
		Access:     &access,
	}
}

func writeAttempt(attempt domain.WriteAttempt, at time.Time) domain.Event {
	return domain.Event{
		EventID:      nextEventID(domain.EventWriteAttempt),
		Kind:         domain.EventWriteAttempt,
		SiteID:       testSite,
		ObservedAt:   at,
		ReceivedAt:   at,
		Source:       "test.modbus_tap",
		Collection:   "passive_tap",
		Protocol:     attempt.Protocol,
		Confidence:   0.9,
		WriteAttempt: &attempt,
	}
}

func assetSeen(assetID domain.AssetID, ip, protocol string, at time.Time) domain.Event {
	return domain.Event{
		EventID:    nextEventID(domain.EventAssetSeen),
		Kind:       domain.EventAssetSeen,
		SiteID:     testSite,
		ZoneID:     testZone,
		AssetID:    assetID,
		ObservedAt: at,
		ReceivedAt: at,
		Source:     "test.discovery",
		Collection: "passive_tap",
		Protocol:   protocol,
		Confidence: 0.6,
		Device:     &domain.DeviceMeta{IP: ip, MAC: "aa:bb:cc:dd:ee:ff", Vendor: "TestVendor"},
	}
}

func integrityEvent(assetID domain.AssetID, integrity domain.IntegrityMeta, at time.Time) domain.Event {
	return domain.Event{
		EventID:    nextEventID(domain.EventIntegrity),
		Kind:       domain.EventIntegrity,
		SiteID:     testSite,
		ZoneID:     testZone,
		AssetID:    assetID,
		ObservedAt: at,
		ReceivedAt: at,
		Source:     "test.integrity",
		Collection: "operator_export",
		Confidence: 0.9,
		Integrity:  &integrity,
	}
}

func maintenanceWindow(id domain.MaintenanceWindowID, start, end time.Time, asset domain.AssetID) domain.MaintenanceWindow {
	return domain.MaintenanceWindow{
		WindowID:       id,
		SiteID:         testSite,
		ZoneIDs:        []domain.ZoneID{testZone},
		Vendor:         "Kältetechnik Müller",
		StartsAt:       start,
		EndsAt:         end,
		TargetAssetIDs: []domain.AssetID{asset},
		Status:         domain.WindowActive,
		CreatedAt:      start.Add(-time.Hour),
		CreatedBy:      domain.UserID("admin-01"),
	}
}

// Assertions -----------------------------------------------------------------

func alertsFor(alerts []domain.Alert, ruleID domain.RuleID) []domain.Alert {
	out := make([]domain.Alert, 0, len(alerts))
	for _, alert := range alerts {
		if alert.RuleID == ruleID {
			out = append(out, alert)
		}
	}
	return out
}

func requireAlert(t *testing.T, alerts []domain.Alert, ruleID domain.RuleID) domain.Alert {
	t.Helper()
	matched := alertsFor(alerts, ruleID)
	if len(matched) == 0 {
		t.Fatalf("expected alert for rule %q, got rules %v", ruleID, ruleIDs(alerts))
	}
	requireValidAlert(t, matched[0])
	return matched[0]
}

func requireNoAlert(t *testing.T, alerts []domain.Alert, ruleID domain.RuleID) {
	t.Helper()
	if matched := alertsFor(alerts, ruleID); len(matched) > 0 {
		t.Fatalf("expected no alert for rule %q, got %+v", ruleID, matched[0])
	}
}

func requireNoAlerts(t *testing.T, alerts []domain.Alert) {
	t.Helper()
	if len(alerts) > 0 {
		t.Fatalf("expected no alerts, got rules %v", ruleIDs(alerts))
	}
}

func requireNoCritical(t *testing.T, alerts []domain.Alert) {
	t.Helper()
	for _, alert := range alerts {
		if alert.Severity == domain.SeverityCritical {
			t.Fatalf("single-rule alert must not be critical: %+v", alert)
		}
	}
}

func requireValidAlert(t *testing.T, alert domain.Alert) {
	t.Helper()
	if err := alert.Validate(); err != nil {
		t.Fatalf("invalid alert: %v", err)
	}
	if alert.RuleVersion != "1" {
		t.Fatalf("expected rule version 1, got %q", alert.RuleVersion)
	}
	if alert.Confidence < 0 || alert.Confidence > 1 {
		t.Fatalf("confidence outside [0,1]: %v", alert.Confidence)
	}
	if len(alert.Evidence) == 0 {
		t.Fatalf("alert %q has no evidence", alert.RuleID)
	}
	for _, evidence := range alert.Evidence {
		if evidence.Description == "" || evidence.Kind == "" || evidence.At.IsZero() {
			t.Fatalf("incomplete evidence in alert %q: %+v", alert.RuleID, evidence)
		}
	}
	if alert.Correlation == nil {
		t.Fatalf("alert %q has no correlation summary", alert.RuleID)
	}
	if len(alert.Correlation.ObservedFacts) == 0 || alert.Correlation.Hypothesis == "" {
		t.Fatalf("alert %q does not separate facts and hypothesis", alert.RuleID)
	}
	if len(alert.Correlation.RecommendedChecks) == 0 {
		t.Fatalf("alert %q has no recommended checks", alert.RuleID)
	}
	if !strings.Contains(alert.Summary, "Beobachtung:") || !strings.Contains(alert.Summary, "Hypothese:") {
		t.Fatalf("alert summary does not separate observation/hypothesis: %q", alert.Summary)
	}
	if !strings.Contains(alert.Summary, "Empfohlene Prüfung:") {
		t.Fatalf("alert summary has no recommended check: %q", alert.Summary)
	}
	if !strings.Contains(string(alert.DedupKey), string(alert.RuleID)) {
		t.Fatalf("dedup key %q does not start with rule id %q", alert.DedupKey, alert.RuleID)
	}
	if len(alert.SafetyConstraints) == 0 {
		t.Fatalf("alert %q has no safety constraints", alert.RuleID)
	}
}

func ruleIDs(alerts []domain.Alert) []domain.RuleID {
	out := make([]domain.RuleID, 0, len(alerts))
	for _, alert := range alerts {
		out = append(out, alert.RuleID)
	}
	return out
}
