package correlate_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/correlate"
	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

var baseTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

const (
	testSite  = domain.SiteID("filiale-001")
	testZone  = domain.ZoneID("zone-kuehl-nord")
	testAsset = domain.AssetID("asset-kuehler-1")
)

var alertSeq uint64

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

// fakeWorld implements correlate.World with synthetic data.
type fakeWorld struct {
	mu        sync.Mutex
	sites     []domain.Site
	assets    []domain.Asset
	sensors   []domain.Sensor
	windows   []domain.MaintenanceWindow
	incidents []domain.Incident
	now       time.Time
}

func newWorld() *fakeWorld {
	return &fakeWorld{
		sites: []domain.Site{{
			SiteID: testSite,
			Name:   "Markt Nord",
			Status: domain.SiteOnline,
			Zones: []domain.Zone{
				{ZoneID: testZone, SiteID: testSite, Name: "Kühl Nord", Kind: domain.ZoneOTProcess, Critical: true},
				{ZoneID: "zone-retail-it", SiteID: testSite, Name: "Retail IT", Kind: domain.ZoneRetailIT},
				{ZoneID: "zone-management", SiteID: testSite, Name: "Management", Kind: domain.ZoneManagement},
			},
		}},
		now: baseTime,
	}
}

func (w *fakeWorld) Sites() []domain.Site {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]domain.Site(nil), w.sites...)
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

func (w *fakeWorld) Incidents(site domain.SiteID) []domain.Incident {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]domain.Incident, 0, len(w.incidents))
	for _, incident := range w.incidents {
		if incident.SiteID == site {
			out = append(out, incident)
		}
	}
	return out
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

func (w *fakeWorld) addWindow(window domain.MaintenanceWindow) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.windows = append(w.windows, window)
}

func (w *fakeWorld) addIncident(incident domain.Incident) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.incidents = append(w.incidents, incident)
}

func newTestEngine(world *fakeWorld, now time.Time) *correlate.Engine {
	return correlate.NewEngine(world, newFakeClock(now))
}

// buildAlert creates a valid rule alert with a stable unique dedup key.
func buildAlert(ruleID domain.RuleID, at time.Time, severity domain.Severity, assets ...domain.AssetID) domain.Alert {
	spec, ok := rules.ByID(ruleID)
	if !ok {
		panic("test: unknown rule " + string(ruleID))
	}
	alertID := domain.AlertID(fmt.Sprintf("alr_test_%d", atomic.AddUint64(&alertSeq, 1)))
	return domain.Alert{
		AlertID:     alertID,
		SiteID:      testSite,
		AssetIDs:    assets,
		ZoneIDs:     []domain.ZoneID{testZone},
		Category:    spec.Category,
		Severity:    severity,
		Confidence:  0.7,
		Title:       spec.Name,
		Summary:     "Beobachtung: Testfakt. Hypothese: Testhypothese. Empfohlene Prüfung: Testprüfung.",
		RuleID:      ruleID,
		RuleVersion: "1",
		FirstSeenAt: at,
		LastSeenAt:  at,
		Status:      domain.AlertOpen,
		Evidence:    []domain.Evidence{{Kind: "event", Description: "Testfakt", At: at, Source: "test", Confidence: 0.8}},
		Correlation: &domain.CorrelationSummary{ObservedFacts: []string{"Testfakt"}, Hypothesis: "Testhypothese", RecommendedChecks: []string{"Testprüfung"}},
		DedupKey:    rules.DedupKey(ruleID, string(testSite), string(alertID)),
		CreatedAt:   at,
		UpdatedAt:   at,
	}
}

// thermalTrail builds the three independent indicators of
// chain-thermal-manipulation: an off-window access, a setpoint deviation and a
// thermal trend.
func thermalTrail(now time.Time) []domain.Alert {
	return []domain.Alert{
		buildAlert(rules.IDAccessOffWindow, now.Add(-10*time.Minute), domain.SeverityMedium, testAsset),
		buildAlert(rules.IDThermalSetpoint, now.Add(-8*time.Minute), domain.SeverityHigh, testAsset),
		buildAlert(rules.IDThermalRate, now.Add(-5*time.Minute), domain.SeverityHigh, testAsset),
	}
}

func assetFixture() domain.Asset {
	return domain.Asset{
		AssetID: testAsset, SiteID: testSite, ZoneID: testZone, Name: "Kälteregler Nord",
		Type: domain.AssetRefrigerationController, Criticality: domain.CriticalityCritical,
		Confidence: 0.9, Classification: domain.ClassificationManual,
		NetworkIDs: []domain.NetworkIdentifier{{Kind: domain.NetIDIP, Value: "10.0.0.5", Source: "test", Confidence: 0.9}},
	}
}

func sensorFixture() domain.Sensor {
	return domain.Sensor{
		SensorID: "sensor-temp-1", SiteID: testSite, AssetID: testAsset, ZoneID: testZone,
		Name: "Lufttemperatur Nord", Metric: "air_temperature", Unit: domain.UnitCelsius, Critical: true,
	}
}

func windowFixture(start, end time.Time) domain.MaintenanceWindow {
	return domain.MaintenanceWindow{
		WindowID: "win-1", SiteID: testSite, ZoneIDs: []domain.ZoneID{testZone}, Vendor: "Kältetechnik Müller",
		StartsAt: start, EndsAt: end, Status: domain.WindowActive, CreatedAt: start.Add(-time.Hour), CreatedBy: "admin-01",
	}
}

// existingIncident creates a stored incident for dedup tests.
func existingIncident(chainID string, status domain.IncidentStatus, lastSeen time.Time) domain.Incident {
	return domain.Incident{
		IncidentID:  "inc_existing",
		SiteID:      testSite,
		Title:       "Bestehender Fall",
		Severity:    domain.SeverityHigh,
		Status:      status,
		FirstSeenAt: lastSeen.Add(-time.Hour),
		LastSeenAt:  lastSeen,
		Summary:     "Bestehender Fall.",
		Correlation: &domain.CorrelationSummary{ChainID: chainID, ObservedFacts: []string{"Altfakt"}, Hypothesis: "Althypothese"},
		CreatedAt:   lastSeen.Add(-time.Hour),
		UpdatedAt:   lastSeen,
	}
}

// Assertions -----------------------------------------------------------------

func requireIncident(t *testing.T, incidents []domain.Incident, chainID string) domain.Incident {
	t.Helper()
	for _, incident := range incidents {
		if incident.Correlation == nil || incident.Correlation.ChainID != chainID {
			continue
		}
		if err := incident.Validate(); err != nil {
			t.Fatalf("invalid incident: %v", err)
		}
		if incident.Correlation.Hypothesis == "" || len(incident.Correlation.ObservedFacts) == 0 {
			t.Fatalf("incident does not separate facts and hypothesis: %+v", incident)
		}
		if len(incident.Correlation.AlternativeExplanations) == 0 {
			t.Fatalf("incident has no alternative explanations: %+v", incident.Correlation)
		}
		if len(incident.Correlation.RecommendedChecks) == 0 {
			t.Fatalf("incident has no recommended checks: %+v", incident.Correlation)
		}
		if len(incident.Correlation.Indicators) < 3 {
			t.Fatalf("incident escalated with %d indicators", len(incident.Correlation.Indicators))
		}
		if incident.Status != domain.IncidentOpen {
			t.Fatalf("new incident must be open, got %s", incident.Status)
		}
		return incident
	}
	t.Fatalf("expected incident for chain %q, got %d incidents", chainID, len(incidents))
	return domain.Incident{}
}

func requireNoIncidents(t *testing.T, incidents []domain.Incident) {
	t.Helper()
	if len(incidents) > 0 {
		t.Fatalf("expected no incidents, got %+v", incidents)
	}
}

func requireUpdate(t *testing.T, updates []domain.Alert, ruleID domain.RuleID) domain.Alert {
	t.Helper()
	for _, update := range updates {
		if update.RuleID == ruleID {
			return update
		}
	}
	t.Fatalf("expected an update for rule %q, got %d updates", ruleID, len(updates))
	return domain.Alert{}
}

func alertIDs(alerts []domain.Alert) []domain.AlertID {
	out := make([]domain.AlertID, 0, len(alerts))
	for _, alert := range alerts {
		out = append(out, alert.AlertID)
	}
	return out
}
