package store

import (
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// fakeClock is a deterministic ports.Clock for the store tests.
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

func testEvent(id string, at time.Time) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(id),
		Kind:       domain.EventTelemetry,
		SiteID:     domain.SiteID("filiale-001"),
		ZoneID:     domain.ZoneID("zone-ot"),
		AssetID:    domain.AssetID("asset-1"),
		SensorID:   domain.SensorID("sensor-1"),
		ObservedAt: at,
		ReceivedAt: at,
		Source:     "modbus.pool1",
		Collection: "read_only_poll",
		Confidence: 0.9,
		Measurement: &domain.Measurement{
			Value:      4.2,
			Unit:       domain.UnitCelsius,
			Quality:    domain.QualityGood,
			Metric:     "air_temperature",
			ObservedAt: at,
		},
	}
}

func testAlert(id, dedup string, status domain.AlertStatus, severity domain.Severity, at time.Time) domain.Alert {
	return domain.Alert{
		AlertID:     domain.AlertID(id),
		SiteID:      domain.SiteID("filiale-001"),
		Category:    domain.CategoryThermal,
		Severity:    severity,
		Confidence:  0.8,
		Title:       "Temperature above limit",
		Summary:     "Zone 1 exceeded the configured maximum for 5 minutes.",
		RuleID:      domain.RuleID("retail.thermal.limit"),
		RuleVersion: "1",
		FirstSeenAt: at,
		LastSeenAt:  at,
		Status:      status,
		DedupKey:    dedup,
		Evidence:    []domain.Evidence{},
		CreatedAt:   at,
		UpdatedAt:   at,
	}
}

func testAuditEntry(action, objectID string, at time.Time) domain.AuditEntry {
	return domain.AuditEntry{
		At:         at,
		Actor:      "admin",
		Role:       "admin",
		Action:     action,
		ObjectType: "policy",
		ObjectID:   objectID,
	}
}

// mustOpenEventLog opens an event log in dir with the given clock and closes it
// at test cleanup.
func mustOpenEventLog(t *testing.T, dir string, clock ports.Clock, maxMB int64, retentionDays int) *EventLog {
	t.Helper()
	log, err := OpenEventLog(Options{Dir: dir, MaxMB: maxMB, RetentionDays: retentionDays, Clock: clock})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	t.Cleanup(func() {
		if cerr := log.Close(); cerr != nil {
			t.Errorf("EventLog.Close: %v", cerr)
		}
	})
	return log
}
