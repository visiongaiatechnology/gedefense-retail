package demo

import (
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestSiteAndZonesValidate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	site := Site(now)
	if err := site.Validate(); err != nil {
		t.Fatalf("site invalid: %v", err)
	}
	if len(site.Zones) < 5 {
		t.Fatalf("expected at least 5 zones, got %d", len(site.Zones))
	}
}

func TestPolicyValidate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	if err := Policy(now).Validate(); err != nil {
		t.Fatalf("policy invalid: %v", err)
	}
}

func TestWindowsValidate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, w := range Windows(now) {
		if err := w.Validate(); err != nil {
			t.Fatalf("window %q invalid: %v", w.WindowID, err)
		}
	}
}

func TestEventsValidate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, scenario := range Scenarios() {
		events := Events(now, scenario)
		if len(events) == 0 {
			t.Fatalf("%s: no events generated", scenario)
		}
		for i, ev := range events {
			if err := ev.Validate(); err != nil {
				t.Fatalf("%s: event %d (%s, kind=%s) invalid: %v", scenario, i, ev.EventID, ev.Kind, err)
			}
			if ev.ObservedAt.After(now.Add(time.Minute)) {
				t.Fatalf("%s: event %d observed in the future", scenario, i)
			}
		}
	}
}

func TestEventsAssetsAndSensors(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, a := range Assets(now) {
		if err := a.Validate(); err != nil {
			t.Fatalf("asset %q invalid: %v", a.AssetID, err)
		}
	}
	for _, s := range Sensors(now) {
		if err := s.Validate(); err != nil {
			t.Fatalf("sensor %q invalid: %v", s.SensorID, err)
		}
	}
}

func TestAttackScenarioContainsObservationSignals(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	var access, writeAttempt, httpsFlow int
	for _, ev := range Events(now, ScenarioAttack) {
		switch ev.Kind {
		case domain.EventAccess:
			access++
		case domain.EventWriteAttempt:
			writeAttempt++
		case domain.EventFlow:
			if ev.Flow != nil && ev.Flow.Protocol == "https" {
				httpsFlow++
			}
		}
	}
	if access == 0 || writeAttempt == 0 || httpsFlow == 0 {
		t.Fatalf("attack scenario misses signals: access=%d write=%d https=%d", access, writeAttempt, httpsFlow)
	}
	// The normal scenario must not fabricate an attack.
	for _, ev := range Events(now, ScenarioNormal) {
		if ev.Kind == domain.EventAccess || ev.Kind == domain.EventWriteAttempt {
			t.Fatalf("normal scenario must not contain access/write_attempt events")
		}
	}
}
