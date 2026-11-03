package state

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestAssetLimitRejectsNewAssetsOnly(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	r.SetAssetLimit(2)
	if r.assetLimit != 2 {
		t.Fatalf("assetLimit = %d, want 2", r.assetLimit)
	}
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		event := assetSeenEvent(fmt.Sprintf("evt-a%d", i), baseTime, domain.AssetID(fmt.Sprintf("asset-%d", i)))
		if err := r.Apply(ctx, event); err != nil {
			t.Fatalf("Apply asset %d: %v", i, err)
		}
	}
	if got := len(r.Assets("filiale-001")); got != 2 {
		t.Fatalf("assets = %d, want 2", got)
	}

	// A third new asset is rejected, counted and does not abort the event.
	third := assetSeenEvent("evt-a3", baseTime, "asset-3")
	if err := r.Apply(ctx, third); err != nil {
		t.Fatalf("Apply beyond limit must not fail the event: %v", err)
	}
	if got := len(r.Assets("filiale-001")); got != 2 {
		t.Errorf("assets after limit = %d, want 2", got)
	}
	health := r.Health()
	if health.AssetsDropped != 1 {
		t.Errorf("AssetsDropped = %d, want 1", health.AssetsDropped)
	}
	if health.EventsIngested != 3 {
		t.Errorf("EventsIngested = %d, want 3 (event still processed)", health.EventsIngested)
	}

	// Re-observing an existing asset at the limit must merge, not drop.
	again := assetSeenEvent("evt-a1", baseTime.Add(time.Minute), "asset-0")
	if err := r.Apply(ctx, again); err != nil {
		t.Fatalf("Apply existing asset: %v", err)
	}
	if got := r.Health().AssetsDropped; got != 1 {
		t.Errorf("AssetsDropped after re-observation = %d, want 1", got)
	}

	// The explicit upsert path reports the capacity error.
	if err := r.UpsertAsset(domain.Asset{
		AssetID: "asset-4", SiteID: "filiale-001", ZoneID: "zone-ot", Name: "Extra",
		Type: domain.AssetPL, Criticality: domain.CriticalityMedium, Confidence: 1,
		Classification: domain.ClassificationManual,
	}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("UpsertAsset beyond limit = %v, want ErrCapacity", err)
	}
}

func TestSensorLimitDropsNewSensorsAndSamples(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	r.SetSensorLimit(2)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if err := r.Apply(ctx, telemetryEvent(fmt.Sprintf("evt-s%d", i), baseTime, domain.SensorID(fmt.Sprintf("sensor-%d", i)), 4.2)); err != nil {
			t.Fatalf("Apply sensor %d: %v", i, err)
		}
	}
	if got := len(r.Sensors("filiale-001")); got != 2 {
		t.Fatalf("sensors = %d, want 2", got)
	}

	// A third sensor must not be tracked and its sample must not be buffered,
	// otherwise a hostile event stream could grow the sample map without bound.
	if err := r.Apply(ctx, telemetryEvent("evt-s3", baseTime, "sensor-3", 4.2)); err != nil {
		t.Fatalf("Apply beyond sensor limit must not fail the event: %v", err)
	}
	if got := len(r.Sensors("filiale-001")); got != 2 {
		t.Errorf("sensors after limit = %d, want 2", got)
	}
	if samples := r.SamplesFor("sensor-3", time.Time{}); len(samples) != 0 {
		t.Errorf("samples for rejected sensor = %d, want 0", len(samples))
	}
	health := r.Health()
	if health.SensorsDropped != 1 {
		t.Errorf("SensorsDropped = %d, want 1", health.SensorsDropped)
	}
	if health.EventsIngested != 3 {
		t.Errorf("EventsIngested = %d, want 3", health.EventsIngested)
	}

	if err := r.UpsertSensor(domain.Sensor{
		SensorID: "sensor-4", SiteID: "filiale-001", ZoneID: "zone-ot", Name: "Extra",
		Metric: "air_temperature", Unit: domain.UnitCelsius,
	}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("UpsertSensor beyond limit = %v, want ErrCapacity", err)
	}
}

func TestLimitsDefaultAndClamping(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	health := r.Health()
	if health.AssetsDropped != 0 || health.SensorsDropped != 0 {
		t.Errorf("initial dropped counters = %+v", health)
	}
	r.SetAssetLimit(0)
	if r.assetLimit != 1 {
		t.Errorf("clamped asset limit = %d, want 1", r.assetLimit)
	}
	r.SetSensorLimit(1_000_000)
	if r.sensorLimit != 100000 {
		t.Errorf("clamped sensor limit = %d, want 100000", r.sensorLimit)
	}
}
