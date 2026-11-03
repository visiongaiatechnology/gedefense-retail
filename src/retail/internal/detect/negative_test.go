package detect_test

import (
	"context"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// TestNegativeCalmCoolingOperation proves that a quiet, correctly configured
// cooling operation does not produce any alert.
func TestNegativeCalmCoolingOperation(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	world.addSensor(sensorFixture())
	values := []float64{3.1, 3.0, 2.9, 3.0, 3.1, 3.0}
	for i, value := range values {
		world.addSample(domain.Sample{
			SensorID: testSensor, SiteID: testSite, ZoneID: testZone, AssetID: testAsset,
			Metric: "air_temperature", Unit: domain.UnitCelsius,
			At: baseTime.Add(-time.Duration(len(values)-i) * 5 * time.Minute), Value: value, Quality: domain.QualityGood,
		})
	}
	engine := newTestEngine(world)
	for _, offset := range []time.Duration{-20 * time.Minute, -10 * time.Minute, 0} {
		alerts := engine.EvaluateEvent(context.Background(), telemetry(testSensor, 3.0, baseTime.Add(offset)))
		requireNoAlerts(t, alerts)
	}
	requireNoAlerts(t, engine.EvaluateTick(context.Background()))
}

// TestNegativeDefrostDoorLoadingNotCritical covers the mandatory false-positive
// boundaries: normal defrost, door and loading phases must never become critical
// and must not produce a rate alert.
func TestNegativeDefrostDoorLoadingNotCritical(t *testing.T) {
	t.Parallel()
	modes := []string{"defrost", "door_open", "loading"}
	for _, mode := range modes {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			world := newWorld()
			world.addSensor(sensorFixture())
			world.setPolicy(func(p *domain.Policy) {
				p.Temperature.Limits = []domain.TemperatureLimit{{
					ZoneID: testZone, Metric: "air_temperature",
					MinC: f64(0), MaxC: f64(4), MaxRateCPerMin: f64(0.5), SetpointToleranceC: f64(0.5),
				}}
			})
			world.addSample(domain.Sample{
				SensorID: testSensor, SiteID: testSite, ZoneID: testZone, AssetID: testAsset,
				Metric: "air_temperature", Unit: domain.UnitCelsius,
				At: baseTime.Add(-4 * time.Minute), Value: 1.0, Quality: domain.QualityGood, Mode: mode,
			})
			engine := newTestEngine(world)
			ev := telemetryFull(testSensor, testZone, testAsset, "air_temperature", 9.0, domain.UnitCelsius, domain.QualityGood, mode, nil, baseTime)
			alerts := engine.EvaluateEvent(context.Background(), ev)
			requireNoCritical(t, alerts)
			requireNoAlert(t, alerts, rules.IDThermalRate)
			if matched := alertsFor(alerts, rules.IDThermalLimit); len(matched) > 0 {
				if matched[0].Severity.Rank() > domain.SeverityMedium.Rank() {
					t.Fatalf("normal %s phase must not exceed medium severity: %s", mode, matched[0].Severity)
				}
			}
		})
	}
}

// TestNegativeNightDefrost proves that a scheduled defrost inside the configured
// limits produces no alert at all.
func TestNegativeNightDefrost(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addSensor(sensorFixture())
	world.setPolicy(func(p *domain.Policy) {
		p.Temperature.Limits = []domain.TemperatureLimit{{
			ZoneID: testZone, Metric: "air_temperature", MinC: f64(0), MaxC: f64(4), MaxRateCPerMin: f64(0.5),
		}}
	})
	for i := 0; i < 4; i++ {
		world.addSample(domain.Sample{
			SensorID: testSensor, SiteID: testSite, ZoneID: testZone, AssetID: testAsset,
			Metric: "air_temperature", Unit: domain.UnitCelsius,
			At: baseTime.Add(-time.Duration(4-i) * 5 * time.Minute), Value: 2.5, Quality: domain.QualityGood, Mode: "defrost",
		})
	}
	engine := newTestEngine(world)
	ev := telemetryFull(testSensor, testZone, testAsset, "air_temperature", 3.0, domain.UnitCelsius, domain.QualityGood, "defrost", nil, baseTime)
	requireNoAlerts(t, engine.EvaluateEvent(context.Background(), ev))
}

// TestNegativeMissingPolicyLimits proves the hard product rule: without
// operator-configured limits there is no temperature alerting at all.
func TestNegativeMissingPolicyLimits(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addSensor(sensorFixture())
	engine := newTestEngine(world)
	alerts := engine.EvaluateEvent(context.Background(), telemetry(testSensor, 12.0, baseTime))
	requireNoAlerts(t, alerts)
	for _, alert := range alerts {
		if alert.Category == domain.CategoryThermal {
			t.Fatalf("no thermal alert may exist without operator limits: %+v", alert)
		}
	}
}

// TestNegativeFrozenVsOutage distinguishes a frozen value from a missing
// telemetry stream: the same physical symptom must produce different signals.
func TestNegativeFrozenVsOutage(t *testing.T) {
	t.Parallel()
	t.Run("frozen value not a gap", func(t *testing.T) {
		t.Parallel()
		world := newWorld()
		world.addSensor(sensorFixture())
		world.setPolicy(func(p *domain.Policy) { p.DataQuality.FrozenValueWindowS = 1800 })
		for i := 0; i < 6; i++ {
			world.addSample(domain.Sample{
				SensorID: testSensor, SiteID: testSite, ZoneID: testZone, AssetID: testAsset,
				Metric: "air_temperature", Unit: domain.UnitCelsius,
				At: baseTime.Add(-time.Duration(6-i) * 5 * time.Minute), Value: 3.0, Quality: domain.QualityGood,
			})
		}
		engine := newTestEngine(world)
		alerts := engine.EvaluateEvent(context.Background(), telemetry(testSensor, 3.0, baseTime))
		requireAlert(t, alerts, rules.IDDataQualityFrozen)
		requireNoAlert(t, alerts, rules.IDDataQualityGap)
	})
	t.Run("outage is a gap not a frozen value", func(t *testing.T) {
		t.Parallel()
		world := newWorld()
		sensor := sensorFixture()
		sensor.LastSeenAt = baseTime.Add(-40 * time.Minute)
		world.addSensor(sensor)
		world.setPolicy(func(p *domain.Policy) { p.DataQuality.TelemetryGapS = 900 })
		engine := newTestEngine(world)
		alerts := engine.EvaluateTick(context.Background())
		requireAlert(t, alerts, rules.IDDataQualityGap)
		requireNoAlert(t, alerts, rules.IDDataQualityFrozen)
	})
}

// TestNegativeWriteInsideWindow ensures approved maintenance writes do not raise
// a security alert.
func TestNegativeWriteInsideWindow(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	world.addWindow(maintenanceWindow("win-1", baseTime.Add(-10*time.Minute), baseTime.Add(20*time.Minute), testAsset))
	engine := newTestEngine(world)
	ev := writeAttempt(domain.WriteAttempt{
		Protocol: "modbus_tcp", Source: "10.0.1.7", Target: "10.0.0.5",
		Function: "fc6_write_single_register", Register: "40001", Allowed: true,
	}, baseTime)
	ev.AssetID = testAsset
	requireNoAlerts(t, engine.EvaluateEvent(context.Background(), ev))
}
