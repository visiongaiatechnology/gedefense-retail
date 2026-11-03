package detect_test

import (
	"context"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestFrozenValueRule(t *testing.T) {
	t.Parallel()
	const peerSensor = domain.SensorID("sensor-temp-2")
	addSeries := func(w *fakeWorld, sensor domain.SensorID, values []float64) {
		for i, value := range values {
			w.addSample(domain.Sample{
				SensorID: sensor, SiteID: testSite, ZoneID: testZone, AssetID: testAsset,
				Metric: "air_temperature", Unit: domain.UnitCelsius,
				At: baseTime.Add(-time.Duration(len(values)-i) * 5 * time.Minute), Value: value, Quality: domain.QualityGood,
			})
		}
	}
	setupFrozen := func(w *fakeWorld) {
		w.addAsset(assetFixture())
		w.addSensor(sensorFixture())
		w.setPolicy(func(p *domain.Policy) { p.DataQuality.FrozenValueWindowS = 1800 })
	}
	cases := []struct {
		name      string
		setup     func(*fakeWorld)
		wantAlert bool
		wantSev   domain.Severity
	}{
		{
			name: "constant series is a data-quality signal",
			setup: func(w *fakeWorld) {
				setupFrozen(w)
				addSeries(w, testSensor, []float64{3.0, 3.0, 3.0, 3.0, 3.0})
			},
			wantAlert: true,
			wantSev:   domain.SeverityMedium,
		},
		{
			name: "moving comparison sensor raises severity",
			setup: func(w *fakeWorld) {
				setupFrozen(w)
				addSeries(w, testSensor, []float64{3.0, 3.0, 3.0, 3.0, 3.0})
				w.addSensor(domain.Sensor{
					SensorID: peerSensor, SiteID: testSite, ZoneID: testZone, Metric: "air_temperature",
					Unit: domain.UnitCelsius, Independent: true,
				})
				addSeries(w, peerSensor, []float64{2.0, 3.0, 4.0, 5.0, 5.5})
			},
			wantAlert: true,
			wantSev:   domain.SeverityHigh,
		},
		{
			name: "varying values are not frozen",
			setup: func(w *fakeWorld) {
				setupFrozen(w)
				addSeries(w, testSensor, []float64{2.9, 3.1, 3.0, 3.2, 3.1})
			},
			wantAlert: false,
		},
		{
			name: "frozen-value detection disabled in policy",
			setup: func(w *fakeWorld) {
				w.addSensor(sensorFixture())
				w.setPolicy(func(p *domain.Policy) { p.DataQuality.FrozenValueWindowS = 0 })
				addSeries(w, testSensor, []float64{3.0, 3.0, 3.0, 3.0, 3.0})
			},
			wantAlert: false,
		},
		{
			name: "sensor outage is a gap, not a frozen value",
			setup: func(w *fakeWorld) {
				setupFrozen(w)
			},
			wantAlert: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			world := newWorld()
			tc.setup(world)
			engine := newTestEngine(world)
			alerts := engine.EvaluateEvent(context.Background(), telemetry(testSensor, 3.0, baseTime))
			if tc.wantAlert {
				alert := requireAlert(t, alerts, rules.IDDataQualityFrozen)
				if alert.Severity != tc.wantSev {
					t.Fatalf("expected %s, got %s", tc.wantSev, alert.Severity)
				}
				if alert.Category != domain.CategoryDataQuality {
					t.Fatalf("frozen value must be data_quality, got %s", alert.Category)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDDataQualityFrozen)
			}
			requireNoCritical(t, alerts)
		})
	}
}

func TestGapRule(t *testing.T) {
	t.Parallel()
	addSample := func(w *fakeWorld, value float64, at time.Time) {
		w.addSample(domain.Sample{
			SensorID: testSensor, SiteID: testSite, ZoneID: testZone, AssetID: testAsset,
			Metric: "air_temperature", Unit: domain.UnitCelsius, At: at, Value: value, Quality: domain.QualityGood,
		})
	}
	cases := []struct {
		name      string
		setup     func(*fakeWorld)
		event     bool
		wantAlert bool
	}{
		{
			name: "telemetry gap detected when data resumes",
			setup: func(w *fakeWorld) {
				w.addSensor(sensorFixture())
				w.setPolicy(func(p *domain.Policy) { p.DataQuality.TelemetryGapS = 900 })
				addSample(w, 3.0, baseTime.Add(-30*time.Minute))
			},
			event:     true,
			wantAlert: true,
		},
		{
			name: "gap below threshold is normal",
			setup: func(w *fakeWorld) {
				w.addSensor(sensorFixture())
				w.setPolicy(func(p *domain.Policy) { p.DataQuality.TelemetryGapS = 900 })
				addSample(w, 3.0, baseTime.Add(-10*time.Minute))
			},
			event:     true,
			wantAlert: false,
		},
		{
			name: "tick reports silent sensor",
			setup: func(w *fakeWorld) {
				sensor := sensorFixture()
				sensor.LastSeenAt = baseTime.Add(-40 * time.Minute)
				w.addSensor(sensor)
				w.setPolicy(func(p *domain.Policy) { p.DataQuality.TelemetryGapS = 900 })
			},
			event:     false,
			wantAlert: true,
		},
		{
			name: "tick ignores never-seen sensor at startup",
			setup: func(w *fakeWorld) {
				w.addSensor(sensorFixture())
				w.setPolicy(func(p *domain.Policy) { p.DataQuality.TelemetryGapS = 900 })
			},
			event:     false,
			wantAlert: false,
		},
		{
			name: "missing telemetry threshold disables the rule",
			setup: func(w *fakeWorld) {
				w.addSensor(sensorFixture())
				w.setPolicy(func(p *domain.Policy) { p.DataQuality.TelemetryGapS = 0 })
				addSample(w, 3.0, baseTime.Add(-30*time.Minute))
			},
			event:     true,
			wantAlert: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			world := newWorld()
			tc.setup(world)
			engine := newTestEngine(world)
			var alerts []domain.Alert
			if tc.event {
				alerts = engine.EvaluateEvent(context.Background(), telemetry(testSensor, 3.0, baseTime))
			} else {
				alerts = engine.EvaluateTick(context.Background())
			}
			if tc.wantAlert {
				alert := requireAlert(t, alerts, rules.IDDataQualityGap)
				if alert.Severity == domain.SeverityCritical {
					t.Fatalf("gap alert must not be critical: %+v", alert)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDDataQualityGap)
			}
		})
	}
}

func TestClockSkewRule(t *testing.T) {
	t.Parallel()
	withMaxSkew := func(w *fakeWorld) {
		w.addSensor(sensorFixture())
		w.setPolicy(func(p *domain.Policy) { p.DataQuality.MaxClockSkewS = 300 })
	}
	cases := []struct {
		name      string
		setup     func(*fakeWorld)
		event     func() domain.Event
		wantDedup string
		wantAlert bool
	}{
		{
			name:  "received/observed deviation over tolerance",
			setup: withMaxSkew,
			event: func() domain.Event {
				ev := telemetry(testSensor, 3.0, baseTime.Add(-10*time.Minute))
				ev.ReceivedAt = baseTime
				return ev
			},
			wantDedup: "skew", wantAlert: true,
		},
		{
			name:  "small deviation is normal",
			setup: withMaxSkew,
			event: func() domain.Event {
				ev := telemetry(testSensor, 3.0, baseTime.Add(-2*time.Minute))
				ev.ReceivedAt = baseTime
				return ev
			},
			wantAlert: false,
		},
		{
			name:  "device source timestamp deviation",
			setup: withMaxSkew,
			event: func() domain.Event {
				ev := telemetry(testSensor, 3.0, baseTime)
				ev.Measurement.SourceTS = baseTime.Add(-20 * time.Minute)
				return ev
			},
			wantDedup: "source-timestamp", wantAlert: true,
		},
		{
			name: "timestamp regression",
			setup: func(w *fakeWorld) {
				withMaxSkew(w)
				w.addEvent(telemetry(testSensor, 3.0, baseTime.Add(-time.Minute)))
			},
			event: func() domain.Event {
				return telemetry(testSensor, 3.0, baseTime.Add(-10*time.Minute))
			},
			wantDedup: "regression", wantAlert: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			world := newWorld()
			tc.setup(world)
			engine := newTestEngine(world)
			alerts := engine.EvaluateEvent(context.Background(), tc.event())
			if tc.wantAlert {
				alert := requireAlert(t, alerts, rules.IDDataQualityClockSkew)
				if !contains(tc.wantDedup, string(alert.DedupKey)) {
					t.Fatalf("dedup key %q does not contain %q", alert.DedupKey, tc.wantDedup)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDDataQualityClockSkew)
			}
			requireNoCritical(t, alerts)
		})
	}
}
