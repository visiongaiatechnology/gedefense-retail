package detect_test

import (
	"context"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestThermalLimitRule(t *testing.T) {
	t.Parallel()
	withLimits := func(w *fakeWorld) {
		w.addAsset(assetFixture())
		w.addSensor(sensorFixture())
		w.setPolicy(func(p *domain.Policy) {
			p.Temperature.Limits = []domain.TemperatureLimit{{
				ZoneID: testZone, Metric: "air_temperature", MinC: f64(0), MaxC: f64(4),
			}}
		})
	}
	cases := []struct {
		name      string
		setup     func(*fakeWorld)
		event     domain.Event
		wantAlert bool
		wantSev   domain.Severity
	}{
		{
			name:      "slight exceedance is low/medium",
			setup:     withLimits,
			event:     telemetry(testSensor, 5.0, baseTime),
			wantAlert: true,
			wantSev:   domain.SeverityMedium,
		},
		{
			name:      "gross exceedance is high but not critical",
			setup:     withLimits,
			event:     telemetry(testSensor, 9.0, baseTime),
			wantAlert: true,
			wantSev:   domain.SeverityHigh,
		},
		{
			name:      "value inside operator limits is normal",
			setup:     withLimits,
			event:     telemetry(testSensor, 3.0, baseTime),
			wantAlert: false,
		},
		{
			name:      "minimum limit breach",
			setup:     withLimits,
			event:     telemetry(testSensor, -1.0, baseTime),
			wantAlert: true,
			wantSev:   domain.SeverityMedium,
		},
		{
			name:      "defrost mode degrades severity",
			setup:     withLimits,
			event:     telemetryFull(testSensor, testZone, testAsset, "air_temperature", 9.0, domain.UnitCelsius, domain.QualityGood, "defrost", nil, baseTime),
			wantAlert: true,
			wantSev:   domain.SeverityMedium,
		},
		{
			name:      "unreliable quality does not raise a process alarm",
			setup:     withLimits,
			event:     telemetryFull(testSensor, testZone, testAsset, "air_temperature", 9.0, domain.UnitCelsius, domain.QualityBad, "", nil, baseTime),
			wantAlert: false,
		},
		{
			name: "missing policy limit means no thermal alerting",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.addSensor(sensorFixture())
			},
			event:     telemetry(testSensor, 12.0, baseTime),
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
			alerts := engine.EvaluateEvent(context.Background(), tc.event)
			if tc.wantAlert {
				alert := requireAlert(t, alerts, rules.IDThermalLimit)
				if alert.Severity != tc.wantSev {
					t.Fatalf("expected %s, got %s", tc.wantSev, alert.Severity)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDThermalLimit)
			}
			requireNoCritical(t, alerts)
		})
	}
}

func TestThermalRateRule(t *testing.T) {
	t.Parallel()
	withRateLimit := func(w *fakeWorld) {
		w.addSensor(sensorFixture())
		w.setPolicy(func(p *domain.Policy) {
			p.Temperature.Limits = []domain.TemperatureLimit{{
				ZoneID: testZone, Metric: "air_temperature", MaxRateCPerMin: f64(0.5),
			}}
		})
	}
	addSample := func(w *fakeWorld, value float64, at time.Time) {
		w.addSample(domain.Sample{
			SensorID: testSensor, SiteID: testSite, ZoneID: testZone, AssetID: testAsset,
			Metric: "air_temperature", Unit: domain.UnitCelsius, At: at, Value: value, Quality: domain.QualityGood,
		})
	}
	cases := []struct {
		name      string
		setup     func(*fakeWorld)
		event     func(*fakeWorld) domain.Event
		wantAlert bool
	}{
		{
			name: "rapid rise above operator rate limit",
			setup: func(w *fakeWorld) {
				withRateLimit(w)
				addSample(w, 2.0, baseTime.Add(-4*time.Minute))
			},
			event: func(*fakeWorld) domain.Event {
				return telemetry(testSensor, 6.0, baseTime)
			},
			wantAlert: true,
		},
		{
			name: "slow change is normal",
			setup: func(w *fakeWorld) {
				withRateLimit(w)
				addSample(w, 2.0, baseTime.Add(-4*time.Minute))
			},
			event: func(*fakeWorld) domain.Event {
				return telemetry(testSensor, 2.1, baseTime)
			},
			wantAlert: false,
		},
		{
			name: "no rate limit in policy",
			setup: func(w *fakeWorld) {
				w.addSensor(sensorFixture())
				w.setPolicy(func(p *domain.Policy) {
					p.Temperature.Limits = []domain.TemperatureLimit{{ZoneID: testZone, Metric: "air_temperature", MaxC: f64(8)}}
				})
				addSample(w, 2.0, baseTime.Add(-4*time.Minute))
			},
			event: func(*fakeWorld) domain.Event {
				return telemetry(testSensor, 6.0, baseTime)
			},
			wantAlert: false,
		},
		{
			name: "defrost mode suppresses rate alerts",
			setup: func(w *fakeWorld) {
				withRateLimit(w)
				addSample(w, 2.0, baseTime.Add(-4*time.Minute))
			},
			event: func(*fakeWorld) domain.Event {
				return telemetryFull(testSensor, testZone, testAsset, "air_temperature", 6.0, domain.UnitCelsius, domain.QualityGood, "defrost", nil, baseTime)
			},
			wantAlert: false,
		},
		{
			name: "insufficient measurement span is not judged",
			setup: func(w *fakeWorld) {
				withRateLimit(w)
				addSample(w, 2.0, baseTime.Add(-time.Minute))
			},
			event: func(*fakeWorld) domain.Event {
				return telemetry(testSensor, 6.0, baseTime)
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
			alerts := engine.EvaluateEvent(context.Background(), tc.event(world))
			if tc.wantAlert {
				alert := requireAlert(t, alerts, rules.IDThermalRate)
				if alert.Severity == domain.SeverityCritical {
					t.Fatalf("rate alert must not be critical: %+v", alert)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDThermalRate)
			}
		})
	}
}

func TestSetpointDeviationRule(t *testing.T) {
	t.Parallel()
	withTolerance := func(w *fakeWorld) {
		w.addSensor(sensorFixture())
		w.setPolicy(func(p *domain.Policy) {
			p.Temperature.Limits = []domain.TemperatureLimit{{
				ZoneID: testZone, Metric: "air_temperature", MaxC: f64(8), SetpointToleranceC: f64(0.5),
			}}
		})
	}
	addPrevious := func(w *fakeWorld, metric string, value float64, mode string) {
		w.addSample(domain.Sample{
			SensorID: testSensor, SiteID: testSite, ZoneID: testZone, AssetID: testAsset,
			Metric: metric, Unit: domain.UnitCelsius, At: baseTime.Add(-10 * time.Minute), Value: value,
			Quality: domain.QualityGood, Mode: mode,
		})
	}
	cases := []struct {
		name      string
		setup     func(*fakeWorld)
		event     func(*fakeWorld) domain.Event
		wantDedup string
		wantAlert bool
		wantSev   domain.Severity
	}{
		{
			name: "setpoint change outside window",
			setup: func(w *fakeWorld) {
				withTolerance(w)
				addPrevious(w, "setpoint", 4.0, "cooling")
			},
			event: func(*fakeWorld) domain.Event {
				return telemetryFull(testSensor, testZone, testAsset, "setpoint", 6.0, domain.UnitCelsius, domain.QualityGood, "", nil, baseTime)
			},
			wantDedup: "setpoint-change", wantAlert: true, wantSev: domain.SeverityHigh,
		},
		{
			name: "setpoint change inside approved window is normal",
			setup: func(w *fakeWorld) {
				withTolerance(w)
				addPrevious(w, "setpoint", 4.0, "cooling")
				w.addWindow(maintenanceWindow("win-1", baseTime.Add(-10*time.Minute), baseTime.Add(20*time.Minute), testAsset))
			},
			event: func(*fakeWorld) domain.Event {
				ev := telemetryFull(testSensor, testZone, testAsset, "setpoint", 6.0, domain.UnitCelsius, domain.QualityGood, "", nil, baseTime)
				ev.AssetID = testAsset
				return ev
			},
			wantAlert: false,
		},
		{
			name: "measured value deviates from reported setpoint",
			setup: func(w *fakeWorld) {
				withTolerance(w)
			},
			event: func(*fakeWorld) domain.Event {
				return telemetryFull(testSensor, testZone, testAsset, "air_temperature", 6.0, domain.UnitCelsius, domain.QualityGood, "", f64(4.0), baseTime)
			},
			wantDedup: "setpoint-deviation", wantAlert: true, wantSev: domain.SeverityHigh,
		},
		{
			name: "missing operator tolerance means no value-deviation alert",
			setup: func(w *fakeWorld) {
				w.addSensor(sensorFixture())
				w.setPolicy(func(p *domain.Policy) {
					p.Temperature.Limits = []domain.TemperatureLimit{{ZoneID: testZone, Metric: "air_temperature", MaxC: f64(8)}}
				})
			},
			event: func(*fakeWorld) domain.Event {
				return telemetryFull(testSensor, testZone, testAsset, "air_temperature", 6.0, domain.UnitCelsius, domain.QualityGood, "", f64(4.0), baseTime)
			},
			wantAlert: false,
		},
		{
			name: "suspicious mode change outside window",
			setup: func(w *fakeWorld) {
				withTolerance(w)
				addPrevious(w, "air_temperature", 3.0, "cooling")
			},
			event: func(*fakeWorld) domain.Event {
				return telemetryFull(testSensor, testZone, testAsset, "air_temperature", 3.0, domain.UnitCelsius, domain.QualityGood, "off", nil, baseTime)
			},
			wantDedup: "mode-change", wantAlert: true, wantSev: domain.SeverityMedium,
		},
		{
			name: "defrost mode change is normal",
			setup: func(w *fakeWorld) {
				withTolerance(w)
				addPrevious(w, "air_temperature", 3.0, "cooling")
			},
			event: func(*fakeWorld) domain.Event {
				return telemetryFull(testSensor, testZone, testAsset, "air_temperature", 3.0, domain.UnitCelsius, domain.QualityGood, "defrost", nil, baseTime)
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
			alerts := engine.EvaluateEvent(context.Background(), tc.event(world))
			if tc.wantAlert {
				alert := requireAlert(t, alerts, rules.IDThermalSetpoint)
				if alert.Severity != tc.wantSev {
					t.Fatalf("expected %s, got %s", tc.wantSev, alert.Severity)
				}
				if tc.wantDedup != "" && !contains(tc.wantDedup, string(alert.DedupKey)) {
					t.Fatalf("dedup key %q does not contain %q", alert.DedupKey, tc.wantDedup)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDThermalSetpoint)
			}
			requireNoCritical(t, alerts)
		})
	}
}

func TestSensorDivergenceRule(t *testing.T) {
	t.Parallel()
	const peerSensor = domain.SensorID("sensor-temp-2")
	withPeer := func(w *fakeWorld, peerValue float64) {
		w.addSensor(sensorFixture())
		w.addSensor(domain.Sensor{
			SensorID: peerSensor, SiteID: testSite, AssetID: testAsset, ZoneID: testZone,
			Name: "Lufttemperatur Süd", Metric: "air_temperature", Unit: domain.UnitCelsius,
			Independent: true, Critical: true,
		})
		w.setPolicy(func(p *domain.Policy) {
			p.Sensors.DivergenceC = f64(1.0)
			p.Sensors.DivergenceWindowS = 600
		})
		w.addSample(domain.Sample{
			SensorID: peerSensor, SiteID: testSite, ZoneID: testZone, AssetID: testAsset,
			Metric: "air_temperature", Unit: domain.UnitCelsius, At: baseTime.Add(-time.Minute), Value: peerValue,
			Quality: domain.QualityGood,
		})
	}
	cases := []struct {
		name      string
		setup     func(*fakeWorld)
		wantAlert bool
		wantSev   domain.Severity
	}{
		{
			name:      "large divergence is high",
			setup:     func(w *fakeWorld) { withPeer(w, 7.0) },
			wantAlert: true,
			wantSev:   domain.SeverityHigh,
		},
		{
			name:      "divergence above threshold is medium",
			setup:     func(w *fakeWorld) { withPeer(w, 5.6) },
			wantAlert: true,
			wantSev:   domain.SeverityMedium,
		},
		{
			name:      "divergence within threshold is normal",
			setup:     func(w *fakeWorld) { withPeer(w, 4.5) },
			wantAlert: false,
		},
		{
			name: "no configured divergence threshold",
			setup: func(w *fakeWorld) {
				w.addSensor(sensorFixture())
				w.addSensor(domain.Sensor{
					SensorID: peerSensor, SiteID: testSite, ZoneID: testZone, Metric: "air_temperature",
					Unit: domain.UnitCelsius, Independent: true,
				})
				w.addSample(domain.Sample{
					SensorID: peerSensor, SiteID: testSite, ZoneID: testZone, Metric: "air_temperature",
					Unit: domain.UnitCelsius, At: baseTime.Add(-time.Minute), Value: 9.0, Quality: domain.QualityGood,
				})
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
			alerts := engine.EvaluateEvent(context.Background(), telemetry(testSensor, 4.0, baseTime))
			if tc.wantAlert {
				alert := requireAlert(t, alerts, rules.IDThermalSensorDivergence)
				if alert.Severity != tc.wantSev {
					t.Fatalf("expected %s, got %s", tc.wantSev, alert.Severity)
				}
				if alert.Category != domain.CategoryDataQuality {
					t.Fatalf("divergence must be a data-quality signal, got %s", alert.Category)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDThermalSensorDivergence)
			}
			requireNoCritical(t, alerts)
		})
	}
}

func contains(needle, haystack string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
