package detect_test

import (
	"context"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestEngineRulesCatalogue(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(newWorld())
	infos := engine.Rules()
	if len(infos) != 15 {
		t.Fatalf("expected 15 shipped rules, got %d", len(infos))
	}
	expected := map[domain.RuleID]bool{
		rules.IDUnknownPeer:             true,
		rules.IDWriteAttempt:            true,
		rules.IDAccessOffWindow:         true,
		rules.IDAccessUntrustedVendor:   true,
		rules.IDAccessManagementUI:      true,
		rules.IDThermalLimit:            true,
		rules.IDThermalRate:             true,
		rules.IDThermalSetpoint:         true,
		rules.IDThermalSensorDivergence: true,
		rules.IDDataQualityFrozen:       true,
		rules.IDDataQualityGap:          true,
		rules.IDDataQualityClockSkew:    true,
		rules.IDIntegrityChange:         true,
		rules.IDDeviceNewAsset:          true,
		rules.IDAssetLifecycleExposed:   true,
	}
	seen := make(map[domain.RuleID]bool, len(infos))
	var previous domain.RuleID
	for _, info := range infos {
		if !expected[info.ID] {
			t.Errorf("unexpected rule %q", info.ID)
		}
		if seen[info.ID] {
			t.Errorf("duplicate rule %q", info.ID)
		}
		seen[info.ID] = true
		if info.Version != "1" {
			t.Errorf("rule %q: expected version 1, got %q", info.ID, info.Version)
		}
		if info.Name == "" || info.Description == "" {
			t.Errorf("rule %q: missing name/description", info.ID)
		}
		if !info.Category.Valid() {
			t.Errorf("rule %q: invalid category %q", info.ID, info.Category)
		}
		if info.Baseline == "" || info.ConfidenceModel == "" || info.DedupKeyTemplate == "" {
			t.Errorf("rule %q: incomplete documented baseline/confidence/dedup key", info.ID)
		}
		if len(info.SeverityMatrix) == 0 {
			t.Errorf("rule %q: empty severity matrix", info.ID)
		}
		if len(info.RecommendedActions) == 0 {
			t.Errorf("rule %q: no recommended actions", info.ID)
		}
		for _, action := range info.RecommendedActions {
			if action.Action == "" {
				t.Errorf("rule %q: empty recommended action", info.ID)
			}
		}
		if len(info.SafetyConstraints) == 0 {
			t.Errorf("rule %q: no safety constraints", info.ID)
		}
		if len(info.FalsePositiveLimits) == 0 {
			t.Errorf("rule %q: no documented false-positive boundaries", info.ID)
		}
		if !info.Tick && len(info.EventKinds) == 0 {
			t.Errorf("rule %q: neither tick nor event kinds declared", info.ID)
		}
		if previous != "" && info.ID < previous {
			t.Errorf("rules not sorted: %q after %q", info.ID, previous)
		}
		previous = info.ID
	}
	for id := range expected {
		if !seen[id] {
			t.Errorf("missing required rule %q", id)
		}
		if _, ok := rules.ByID(id); !ok {
			t.Errorf("rule pack has no metadata for %q", id)
		}
	}
	// Rules() must return a defensive copy.
	infos[0].Name = "mutated"
	if engine.Rules()[0].Name == "mutated" {
		t.Fatal("Rules() must return a defensive copy")
	}
}

func TestEngineInertWithoutWorld(t *testing.T) {
	t.Parallel()
	engine := detect.NewEngine(nil, nil)
	if engine == nil {
		t.Fatal("NewEngine must not return nil")
	}
	ev := telemetry(testSensor, 3, baseTime)
	if alerts := engine.EvaluateEvent(context.Background(), ev); len(alerts) != 0 {
		t.Fatalf("nil world must be inert, got %d alerts", len(alerts))
	}
	if alerts := engine.EvaluateTick(context.Background()); len(alerts) != 0 {
		t.Fatalf("nil world tick must be inert, got %d alerts", len(alerts))
	}
	if len(engine.Rules()) != 15 {
		t.Fatal("rule catalogue must remain available without a world")
	}
	var zero *detect.Engine
	if alerts := zero.EvaluateEvent(context.Background(), ev); alerts != nil {
		t.Fatal("nil engine must return no alerts")
	}
}

func TestEngineRejectsInvalidEvent(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(newWorld())
	if alerts := engine.EvaluateEvent(context.Background(), domain.Event{}); len(alerts) != 0 {
		t.Fatalf("invalid event must be rejected, got %d alerts", len(alerts))
	}
}

func TestEngineStopsOnCanceledContext(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(newWorld())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if alerts := engine.EvaluateEvent(ctx, telemetry(testSensor, 3, baseTime)); alerts != nil {
		t.Fatalf("canceled context must stop evaluation, got %d alerts", len(alerts))
	}
	if alerts := engine.EvaluateTick(ctx); alerts != nil {
		t.Fatalf("canceled context must stop tick, got %d alerts", len(alerts))
	}
}

func TestEngineDeterministicOutput(t *testing.T) {
	t.Parallel()
	ev := flow("10.0.1.7", "10.0.0.5", 502, "modbus_tcp", baseTime)
	newDeterministicWorld := func() *fakeWorld {
		world := newWorld()
		world.setPolicy(func(p *domain.Policy) {
			p.Network.BaselineRequired = true
			p.Network.UnknownPeerGraceS = 0
		})
		world.addAsset(assetFixture())
		// The pipeline stores the event before detection runs.
		world.addEvent(ev)
		return world
	}
	first := newTestEngine(newDeterministicWorld()).EvaluateEvent(context.Background(), ev)
	second := newTestEngine(newDeterministicWorld()).EvaluateEvent(context.Background(), ev)
	if len(first) == 0 {
		t.Fatal("expected the unknown-peer alert")
	}
	if len(first) != len(second) {
		t.Fatalf("non-deterministic alert count: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].RuleID != second[i].RuleID || first[i].DedupKey != second[i].DedupKey || first[i].Severity != second[i].Severity {
			t.Fatalf("non-deterministic alert order at %d: %+v vs %+v", i, first[i], second[i])
		}
	}
	// Timestamps must come from the clock, not from wall time.
	if !first[0].CreatedAt.Equal(baseTime) || !first[0].FirstSeenAt.Equal(baseTime) {
		t.Fatalf("alert timestamps are not derived from the injected clock: %+v", first[0])
	}
	// The baseline is learned once: a second evaluation of the same event must
	// not emit the unknown-peer alert again.
	engine := newTestEngine(newDeterministicWorld())
	engine.EvaluateEvent(context.Background(), ev)
	if again := engine.EvaluateEvent(context.Background(), ev); len(alertsFor(again, rules.IDUnknownPeer)) != 0 {
		t.Fatal("peer baseline must be learned after the first observation")
	}
}

func TestEngineTickUsesWorldClock(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.setPolicy(func(p *domain.Policy) {
		p.DataQuality.TelemetryGapS = 900
	})
	world.addSensor(sensorFixture())
	// Last telemetry 40 minutes before now -> gap alert.
	world.addSample(domain.Sample{
		SensorID: testSensor, SiteID: testSite, ZoneID: testZone, Metric: "air_temperature",
		Unit: domain.UnitCelsius, At: baseTime.Add(-40 * time.Minute), Value: 3, Quality: domain.QualityGood,
	})
	engine := newTestEngine(world)
	alerts := engine.EvaluateTick(context.Background())
	if len(alerts) == 0 {
		t.Fatal("expected a telemetry-gap alert from the tick")
	}
	if !alerts[0].FirstSeenAt.Equal(baseTime) {
		t.Fatalf("tick alert timestamp not derived from clock: %v", alerts[0].FirstSeenAt)
	}
}
