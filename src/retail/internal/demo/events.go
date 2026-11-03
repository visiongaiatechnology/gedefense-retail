package demo

import (
	"math"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/idgen"
)

// Scenarios supported by the simulator/demo feed.
const (
	ScenarioNormal = "normal"
	ScenarioAttack = "angriff"
)

// Scenarios lists the demo scenarios (for CLI help and tests).
func Scenarios() []string { return []string{ScenarioNormal, ScenarioAttack} }

// Events generates a reproducible synthetic event stream for the demo site.
// The stream is passive: it contains observations only, never a control action.
// In the attack scenario the observed element is an external device talking to
// the management web UI and a Modbus write attempt – GeDefense observes it, it
// never performs it.
func Events(now time.Time, scenario string) []domain.Event {
	now = now.UTC()
	start := now.Add(-3 * time.Hour)
	step := 3 * time.Minute
	attackStart := now.Add(-30 * time.Minute)

	events := make([]domain.Event, 0, 512)
	add := func(e domain.Event) { events = append(events, e) }

	// Baseline observations of the known OT devices.
	for i, asset := range []struct {
		id        domain.AssetID
		ip, proto string
		port      int
	}{
		{AssetDanfossAKSM, "10.10.20.10", "modbus_tcp", 502},
		{AssetDixellXWEB, "10.10.20.11", "http", 80},
		{AssetCarelRack, "10.10.20.12", "modbus_tcp", 502},
		{AssetBMS, "10.10.20.20", "bacnet_ip", 47808},
		{AssetMQTTGateway, "10.10.20.30", "mqtt", 1883},
	} {
		at := start.Add(time.Duration(i) * time.Second)
		add(flowEvent(at, "10.10.30.5", asset.ip, 30000+i, asset.port, asset.proto))
		add(assetSeenEvent(at, asset.ip, AssetTypeHint(asset.proto)))
	}

	i := 0
	for t := start; t.Before(now); t = t.Add(step) {
		i++
		phase := float64(i) / 6.0
		meat1 := 3.1 + 0.35*math.Sin(phase)
		meat2 := 3.0 + 0.30*math.Sin(phase+0.4)
		dairy := 4.0 + 0.40*math.Sin(phase+1.1) + 0.20*math.Sin(phase*2.3)
		frozen := -18.4 + 0.30*math.Sin(phase+0.9)

		mode := "cooling"
		if (i/15)%2 == 1 { // simulated defrost cycle every ~45 minutes
			mode = "defrost"
			meat1 += 1.4
			meat2 += 1.3
		}
		doorOpen := (i/7)%2 == 1 // door open ~ every 21 minutes

		if scenario == ScenarioAttack && t.After(attackStart) {
			progress := t.Sub(attackStart).Minutes() / 30.0
			if progress > 1 {
				progress = 1
			}
			meat1 = 3.2 + 6.4*progress
			meat2 = 3.1 + 4.1*progress
			mode = "cooling"
		}

		add(telemetryEvent(t, SensorMeat1, AssetDanfossAKSM, ZoneColdMeat, "air_temperature", meat1, mode))
		add(telemetryEvent(t, SensorMeat2, AssetDixellXWEB, ZoneColdMeat, "air_temperature", meat2, mode))
		add(telemetryEvent(t, SensorDairy, AssetCarelRack, ZoneColdDairy, "air_temperature", dairy, mode))
		add(telemetryEvent(t, SensorFrozen, AssetCarelRack, ZoneColdFrozen, "air_temperature", frozen, mode))
		door := 0.0
		if doorOpen {
			door = 1.0
		}
		add(measurementEvent(t, SensorDoor, AssetDanfossAKSM, ZoneColdMeat, "door_state", door, domain.UnitBoolean, "good", "", nil))
	}

	if scenario == ScenarioAttack {
		at := attackStart
		add(flowEvent(at, "10.99.0.66", "10.10.20.10", 51514, 443, "https"))
		add(assetSeenEvent(at, "10.99.0.66", "unknown"))
		add(accessEvent(at, "10.99.0.66", AssetDanfossAKSM, "web_ui", false))
		add(writeAttemptEvent(at.Add(90*time.Second), "10.99.0.66", "10.10.20.10", "fc6_write_single_register", "40001", "9.0", false))
		add(measurementEvent(at.Add(2*time.Minute), SensorMeat1, AssetDanfossAKSM, ZoneColdMeat, "setpoint", 9.0, domain.UnitCelsius, "good", "cooling", floatPtr(9.0)))
		add(accessEvent(at.Add(9*time.Minute), "10.99.0.66", AssetDanfossAKSM, "web_ui", false))
	}
	return events
}

// AssetTypeHint maps a protocol to a passive classification hint used by the
// demo asset_seen events. It carries no identity claim.
func AssetTypeHint(protocol string) string {
	switch protocol {
	case "modbus_tcp":
		return "refrigeration_controller"
	case "bacnet_ip":
		return "bms"
	case "mqtt":
		return "sensor_gateway"
	case "http":
		return "refrigeration_controller"
	default:
		return "unknown"
	}
}

func telemetryEvent(t time.Time, sensor domain.SensorID, asset domain.AssetID, zone domain.ZoneID, metric string, value float64, mode string) domain.Event {
	unit := domain.UnitCelsius
	return measurementEvent(t, sensor, asset, zone, metric, value, unit, domain.QualityGood, mode, nil)
}

func measurementEvent(t time.Time, sensor domain.SensorID, asset domain.AssetID, zone domain.ZoneID, metric string, value float64, unit domain.Unit, quality domain.Quality, mode string, setpoint *float64) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(idgen.New("evt")),
		Kind:       domain.EventTelemetry,
		SiteID:     SiteID,
		ZoneID:     zone,
		AssetID:    asset,
		SensorID:   sensor,
		ObservedAt: t.UTC(),
		ReceivedAt: t.Add(1500 * time.Millisecond).UTC(),
		Source:     "sim.demo",
		Collection: "read_only_poll",
		Protocol:   "modbus_tcp",
		Confidence: 0.9,
		Quality:    quality,
		Measurement: &domain.Measurement{
			Value: value, Unit: unit, Quality: quality, Metric: metric,
			Mode: mode, ObservedAt: t.UTC(), SourceTS: t.UTC(), Setpoint: setpoint,
		},
	}
}

func flowEvent(t time.Time, src, dst string, srcPort, dstPort int, protocol string) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(idgen.New("evt")),
		Kind:       domain.EventFlow,
		SiteID:     SiteID,
		ZoneID:     ZoneMonitoring,
		ObservedAt: t.UTC(),
		ReceivedAt: t.Add(time.Second).UTC(),
		Source:     "sim.tap",
		Collection: "passive_tap",
		Protocol:   protocol,
		Confidence: 0.8,
		Flow:       &domain.FlowMeta{SrcIP: src, DstIP: dst, SrcPort: srcPort, DstPort: dstPort, Protocol: protocol, Bytes: 1240, Packets: 18, Direction: "internal"},
	}
}

func assetSeenEvent(t time.Time, ip, hint string) domain.Event {
	protocol := "arp"
	if hint != "unknown" {
		protocol = hint
	}
	return domain.Event{
		EventID:    domain.EventID(idgen.New("evt")),
		Kind:       domain.EventAssetSeen,
		SiteID:     SiteID,
		ZoneID:     ZoneMonitoring,
		ObservedAt: t.UTC(),
		ReceivedAt: t.Add(time.Second).UTC(),
		Source:     "sim.tap",
		Collection: "passive_tap",
		Protocol:   protocol,
		Confidence: 0.5,
		Device:     &domain.DeviceMeta{IP: ip},
	}
}

func accessEvent(t time.Time, sourceIP string, target domain.AssetID, method string, inWindow bool) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(idgen.New("evt")),
		Kind:       domain.EventAccess,
		SiteID:     SiteID,
		ZoneID:     ZoneMaintenance,
		AssetID:    target,
		ObservedAt: t.UTC(),
		ReceivedAt: t.Add(time.Second).UTC(),
		Source:     "sim.httpui",
		Collection: "passive_tap",
		Protocol:   "https",
		Confidence: 0.7,
		Access: &domain.AccessMeta{
			Vendor: "", User: "", Method: method,
			TargetAsset: target, InWindow: inWindow,
			SourceDevice: sourceIP, SessionID: idgen.New("ses"),
		},
	}
}

func writeAttemptEvent(t time.Time, src, dst, function, register, valueHint string, allowed bool) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(idgen.New("evt")),
		Kind:       domain.EventWriteAttempt,
		SiteID:     SiteID,
		ZoneID:     ZoneProcess,
		AssetID:    AssetDanfossAKSM,
		ObservedAt: t.UTC(),
		ReceivedAt: t.Add(time.Second).UTC(),
		Source:     "sim.modbus.tap",
		Collection: "passive_tap",
		Protocol:   "modbus_tcp",
		Confidence: 0.85,
		WriteAttempt: &domain.WriteAttempt{
			Protocol: "modbus_tcp", Source: src, Target: dst,
			Function: function, Register: register, ValueHint: valueHint, Allowed: allowed,
		},
	}
}

func floatPtr(v float64) *float64 { return &v }
