// Synthetic event generator for the dev-ingest feed.
package main

import (
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/collect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Simulation scenarios supported by the feed.
const (
	scenarioNormal        = "normal"
	scenarioAbtau         = "abtau"
	scenarioTuer          = "tuer"
	scenarioAngriff       = "angriff"
	scenarioAngriffMgmtUI = "angriff-management-ui"
)

// Simulation addresses (documentation range 172.16.50.0/24).
const (
	simControllerIP = "172.16.50.10"
	simPanelIP      = "172.16.50.20"
	simGatewayIP    = "172.16.50.30"
	simBrokerIP     = "172.16.50.40"
	simForeignIP    = "192.168.99.50"
)

var (
	simSensorAir1 = domain.SensorID("sensor_kaelte_01")
	simSensorAir2 = domain.SensorID("sensor_kaelte_02")
	simSensorAir3 = domain.SensorID("sensor_kaelte_03")
	simSensorSet  = domain.SensorID("sensor_setpoint_01")
	simSensorDoor = domain.SensorID("sensor_door_01")
	simSensorMode = domain.SensorID("sensor_mode_01")
	simAssetRack  = domain.AssetID("asset_rack_01")
)

// feedGenerator produces a deterministic event stream for one scenario.
type feedGenerator struct {
	scenario string
	site     domain.SiteID
	zone     domain.ZoneID
	step     int
	rnd      *rand.Rand
}

func newFeedGenerator(scenario, site, zone string) (*feedGenerator, error) {
	switch scenario {
	case scenarioNormal, scenarioAbtau, scenarioTuer, scenarioAngriff, scenarioAngriffMgmtUI:
	default:
		return nil, fmt.Errorf("unknown scenario %q", scenario)
	}
	return &feedGenerator{
		scenario: scenario,
		site:     domain.SiteID(site),
		zone:     domain.ZoneID(zone),
		rnd:      rand.New(rand.NewPCG(0x0e1f, 0x5eed)),
	}, nil
}

// Next returns the next valid event of the scenario.
func (g *feedGenerator) Next() (domain.Event, error) {
	step := g.step
	g.step++
	switch g.scenario {
	case scenarioNormal:
		return g.normal(step)
	case scenarioAbtau:
		return g.abtau(step)
	case scenarioTuer:
		return g.tuer(step)
	case scenarioAngriff:
		return g.angriff(step)
	case scenarioAngriffMgmtUI:
		return g.angriffManagementUI(step)
	default:
		return domain.Event{}, fmt.Errorf("unknown scenario %q", g.scenario)
	}
}

// normal: stable cold-chain operation with occasional defrost and management
// traffic (negative cases that must not become critical alerts).
func (g *feedGenerator) normal(step int) (domain.Event, error) {
	switch step % 12 {
	case 0, 3, 6, 9:
		value := 4.0 + g.rnd.Float64()*0.4
		return g.telemetry(simSensorAir1, simAssetRack, "air_temperature", domain.UnitCelsius, value, "")
	case 1:
		return g.telemetry(simSensorSet, simAssetRack, "setpoint", domain.UnitCelsius, 4.0, "")
	case 2:
		return g.telemetry(simSensorMode, simAssetRack, "operating_mode", domain.UnitCount, 0, "cooling")
	case 4:
		value := 4.2 + g.rnd.Float64()*0.4
		return g.telemetry(simSensorAir2, simAssetRack, "air_temperature", domain.UnitCelsius, value, "")
	case 5:
		return g.flow("modbus_tcp", simPanelIP, simControllerIP, 49152+step%1000, 502)
	case 7:
		return g.assetSeen(simControllerIP, "storeview-ak-sm-800.filiale.local", "Danfoss", "StoreView", "http")
	case 8:
		return g.flow("https", simPanelIP, simControllerIP, 49152+step%1000, 443)
	case 10:
		return g.telemetry(simSensorDoor, simAssetRack, "door_state", domain.UnitBoolean, 0, "")
	case 11:
		return g.flow("mqtt", simBrokerIP, simGatewayIP, 1883, 51234)
	default:
		return g.normal(step + 12)
	}
}

// abtau: defrost cycle with a temperature rise (documented negative case).
func (g *feedGenerator) abtau(step int) (domain.Event, error) {
	phase := step % 16
	switch phase {
	case 0:
		return g.telemetry(simSensorMode, simAssetRack, "operating_mode", domain.UnitCount, 1, "defrost")
	case 1, 3, 5, 7:
		rise := float64(phase) * 0.55
		return g.telemetry(simSensorAir1, simAssetRack, "air_temperature", domain.UnitCelsius, 4.0+rise, "defrost")
	case 2:
		return g.flow("modbus_tcp", simPanelIP, simControllerIP, 49152+step%1000, 502)
	case 4, 8:
		return g.telemetry(simSensorSet, simAssetRack, "setpoint", domain.UnitCelsius, 4.0, "defrost")
	case 9:
		return g.telemetry(simSensorMode, simAssetRack, "operating_mode", domain.UnitCount, 0, "cooling")
	case 10, 12, 14:
		return g.telemetry(simSensorAir1, simAssetRack, "air_temperature", domain.UnitCelsius, 7.5-float64(phase)*0.2, "cooling")
	default:
		return g.telemetry(simSensorDoor, simAssetRack, "door_state", domain.UnitBoolean, 0, "")
	}
}

// tuer: door opening with a temperature rise (documented negative case).
func (g *feedGenerator) tuer(step int) (domain.Event, error) {
	phase := step % 10
	switch phase {
	case 0:
		return g.telemetry(simSensorDoor, simAssetRack, "door_state", domain.UnitBoolean, 1, "")
	case 1, 3, 5:
		return g.telemetry(simSensorAir1, simAssetRack, "air_temperature", domain.UnitCelsius, 4.0+float64(phase)*0.4, "")
	case 2:
		return g.flow("flow", simPanelIP, simControllerIP, 49152+step%1000, 502)
	case 4:
		return g.telemetry(simSensorSet, simAssetRack, "setpoint", domain.UnitCelsius, 4.0, "")
	case 6:
		return g.telemetry(simSensorDoor, simAssetRack, "door_state", domain.UnitBoolean, 0, "")
	case 7, 9:
		return g.telemetry(simSensorAir1, simAssetRack, "air_temperature", domain.UnitCelsius, 5.0-float64(phase-7)*0.3, "")
	default:
		return g.telemetry(simSensorAir2, simAssetRack, "air_temperature", domain.UnitCelsius, 4.1, "")
	}
}

// angriff: foreign peer, observed Modbus write attempt, manipulated setpoint,
// heating trend and an off-window maintenance session. All only observed.
func (g *feedGenerator) angriff(step int) (domain.Event, error) {
	switch step % 12 {
	case 0, 6, 10:
		return g.telemetry(simSensorAir1, simAssetRack, "air_temperature", domain.UnitCelsius, 6.0+float64(step%12)*0.7, "")
	case 1:
		return g.telemetry(simSensorSet, simAssetRack, "setpoint", domain.UnitCelsius, 12.0, "")
	case 2:
		return g.telemetry(simSensorMode, simAssetRack, "operating_mode", domain.UnitCount, 2, "heating")
	case 3:
		return g.writeAttempt("modbus_tcp", simForeignIP, simControllerIP+":502",
			"fc6_write_single_register", "holding:40002")
	case 4:
		return g.flow("modbus_tcp", simForeignIP, simControllerIP, 50000+step%1000, 502)
	case 5:
		return g.assetSeen(simForeignIP, "", "", "", "http")
	case 7:
		return g.access("unbekannter-dienstleister", false)
	case 8:
		return g.flow("https", simForeignIP, simControllerIP, 50000+step%1000, 443)
	case 9:
		return g.writeAttempt("http", simForeignIP, simControllerIP+":443", "http_post", "/xml.cgi")
	case 11:
		return g.telemetry(simSensorDoor, simAssetRack, "door_state", domain.UnitBoolean, 1, "")
	default:
		return g.telemetry(simSensorAir2, simAssetRack, "air_temperature", domain.UnitCelsius, 9.0, "")
	}
}

// angriffManagementUI: the documented 2026 entry path — a foreign device talks
// to the supervisor's management UI outside the maintenance window.
func (g *feedGenerator) angriffManagementUI(step int) (domain.Event, error) {
	switch step % 10 {
	case 0:
		return g.assetSeen(simControllerIP, "storeview-ak-sm-800.filiale.local", "Danfoss", "StoreView", "http")
	case 1, 4:
		return g.flow("https", simForeignIP, simControllerIP, 50000+step%1000, 443)
	case 2:
		return g.writeAttempt("http", simForeignIP, simControllerIP+":443", "http_post", "/xml.cgi")
	case 3:
		return g.access("fremder-dienstleister", false)
	case 5:
		return g.telemetry(simSensorSet, simAssetRack, "setpoint", domain.UnitCelsius, 11.5, "")
	case 6, 8:
		return g.telemetry(simSensorAir1, simAssetRack, "air_temperature", domain.UnitCelsius, 7.0+float64(step%10)*0.6, "")
	case 7:
		return g.flow("modbus_tcp", simControllerIP, simPanelIP, 502, 50000+step%1000)
	case 9:
		return g.telemetry(simSensorDoor, simAssetRack, "door_state", domain.UnitBoolean, 1, "")
	default:
		return g.telemetry(simSensorAir2, simAssetRack, "air_temperature", domain.UnitCelsius, 6.5, "")
	}
}

// base builds the common event envelope.
func (g *feedGenerator) base(kind domain.EventKind, protocol string, confidence float64) (domain.Event, error) {
	id, err := collect.NewEventID()
	if err != nil {
		return domain.Event{}, err
	}
	now := time.Now().UTC()
	return domain.Event{
		EventID:    id,
		Kind:       kind,
		SiteID:     g.site,
		ZoneID:     g.zone,
		ObservedAt: now,
		ReceivedAt: now,
		Source:     "sim.feed",
		Collection: collect.CollectionPassiveTap,
		Protocol:   protocol,
		Confidence: confidence,
		Quality:    domain.QualityGood,
	}, nil
}

func (g *feedGenerator) telemetry(sensor domain.SensorID, asset domain.AssetID, metric string, unit domain.Unit, value float64, mode string) (domain.Event, error) {
	ev, err := g.base(domain.EventTelemetry, "", 0.95)
	if err != nil {
		return domain.Event{}, err
	}
	ev.SensorID = sensor
	ev.AssetID = asset
	ev.Measurement = &domain.Measurement{
		Value:      value,
		Unit:       unit,
		Quality:    domain.QualityGood,
		Metric:     metric,
		Mode:       mode,
		ObservedAt: ev.ObservedAt,
	}
	return ev, nil
}

func (g *feedGenerator) flow(protocol, src, dst string, srcPort, dstPort int) (domain.Event, error) {
	ev, err := g.base(domain.EventFlow, protocol, 0.6)
	if err != nil {
		return domain.Event{}, err
	}
	ev.Flow = &domain.FlowMeta{
		SrcIP:     src,
		DstIP:     dst,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		Packets:   12,
		Bytes:     1440,
		Direction: "internal",
	}
	return ev, nil
}

func (g *feedGenerator) assetSeen(ip, hostname, vendor, model, protocol string) (domain.Event, error) {
	ev, err := g.base(domain.EventAssetSeen, protocol, 0.55)
	if err != nil {
		return domain.Event{}, err
	}
	ev.AssetID = ""
	ev.Device = &domain.DeviceMeta{IP: ip, Hostname: hostname, Vendor: vendor, Model: model}
	return ev, nil
}

func (g *feedGenerator) writeAttempt(protocol, source, target, function, register string) (domain.Event, error) {
	ev, err := g.base(domain.EventWriteAttempt, protocol, 0.85)
	if err != nil {
		return domain.Event{}, err
	}
	ev.AssetID = simAssetRack
	ev.WriteAttempt = &domain.WriteAttempt{
		Protocol: protocol,
		Source:   source,
		Target:   target,
		Function: function,
		Register: register,
		Allowed:  false,
	}
	return ev, nil
}

func (g *feedGenerator) access(vendor string, inWindow bool) (domain.Event, error) {
	ev, err := g.base(domain.EventAccess, "http", 0.6)
	if err != nil {
		return domain.Event{}, err
	}
	ev.Access = &domain.AccessMeta{
		Vendor:       vendor,
		Method:       "vpn",
		TargetAsset:  simAssetRack,
		InWindow:     inWindow,
		SourceDevice: simForeignIP,
		SessionID:    "sim-session",
	}
	return ev, nil
}
