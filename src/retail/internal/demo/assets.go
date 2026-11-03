package demo

import (
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Demo site identity. The identifiers are stable so that API examples, docs and
// the simulator all refer to the same fictional store.
const (
	SiteID = domain.SiteID("filiale-001")

	ZoneProcess     = domain.ZoneID("zone-ot-process")
	ZoneMonitoring  = domain.ZoneID("zone-ot-monitoring")
	ZoneRetailIT    = domain.ZoneID("zone-retail-it")
	ZoneManagement  = domain.ZoneID("zone-management")
	ZoneMaintenance = domain.ZoneID("zone-external-maint")

	ZoneColdMeat   = domain.ZoneID("zone-cool-meat")
	ZoneColdDairy  = domain.ZoneID("zone-cool-dairy")
	ZoneColdFrozen = domain.ZoneID("zone-cool-frozen")

	AssetDanfossAKSM = domain.AssetID("asset-danfoss-aksm800")
	AssetDixellXWEB  = domain.AssetID("asset-dixell-xweb")
	AssetCarelRack   = domain.AssetID("asset-carel-rack")
	AssetBMS         = domain.AssetID("asset-bms-bacnet")
	AssetMQTTGateway = domain.AssetID("asset-mqtt-gateway")
	AssetEdge        = domain.AssetID("asset-edge-gateway")
	AssetSwitch      = domain.AssetID("asset-switch-ot")

	SensorMeat1  = domain.SensorID("sensor-meat-01-air")
	SensorMeat2  = domain.SensorID("sensor-meat-02-air")
	SensorDairy  = domain.SensorID("sensor-dairy-01-air")
	SensorFrozen = domain.SensorID("sensor-frozen-01-air")
	SensorDoor   = domain.SensorID("sensor-meat-01-door")
)

// Site returns the demo store description (one supermarket).
func Site(now time.Time) domain.Site {
	return domain.Site{
		SiteID:    SiteID,
		TenantID:  "tenant-demo",
		Name:      "Markt Nord (Demo)",
		Country:   "DE",
		Timezone:  "Europe/Berlin",
		Status:    domain.SiteOnline,
		GatewayID: AssetEdge,
		Zones:     Zones(),
		CreatedAt: now.Add(-90 * 24 * time.Hour).UTC(),
		UpdatedAt: now.UTC(),
		Tags:      []string{"demo", "pilot"},
	}
}

// Zones returns the five blueprint zones of the demo site.
func Zones() []domain.Zone {
	return []domain.Zone{
		{ZoneID: ZoneProcess, SiteID: SiteID, Name: "OT-Prozess (Kälte)", Kind: domain.ZoneOTProcess, Purpose: "Verbundregler, Kühlstellenregler, Feldbus", Critical: true},
		{ZoneID: ZoneMonitoring, SiteID: SiteID, Name: "OT-Monitoring (TAP)", Kind: domain.ZoneOTMonitoring, Purpose: "Passiver Netzwerk-TAP / SPAN", Critical: true},
		{ZoneID: ZoneRetailIT, SiteID: SiteID, Name: "Retail-IT", Kind: domain.ZoneRetailIT, Purpose: "Kasse, Office, Warenwirtschaft"},
		{ZoneID: ZoneManagement, SiteID: SiteID, Name: "Management", Kind: domain.ZoneManagement, Purpose: "GeDefense-Gateway, Admin-Zugänge", Critical: true},
		{ZoneID: ZoneMaintenance, SiteID: SiteID, Name: "Externe Wartung", Kind: domain.ZoneExternalMaintenance, Purpose: "Dienstleister-Fernzugang"},
		{ZoneID: ZoneColdMeat, SiteID: SiteID, Name: "Kühlbereich Fleisch", Kind: domain.ZoneCoolingArea, Purpose: "Fleisch-/Fisch-Kühlregale", Critical: true},
		{ZoneID: ZoneColdDairy, SiteID: SiteID, Name: "Kühlbereich Molkerei", Kind: domain.ZoneCoolingArea, Purpose: "Molkerei-/Frischeregale", Critical: true},
		{ZoneID: ZoneColdFrozen, SiteID: SiteID, Name: "Tiefkühlbereich", Kind: domain.ZoneCoolingArea, Purpose: "Tiefkühlregale und TK-Lager", Critical: true},
	}
}

// Assets returns the demo asset inventory. Device families and lifecycles follow
// the researched DE/EU landscape (docs/retail/vendor-landscape.md).
func Assets(now time.Time) []domain.Asset {
	first := now.Add(-30 * 24 * time.Hour).UTC()
	return []domain.Asset{
		{
			AssetID: AssetDanfossAKSM, SiteID: SiteID, ZoneID: ZoneProcess,
			Name: "Kälte-Supervisor StoreView", Type: domain.AssetRefrigerationController,
			Vendor: "Danfoss", Model: "AK-SM 800", FirmwareVersion: "4.2",
			FirmwareSource: "manual", FirmwareConfidence: 0.6,
			Protocols: []string{"modbus_tcp", "http"},
			NetworkIDs: []domain.NetworkIdentifier{
				{Kind: domain.NetIDIP, Value: "10.10.20.10", Source: "pcap.tap", Confidence: 0.9, LastSeen: now.UTC()},
			},
			Criticality: domain.CriticalityCritical, Confidence: 0.8,
			Classification: domain.ClassificationAuto,
			Lifecycle:      domain.LifecycleEOL, LifecycleSource: "ot-catalog:danfoss-ak-sm-800",
			ManagementInterface: true,
			Source:              "passive discovery",
			FirstSeenAt:         first, LastSeenAt: now.UTC(),
		},
		{
			AssetID: AssetDixellXWEB, SiteID: SiteID, ZoneID: ZoneProcess,
			Name: "Fernüberwachung XWEB", Type: domain.AssetRefrigerationController,
			Vendor: "Copeland/Dixell", Model: "XWEB",
			Protocols: []string{"http"},
			NetworkIDs: []domain.NetworkIdentifier{
				{Kind: domain.NetIDIP, Value: "10.10.20.11", Source: "pcap.tap", Confidence: 0.9, LastSeen: now.UTC()},
			},
			Criticality: domain.CriticalityCritical, Confidence: 0.75,
			Classification: domain.ClassificationAuto,
			Lifecycle:      domain.LifecycleUnknown, LifecycleSource: "ot-catalog:copeland-xweb",
			ManagementInterface: true,
			Source:              "passive discovery",
			FirstSeenAt:         first, LastSeenAt: now.UTC(),
		},
		{
			AssetID: AssetCarelRack, SiteID: SiteID, ZoneID: ZoneProcess,
			Name: "Verbundregler Kälte", Type: domain.AssetRefrigerationController,
			Vendor: "Carel", Model: "pRack",
			Protocols: []string{"modbus_tcp"},
			NetworkIDs: []domain.NetworkIdentifier{
				{Kind: domain.NetIDIP, Value: "10.10.20.12", Source: "pcap.tap", Confidence: 0.85, LastSeen: now.UTC()},
			},
			Criticality: domain.CriticalityHigh, Confidence: 0.7,
			Classification: domain.ClassificationAuto,
			Lifecycle:      domain.LifecycleUnknown,
			Source:         "passive discovery",
			FirstSeenAt:    first, LastSeenAt: now.UTC(),
		},
		{
			AssetID: AssetBMS, SiteID: SiteID, ZoneID: ZoneProcess,
			Name: "Gebäudeautomation", Type: domain.AssetBMS,
			Vendor: "unbekannt", Protocols: []string{"bacnet_ip"},
			NetworkIDs: []domain.NetworkIdentifier{
				{Kind: domain.NetIDIP, Value: "10.10.20.20", Source: "pcap.tap", Confidence: 0.8, LastSeen: now.UTC()},
			},
			Criticality: domain.CriticalityMedium, Confidence: 0.5,
			Classification: domain.ClassificationAuto,
			Lifecycle:      domain.LifecycleUnknown,
			Source:         "passive discovery",
			FirstSeenAt:    first, LastSeenAt: now.UTC(),
		},
		{
			AssetID: AssetMQTTGateway, SiteID: SiteID, ZoneID: ZoneProcess,
			Name: "IoT-Sensor-Gateway", Type: domain.AssetSensorGateway,
			Protocols: []string{"mqtt"},
			NetworkIDs: []domain.NetworkIdentifier{
				{Kind: domain.NetIDIP, Value: "10.10.20.30", Source: "pcap.tap", Confidence: 0.85, LastSeen: now.UTC()},
			},
			Criticality: domain.CriticalityHigh, Confidence: 0.7,
			Classification: domain.ClassificationAuto,
			Lifecycle:      domain.LifecycleUnknown,
			Source:         "passive discovery",
			FirstSeenAt:    first, LastSeenAt: now.UTC(),
		},
		{
			AssetID: AssetEdge, SiteID: SiteID, ZoneID: ZoneManagement,
			Name: "GeDefense Retail Edge", Type: domain.AssetEdgeGateway,
			Criticality: domain.CriticalityCritical, Confidence: 1,
			Classification: domain.ClassificationManual,
			Lifecycle:      domain.LifecycleActive,
			Source:         "config", FirstSeenAt: first, LastSeenAt: now.UTC(),
		},
		{
			AssetID: AssetSwitch, SiteID: SiteID, ZoneID: ZoneMonitoring,
			Name: "OT-Switch mit SPAN", Type: domain.AssetNetworkDevice,
			Criticality: domain.CriticalityHigh, Confidence: 0.9,
			Classification: domain.ClassificationAuto,
			Lifecycle:      domain.LifecycleActive,
			Source:         "config", FirstSeenAt: first, LastSeenAt: now.UTC(),
		},
	}
}

// Sensors returns the demo measurement points.
func Sensors(now time.Time) []domain.Sensor {
	return []domain.Sensor{
		{SensorID: SensorMeat1, SiteID: SiteID, AssetID: AssetDanfossAKSM, ZoneID: ZoneColdMeat, Name: "Fleisch 1 Luft", Metric: "air_temperature", Unit: domain.UnitCelsius, Kind: "air", Critical: true, LastSeenAt: now.UTC()},
		{SensorID: SensorMeat2, SiteID: SiteID, AssetID: AssetDixellXWEB, ZoneID: ZoneColdMeat, Name: "Fleisch 1 Vergleichssonde", Metric: "air_temperature", Unit: domain.UnitCelsius, Kind: "air", Independent: true, Critical: true, LastSeenAt: now.UTC()},
		{SensorID: SensorDairy, SiteID: SiteID, AssetID: AssetCarelRack, ZoneID: ZoneColdDairy, Name: "Molkerei Luft", Metric: "air_temperature", Unit: domain.UnitCelsius, Kind: "air", Critical: true, LastSeenAt: now.UTC()},
		{SensorID: SensorFrozen, SiteID: SiteID, AssetID: AssetCarelRack, ZoneID: ZoneColdFrozen, Name: "Tiefkühl Luft", Metric: "air_temperature", Unit: domain.UnitCelsius, Kind: "air", Critical: true, LastSeenAt: now.UTC()},
		{SensorID: SensorDoor, SiteID: SiteID, AssetID: AssetDanfossAKSM, ZoneID: ZoneColdMeat, Name: "Fleisch 1 Tür", Metric: "door_state", Unit: domain.UnitBoolean, Kind: "door", LastSeenAt: now.UTC()},
	}
}
