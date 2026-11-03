package demo

import (
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Policy returns the demo operator policy. The limits are illustrative examples
// for one fictional store – real limits are set and owned by the operator.
func Policy(now time.Time) domain.Policy {
	f := func(v float64) *float64 { return &v }
	p := domain.DefaultPolicy(SiteID, now)
	p.Reason = "Demo-Policy für fiktive Filiale (Beispielwerte, Betreiber verantwortet real)"
	p.Temperature.Limits = []domain.TemperatureLimit{
		{ZoneID: ZoneColdMeat, Metric: "air_temperature", MinC: f(1.0), MaxC: f(5.0), MaxRateCPerMin: f(0.20), SetpointToleranceC: f(1.0)},
		{ZoneID: ZoneColdDairy, Metric: "air_temperature", MinC: f(1.0), MaxC: f(7.0), MaxRateCPerMin: f(0.20), SetpointToleranceC: f(1.0)},
		{ZoneID: ZoneColdFrozen, Metric: "air_temperature", MinC: f(-22.0), MaxC: f(-15.0), MaxRateCPerMin: f(0.30), SetpointToleranceC: f(2.0)},
	}
	p.Sensors = domain.SensorPolicy{DivergenceC: f(1.5), DivergenceWindowS: 600}
	p.Network = domain.NetworkPolicy{
		BaselineRequired:       false,
		LearnedBaselineWindowS: 3600,
		UnknownPeerGraceS:      600,
		AllowedPairs: []domain.AllowedPair{
			{SourceAssetID: AssetEdge, TargetAssetID: AssetDanfossAKSM, Protocol: "modbus_tcp", Port: 502, Note: "Edge liest Status"},
			{SourceAssetID: AssetMQTTGateway, TargetAssetID: AssetEdge, Protocol: "mqtt", Port: 1883, Note: "Telemetrie-Gateway"},
		},
	}
	p.Maintenance = domain.MaintenancePolicy{
		RequireWindow:  true,
		GracePeriodS:   300,
		TrustedVendors: []string{"Kältetechnik Müller GmbH"},
	}
	p.DataQuality = domain.DataQualityPolicy{FrozenValueWindowS: 1800, TelemetryGapS: 900, MaxClockSkewS: 300}
	p.Retention = domain.RetentionPolicy{EventDays: 30, AlertDays: 180, AuditDays: 365, MaxEventMB: 2048, MaxSpoolMB: 512}
	p.Alerting = domain.AlertingPolicy{MinNotifySeverity: domain.SeverityHigh}
	return p
}

// Windows returns the demo maintenance windows: one closed window yesterday and
// one planned window tomorrow. The simulated attack therefore happens outside
// any approved window.
func Windows(now time.Time) []domain.MaintenanceWindow {
	y := now.Add(-24 * time.Hour).Truncate(time.Hour)
	tomorrow := now.Add(18 * time.Hour).Truncate(time.Hour)
	return []domain.MaintenanceWindow{
		{
			WindowID:       "win-demo-20261102",
			SiteID:         SiteID,
			ZoneIDs:        []domain.ZoneID{ZoneProcess},
			Vendor:         "Kältetechnik Müller GmbH",
			TicketRef:      "SVC-2026-1102",
			ApprovedBy:     "admin",
			ApprovedAt:     y.Add(-12 * time.Hour),
			StartsAt:       y.Add(6 * time.Hour),
			EndsAt:         y.Add(8 * time.Hour),
			TargetAssetIDs: []domain.AssetID{AssetDanfossAKSM, AssetCarelRack},
			Status:         domain.WindowClosed,
			CreatedAt:      y.Add(-13 * time.Hour),
			CreatedBy:      "admin",
			Notes:          "Halbjährliche Wartung Verbund",
		},
		{
			WindowID:       "win-demo-20261104",
			SiteID:         SiteID,
			ZoneIDs:        []domain.ZoneID{ZoneProcess},
			Vendor:         "Kältetechnik Müller GmbH",
			TicketRef:      "SVC-2026-1104",
			ApprovedBy:     "admin",
			ApprovedAt:     now.Add(-2 * time.Hour),
			StartsAt:       tomorrow,
			EndsAt:         tomorrow.Add(2 * time.Hour),
			TargetAssetIDs: []domain.AssetID{AssetDanfossAKSM},
			Status:         domain.WindowPlanned,
			CreatedAt:      now.Add(-2 * time.Hour),
			CreatedBy:      "admin",
			Notes:          "Geplanter Filterwechsel",
		},
	}
}
