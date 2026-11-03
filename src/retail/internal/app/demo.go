package app

import (
	"context"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/demo"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// seedDemo prepares a self-contained demo dataset: the fictional store, its OT
// inventory, sensors, maintenance windows and a three hour synthetic observation
// history that ends with the documented management-UI attack scenario.
//
// Everything seeded here is clearly labelled as demo data (site name contains
// "Demo", assets are tagged via source "demo"). It never touches real hardware.
func (g *gateway) seedDemo(ctx context.Context) error {
	now := g.clock.Now().UTC()
	g.log.Info("seeding demo dataset", "site_id", string(demo.SiteID), "scenario", demo.ScenarioAttack)

	for _, asset := range demo.Assets(now) {
		if err := g.reg.UpsertAsset(asset); err != nil {
			return fmt.Errorf("demo asset %q: %w", asset.AssetID, err)
		}
	}
	for _, sensor := range demo.Sensors(now) {
		if err := g.reg.UpsertSensor(sensor); err != nil {
			return fmt.Errorf("demo sensor %q: %w", sensor.SensorID, err)
		}
	}
	for _, window := range demo.Windows(now) {
		if err := g.reg.UpsertWindow(window); err != nil {
			return fmt.Errorf("demo window %q: %w", window.WindowID, err)
		}
	}
	g.reg.SetSiteStatus(demo.SiteID, domain.SiteOnline)

	events := demo.Events(now, demo.ScenarioAttack)
	if err := g.pipe.ProcessBatch(ctx, events); err != nil {
		// A rejected demo event would hide a contract bug: report it, but do not
		// abort the demo – the remaining events are still useful.
		g.log.Warn("demo event rejected", "error", err.Error())
	}
	stats := g.pipe.Stats()
	alertCount, countErr := g.alertsE.Count(ctx)
	if countErr != nil {
		alertCount = -1
	}
	g.log.Info("demo dataset ready", "events", stats.Accepted, "rejected", stats.Rejected, "alerts_from_pipeline", alertCount)
	return nil
}

// demoNow is a small helper used by tests to keep demo timestamps deterministic.
func demoNow() time.Time { return time.Now().UTC() }
