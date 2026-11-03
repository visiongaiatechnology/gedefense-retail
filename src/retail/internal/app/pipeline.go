package app

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/alert"
	"github.com/visiongaiatechnology/gedefense/retail/internal/api"
	"github.com/visiongaiatechnology/gedefense/retail/internal/correlate"
	"github.com/visiongaiatechnology/gedefense/retail/internal/detect"
	"github.com/visiongaiatechnology/gedefense/retail/internal/discovery"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/policy"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
	"github.com/visiongaiatechnology/gedefense/retail/internal/state"
)

// pipeline turns normalized observations into stored events, registry state and
// alerts. It is the single place where the detection and correlation engines are
// invoked; collectors and the simulator ingest path both go through it.
type pipeline struct {
	log       *slog.Logger
	clock     ports.Clock
	events    ports.EventStore
	reg       *state.Registry
	policy    *policy.Manager
	detect    *detect.Engine
	correlate *correlate.Engine
	alerts    *alert.Engine
	discovery *discovery.Discoverer
	spool     ports.Spool
	hub       *api.Hub
	siteID    domain.SiteID

	accepted atomic.Uint64
	rejected atomic.Uint64
	spooled  atomic.Uint64
}

type pipelineDeps struct {
	Log       *slog.Logger
	Clock     ports.Clock
	Events    ports.EventStore
	Registry  *state.Registry
	Policy    *policy.Manager
	Detect    *detect.Engine
	Correlate *correlate.Engine
	Alerts    *alert.Engine
	Discovery *discovery.Discoverer
	Spool     ports.Spool
	Hub       *api.Hub
	SiteID    domain.SiteID
}

func newPipeline(d pipelineDeps) *pipeline {
	return &pipeline{
		log: d.Log, clock: d.Clock, events: d.Events, reg: d.Registry,
		policy: d.Policy, detect: d.Detect, correlate: d.Correlate,
		alerts: d.Alerts, discovery: d.Discovery, spool: d.Spool, hub: d.Hub, siteID: d.SiteID,
	}
}

// Emit implements ports.Sink so collectors can feed the pipeline directly.
func (p *pipeline) Emit(ctx context.Context, ev domain.Event) error {
	if err := p.ProcessBatch(ctx, []domain.Event{ev}); err != nil {
		return err
	}
	return nil
}

// ProcessBatch validates, stores and evaluates a batch of events. Events that
// fail validation are counted and reported, never silently repaired. The
// returned error is non-nil if at least one event was rejected.
func (p *pipeline) ProcessBatch(ctx context.Context, events []domain.Event) error {
	if ctx == nil {
		return errNilContext
	}
	var firstErr error
	for i := range events {
		ev := events[i]
		if err := ev.Validate(); err != nil {
			p.rejected.Add(1)
			if firstErr == nil {
				firstErr = err
			}
			p.log.Warn("event rejected", "event_id", string(ev.EventID), "kind", string(ev.Kind), "error", err.Error())
			continue
		}
		if err := p.store(ctx, ev); err != nil {
			p.rejected.Add(1)
			if firstErr == nil {
				firstErr = err
			}
			p.log.Warn("event store failed", "event_id", string(ev.EventID), "error", err.Error())
			continue
		}
		p.accepted.Add(1)
		p.evaluate(ctx, ev)
	}
	return firstErr
}

// store persists the event, applies it to the registry and learns assets.
func (p *pipeline) store(ctx context.Context, ev domain.Event) error {
	if err := p.events.Append(ctx, ev); err != nil {
		return err
	}
	if err := p.reg.Apply(ctx, ev); err != nil {
		return err
	}
	if ev.SiteID != "" {
		if st, ok := p.reg.SiteStatus(ev.SiteID); !ok || st != domain.SiteOnline {
			p.reg.SetSiteStatus(ev.SiteID, domain.SiteOnline)
		}
	}
	if p.discovery != nil {
		if asset, ok := p.discovery.Observe(ev); ok {
			if err := p.reg.UpsertAsset(asset); err != nil {
				p.log.Debug("asset hypothesis rejected", "asset_id", string(asset.AssetID), "error", err.Error())
			}
		}
	}
	if p.spool != nil {
		if err := p.spool.Enqueue(ctx, ev); err != nil {
			p.log.Warn("spool enqueue failed", "event_id", string(ev.EventID), "error", err.Error())
		} else {
			p.spooled.Add(1)
		}
	}
	p.publishEvent(ev)
	return nil
}

// evaluate runs event-based detection, the alert workflow and correlation.
func (p *pipeline) evaluate(ctx context.Context, ev domain.Event) {
	alerts := p.detect.EvaluateEvent(ctx, ev)
	if len(alerts) == 0 {
		return
	}
	p.observeAlerts(ctx, alerts)
}

// observeAlerts persists alerts and runs the correlation chain, which may
// escalate alerts and create incidents.
func (p *pipeline) observeAlerts(ctx context.Context, alerts []domain.Alert) {
	if len(alerts) == 0 {
		return
	}
	if err := p.alerts.Observe(ctx, alerts); err != nil {
		p.log.Error("alert observe failed", "count", len(alerts), "error", err.Error())
		return
	}
	updates, incidents := p.correlate.Observe(ctx, alerts)
	if len(updates) > 0 {
		if err := p.alerts.Observe(ctx, updates); err != nil {
			p.log.Error("correlated alert update failed", "count", len(updates), "error", err.Error())
		}
	}
	for i := range incidents {
		inc := incidents[i]
		if err := p.reg.UpsertIncident(inc); err != nil {
			p.log.Error("incident upsert failed", "incident_id", string(inc.IncidentID), "error", err.Error())
			continue
		}
		if p.hub != nil {
			p.hub.Publish("incident", inc)
		}
	}
}

// Tick runs the time-based rules (frozen values, telemetry gaps, clock skew,
// lifecycle exposure) once per detection interval.
func (p *pipeline) Tick(ctx context.Context) {
	alerts := p.detect.EvaluateTick(ctx)
	p.observeAlerts(ctx, alerts)
}

// DrainSpool forwards buffered events to the central plane in bounded batches.
func (p *pipeline) DrainSpool(ctx context.Context) {
	if p.spool == nil {
		return
	}
	for i := 0; i < 4; i++ {
		batch, err := p.spool.Drain(ctx, 100)
		if err != nil {
			p.log.Warn("spool drain failed", "error", err.Error())
			return
		}
		if len(batch) == 0 {
			return
		}
	}
}

// publishEvent sends a small metadata-only event to the SSE hub. Packet payloads
// are never published because they are never collected.
func (p *pipeline) publishEvent(ev domain.Event) {
	if p.hub == nil {
		return
	}
	meta := struct {
		EventID    domain.EventID   `json:"event_id"`
		Kind       domain.EventKind `json:"kind"`
		SiteID     domain.SiteID    `json:"site_id"`
		AssetID    domain.AssetID   `json:"asset_id,omitempty"`
		SensorID   domain.SensorID  `json:"sensor_id,omitempty"`
		ObservedAt time.Time        `json:"observed_at"`
	}{ev.EventID, ev.Kind, ev.SiteID, ev.AssetID, ev.SensorID, ev.ObservedAt}
	p.hub.Publish("event", meta)
}

// Stats returns the observed pipeline counters (used by the self-check report).
type Stats struct {
	Accepted uint64
	Rejected uint64
	Spooled  uint64
}

// Stats returns a snapshot of the pipeline counters.
func (p *pipeline) Stats() Stats {
	return Stats{Accepted: p.accepted.Load(), Rejected: p.rejected.Load(), Spooled: p.spooled.Load()}
}
