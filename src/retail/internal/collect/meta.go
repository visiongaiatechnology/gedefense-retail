// Event construction helpers shared by every adapter and decoder.
package collect

import (
	"context"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Meta is the stable provenance an adapter or decoder stamps onto each event.
// It is a value type so that it can be copied into per-connection decoders.
type Meta struct {
	SiteID     domain.SiteID
	ZoneID     domain.ZoneID
	Source     string
	Collection string
	Protocol   string
	Clock      ports.Clock
}

// Validate checks the mandatory provenance fields. Collection must be one of
// the three product-wide labels; an adapter can therefore never invent a new
// collection method.
func (m Meta) Validate() error {
	if err := m.SiteID.Validate(); err != nil {
		return fmt.Errorf("collect: meta site: %w", err)
	}
	if m.Source == "" {
		return fmt.Errorf("collect: meta source is required")
	}
	if !ValidCollection(m.Collection) {
		return fmt.Errorf("collect: meta collection %q is invalid", m.Collection)
	}
	if m.Protocol != "" && len(m.Protocol) > 32 {
		return fmt.Errorf("collect: meta protocol %q too long", m.Protocol)
	}
	if m.ZoneID != "" {
		if err := m.ZoneID.Validate(); err != nil {
			return fmt.Errorf("collect: meta zone: %w", err)
		}
	}
	return nil
}

// Now returns the current UTC time from the injected clock.
func (m Meta) Now() time.Time {
	if m.Clock != nil {
		return m.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

// NewEvent creates the base event (id, time, provenance) for one observation.
// observedAt is the device/packet time; when zero the meta clock time is used.
func (m Meta) NewEvent(kind domain.EventKind, observedAt time.Time) (domain.Event, error) {
	if err := m.Validate(); err != nil {
		return domain.Event{}, err
	}
	if !kind.Valid() {
		return domain.Event{}, fmt.Errorf("collect: invalid event kind %q", kind)
	}
	id, err := NewEventID()
	if err != nil {
		return domain.Event{}, err
	}
	now := m.Now()
	if observedAt.IsZero() {
		observedAt = now
	}
	return domain.Event{
		EventID:    id,
		Kind:       kind,
		SiteID:     m.SiteID,
		ZoneID:     m.ZoneID,
		ObservedAt: observedAt.UTC(),
		ReceivedAt: now,
		Source:     m.Source,
		Collection: m.Collection,
		Protocol:   m.Protocol,
		Confidence: 0.5,
		Quality:    domain.QualityGood,
	}, nil
}

// FlowEvent builds a flow event from the passive metadata.
func (m Meta) FlowEvent(flow domain.FlowMeta, confidence float64, observedAt time.Time) (domain.Event, error) {
	ev, err := m.NewEvent(domain.EventFlow, observedAt)
	if err != nil {
		return domain.Event{}, err
	}
	ev.Flow = &flow
	ev.Confidence = clamp(confidence)
	return ev, nil
}

// AssetSeenEvent builds an asset_seen event from passive device metadata.
func (m Meta) AssetSeenEvent(dev domain.DeviceMeta, confidence float64, observedAt time.Time) (domain.Event, error) {
	ev, err := m.NewEvent(domain.EventAssetSeen, observedAt)
	if err != nil {
		return domain.Event{}, err
	}
	ev.Device = &dev
	ev.Confidence = clamp(confidence)
	return ev, nil
}

// TelemetryEvent builds a telemetry event from a normalized measurement.
func (m Meta) TelemetryEvent(sensor domain.SensorID, asset domain.AssetID, meas domain.Measurement, confidence float64, observedAt time.Time) (domain.Event, error) {
	ev, err := m.NewEvent(domain.EventTelemetry, observedAt)
	if err != nil {
		return domain.Event{}, err
	}
	ev.SensorID = sensor
	ev.AssetID = asset
	ev.Measurement = &meas
	ev.Quality = meas.Quality
	ev.Confidence = clamp(confidence)
	return ev, nil
}

// WriteAttemptEvent builds the observation of a write attempt. The event only
// records what was seen on the wire; nothing is ever executed.
func (m Meta) WriteAttemptEvent(attempt domain.WriteAttempt, confidence float64, observedAt time.Time) (domain.Event, error) {
	ev, err := m.NewEvent(domain.EventWriteAttempt, observedAt)
	if err != nil {
		return domain.Event{}, err
	}
	ev.WriteAttempt = &attempt
	ev.Confidence = clamp(confidence)
	return ev, nil
}

func clamp(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	}
	return v
}

// EmitAll forwards events in order and stops at the first sink error. The
// framework's counting sink has already counted the failure; adapters use the
// returned error only to decide whether to keep the loop going.
func EmitAll(ctx context.Context, sink ports.Sink, events []domain.Event) error {
	for i := range events {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := sink.Emit(ctx, events[i]); err != nil {
			return err
		}
	}
	return nil
}
