package detect

import (
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// World is the consumer-defined read model the detection engine evaluates
// against. It is deliberately narrow: the composition root wires the in-memory
// registry into it, and tests implement it with synthetic data. The interface is
// defined here (and not in ports) because no other package needs to consume it.
//
// Semantics the implementation relies on:
//
//   - Policy returns the currently active operator policy of the site.
//   - Events returns events matching the query, newest-first or oldest-first;
//     rules never rely on ordering and always bound the query with Since/Limit.
//   - WindowsAt returns maintenance windows relevant at the given instant; rules
//     re-check containment because the window set is operator-owned state.
//   - KnownPeer/ObservePeer manage the passive communication baseline. Rules
//     treat the observation set as a hint and additionally verify history
//     through Events, because the pipeline may apply the current event to the
//     registry before detection runs.
//   - Now returns the same instant domain as the injected clock.
type World interface {
	Policy() domain.Policy
	Sites() []domain.Site
	Assets(domain.SiteID) []domain.Asset
	Asset(domain.AssetID) (domain.Asset, bool)
	Sensors(domain.SiteID) []domain.Sensor
	Samples(domain.SiteID, time.Time) []domain.Sample
	SamplesFor(domain.SensorID, time.Time) []domain.Sample
	Events(ports.EventQuery) []domain.Event
	WindowsAt(domain.SiteID, time.Time) []domain.MaintenanceWindow
	KnownPeer(src, dst, protocol string) bool
	ObservePeer(src, dst, protocol string)
	Now() time.Time
}
