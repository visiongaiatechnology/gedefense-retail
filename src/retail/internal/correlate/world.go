package correlate

import (
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// World is the consumer-defined read model the correlation engine uses for
// context and incident deduplication. The composition root satisfies it with the
// in-memory registry; tests use a synthetic implementation.
type World interface {
	Sites() []domain.Site
	Asset(domain.AssetID) (domain.Asset, bool)
	Sensors(domain.SiteID) []domain.Sensor
	WindowsAt(domain.SiteID, time.Time) []domain.MaintenanceWindow
	Incidents(domain.SiteID) []domain.Incident
	Now() time.Time
}
