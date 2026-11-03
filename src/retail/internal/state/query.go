package state

import (
	"sort"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Query limits for the in-memory window.
const (
	defaultEventQueryLimit = 200
	maxEventQueryLimit     = 2000
)

// Assets returns the assets of a site ordered by identifier. An empty site
// returns every asset.
func (r *Registry) Assets(site domain.SiteID) []domain.Asset {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]domain.Asset, 0, len(r.assets))
	for _, id := range r.sortedAssetIDs() {
		asset := r.assets[id]
		if site != "" && asset.SiteID != site {
			continue
		}
		out = append(out, copyAsset(asset))
	}
	return out
}

// Asset returns one asset.
func (r *Registry) Asset(id domain.AssetID) (domain.Asset, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	asset, ok := r.assets[id]
	if !ok {
		return domain.Asset{}, false
	}
	return copyAsset(asset), true
}

// UpsertAsset validates and merges one asset.
func (r *Registry) UpsertAsset(asset domain.Asset) error {
	if err := asset.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.upsertAssetLocked(copyAsset(asset))
}

// Sensors returns the sensors of a site ordered by identifier. An empty site
// returns every sensor.
func (r *Registry) Sensors(site domain.SiteID) []domain.Sensor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]domain.Sensor, 0, len(r.sensors))
	for _, id := range r.sortedSensorIDs() {
		sensor := r.sensors[id]
		if site != "" && sensor.SiteID != site {
			continue
		}
		out = append(out, sensor)
	}
	return out
}

// Sensor returns one sensor.
func (r *Registry) Sensor(id domain.SensorID) (domain.Sensor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sensor, ok := r.sensors[id]
	return sensor, ok
}

// UpsertSensor validates and merges one sensor.
func (r *Registry) UpsertSensor(sensor domain.Sensor) error {
	if err := sensor.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.upsertSensorLocked(sensor)
}

// Samples returns the buffered samples of a site at or after since, ordered by
// observation time and sensor identity.
func (r *Registry) Samples(site domain.SiteID, since time.Time) []domain.Sample {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sensorIDs := make([]domain.SensorID, 0, len(r.samples))
	for id, sensor := range r.sensors {
		if site != "" && sensor.SiteID != site {
			continue
		}
		if _, ok := r.samples[id]; ok {
			sensorIDs = append(sensorIDs, id)
		}
	}
	sort.Slice(sensorIDs, func(i, j int) bool { return sensorIDs[i] < sensorIDs[j] })

	out := make([]domain.Sample, 0, 256)
	for _, id := range sensorIDs {
		for _, sample := range r.samples[id] {
			if sample.At.Before(since) {
				continue
			}
			out = append(out, copySample(sample))
			if len(out) >= maxSamplesPerQuery {
				sortSamples(out)
				return out
			}
		}
	}
	sortSamples(out)
	return out
}

// SamplesFor returns the buffered samples of one sensor at or after since.
func (r *Registry) SamplesFor(sensor domain.SensorID, since time.Time) []domain.Sample {
	r.mu.RLock()
	defer r.mu.RUnlock()
	buffer := r.samples[sensor]
	out := make([]domain.Sample, 0, len(buffer))
	for _, sample := range buffer {
		if sample.At.Before(since) {
			continue
		}
		out = append(out, copySample(sample))
	}
	sortSamples(out)
	return out
}

// Events returns the recent event window filtered by q, newest first.
//
// The window is the live view of the stream; the durable history lives in the
// event store. A malformed time bound yields no results instead of silently
// ignoring the filter (the method signature cannot report an error).
func (r *Registry) Events(q ports.EventQuery) []domain.Event {
	since, sinceOK := parseQueryTime(q.Since)
	until, untilOK := parseQueryTime(q.Until)
	if !sinceOK || !untilOK {
		return nil
	}
	limit := q.Limit
	if limit <= 0 {
		limit = defaultEventQueryLimit
	}
	if limit > maxEventQueryLimit {
		limit = maxEventQueryLimit
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]domain.Event, 0, min(limit, len(r.events)))
	for i := len(r.events) - 1; i >= 0 && len(out) < limit; i-- {
		ev := r.events[i]
		if q.SiteID != "" && ev.SiteID != q.SiteID {
			continue
		}
		if q.Kind != "" && ev.Kind != q.Kind {
			continue
		}
		if q.AssetID != "" && ev.AssetID != q.AssetID {
			continue
		}
		if q.SensorID != "" && ev.SensorID != q.SensorID {
			continue
		}
		if !since.IsZero() && ev.ObservedAt.Before(since) {
			continue
		}
		if !until.IsZero() && !ev.ObservedAt.Before(until) {
			continue
		}
		out = append(out, copyEvent(ev))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ObservedAt.After(out[j].ObservedAt) })
	return out
}

// KnownPeer reports whether the communication relationship was already observed
// during the passive learning phase.
func (r *Registry) KnownPeer(src, dst, protocol string) bool {
	if src == "" || dst == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.peers[peerKey(src, dst, protocol)]
	return ok
}

// ObservePeer records one observed communication relationship.
func (r *Registry) ObservePeer(src, dst, protocol string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observePeerLocked(src, dst, protocol)
}

// PeerCount returns the number of distinct observed communication relationships.
func (r *Registry) PeerCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.peers)
}

// Peers returns the observed communication relationships as "src|dst|protocol"
// keys. It exists for diagnostics and the overview counters.
func (r *Registry) Peers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.peers))
	for key := range r.peers {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// peerKey builds the normalized relationship key.
func peerKey(src, dst, protocol string) string {
	return src + "|" + dst + "|" + protocol
}

// sortSamples orders samples by observation time, then sensor identity.
func sortSamples(samples []domain.Sample) {
	sort.SliceStable(samples, func(i, j int) bool {
		if !samples[i].At.Equal(samples[j].At) {
			return samples[i].At.Before(samples[j].At)
		}
		return samples[i].SensorID < samples[j].SensorID
	})
}

// parseQueryTime parses an optional RFC 3339 bound. ok=false marks a malformed
// value.
func parseQueryTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, true
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
