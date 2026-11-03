package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Apply validates one event and updates the world model. Invalid events are
// rejected with an error and counted; they are never partially applied.
func (r *Registry) Apply(ctx context.Context, ev domain.Event) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("state: apply event: %w", err)
	}
	if err := ev.Validate(); err != nil {
		r.mu.Lock()
		r.rejected++
		r.mu.Unlock()
		return fmt.Errorf("state: apply event: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.ingested++
	r.lastEventAt = maxTime(r.lastEventAt, ev.ObservedAt)
	r.touchSiteLocked(ev.SiteID, ev.ObservedAt)
	r.appendEventLocked(ev)

	switch ev.Kind {
	case domain.EventTelemetry:
		if err := r.addSampleLocked(ev); err != nil && !errors.Is(err, ErrCapacity) {
			return fmt.Errorf("state: apply event %q: %w", ev.EventID, err)
		}
	case domain.EventAssetSeen:
		if ev.AssetID != "" {
			if err := r.upsertAssetLocked(r.assetFromEventLocked(ev)); err != nil && !errors.Is(err, ErrCapacity) {
				return fmt.Errorf("state: apply event %q: %w", ev.EventID, err)
			}
		}
	case domain.EventFlow:
		if ev.Flow != nil {
			r.observePeerLocked(ev.Flow.SrcIP, ev.Flow.DstIP, ev.Flow.Protocol)
		}
	}
	return nil
}

// touchSiteLocked refreshes last-seen and reachability of the event's site.
func (r *Registry) touchSiteLocked(siteID domain.SiteID, at time.Time) {
	site, ok := r.sites[siteID]
	if !ok {
		return
	}
	site.LastSeenAt = maxTime(site.LastSeenAt, at)
	site.Status = domain.SiteOnline
	site.UpdatedAt = r.clock.Now().UTC()
	r.sites[siteID] = site
	r.siteStatus[siteID] = site.Status
}

// appendEventLocked inserts the event into the bounded recent-event window.
func (r *Registry) appendEventLocked(ev domain.Event) {
	r.events = append(r.events, copyEvent(ev))
	if overflow := len(r.events) - r.eventLimit; overflow > 0 {
		kept := make([]domain.Event, r.eventLimit)
		copy(kept, r.events[overflow:])
		r.events = kept
	}
}

// addSampleLocked buffers a telemetry sample. Samples without a sensor identity
// cannot be keyed and are not buffered; the event itself is still stored.
func (r *Registry) addSampleLocked(ev domain.Event) error {
	if ev.SensorID == "" {
		return nil
	}
	sample, ok := domain.SampleFromMeasurement(ev)
	if !ok {
		return nil
	}
	if err := sample.Validate(); err != nil {
		return nil
	}
	if _, known := r.sensors[sample.SensorID]; !known {
		if r.sensorLimitReached(sample.SiteID) {
			r.sensorsDropped++
			warnCapacityOnce(r.warnedSensors, "sensor", sample.SiteID, r.sensorLimit, r.sensorsDropped)
			return fmt.Errorf("%w: sensor limit %d reached for site %q", ErrCapacity, r.sensorLimit, sample.SiteID)
		}
		if err := r.upsertSensorLocked(sensorFromSample(sample)); err != nil {
			return err
		}
	}
	buffer := append(r.samples[sample.SensorID], sample)
	if overflow := len(buffer) - r.sampleLimit; overflow > 0 {
		kept := make([]domain.Sample, r.sampleLimit)
		copy(kept, buffer[overflow:])
		buffer = kept
	}
	r.samples[sample.SensorID] = buffer

	sensor := r.sensors[sample.SensorID]
	sensor.LastSeenAt = maxTime(sensor.LastSeenAt, sample.At)
	r.sensors[sample.SensorID] = sensor
	return nil
}

// sensorFromSample derives a placeholder sensor from its first sample. The
// operator-facing name and criticality stay conservative until the operator or
// the discovery engine classifies the device.
func sensorFromSample(sample domain.Sample) domain.Sensor {
	return domain.Sensor{
		SensorID:   sample.SensorID,
		SiteID:     sample.SiteID,
		AssetID:    sample.AssetID,
		ZoneID:     sample.ZoneID,
		Name:       string(sample.SensorID),
		Metric:     sample.Metric,
		Unit:       sample.Unit,
		LastSeenAt: sample.At,
	}
}

// assetFromEventLocked derives a provisional asset classification from a passive
// asset_seen event. The discovery engine refines it later; the registry never
// claims more than the event proves.
func (r *Registry) assetFromEventLocked(ev domain.Event) domain.Asset {
	now := r.clock.Now().UTC()
	asset := domain.Asset{
		AssetID:        ev.AssetID,
		SiteID:         ev.SiteID,
		ZoneID:         ev.ZoneID,
		Name:           string(ev.AssetID),
		Type:           domain.AssetUnknown,
		Criticality:    domain.CriticalityLow,
		Confidence:     ev.Confidence,
		Classification: domain.ClassificationAuto,
		Source:         ev.Source,
		FirstSeenAt:    ev.ObservedAt,
		LastSeenAt:     ev.ObservedAt,
	}
	if asset.FirstSeenAt.IsZero() {
		asset.FirstSeenAt = now
		asset.LastSeenAt = now
	}
	if ev.Device != nil {
		device := ev.Device
		asset.Vendor = device.Vendor
		asset.Model = device.Model
		if device.Hostname != "" {
			asset.Name = device.Hostname
		}
		if device.IP != "" {
			asset.NetworkIDs = append(asset.NetworkIDs, domain.NetworkIdentifier{
				Kind: domain.NetIDIP, Value: device.IP, Source: ev.Source,
				Confidence: ev.Confidence, FirstSeen: ev.ObservedAt, LastSeen: ev.ObservedAt,
			})
		}
		if device.MAC != "" {
			asset.NetworkIDs = append(asset.NetworkIDs, domain.NetworkIdentifier{
				Kind: domain.NetIDMAC, Value: device.MAC, Source: ev.Source,
				Confidence: ev.Confidence, FirstSeen: ev.ObservedAt, LastSeen: ev.ObservedAt,
			})
		}
		if device.Hostname != "" {
			asset.NetworkIDs = append(asset.NetworkIDs, domain.NetworkIdentifier{
				Kind: domain.NetIDHostname, Value: device.Hostname, Source: ev.Source,
				Confidence: ev.Confidence, FirstSeen: ev.ObservedAt, LastSeen: ev.ObservedAt,
			})
		}
	}
	if ev.Protocol != "" {
		asset.Protocols = append(asset.Protocols, ev.Protocol)
	}
	return asset
}

// upsertAssetLocked stores an asset, merging passive re-observations without
// overwriting operator-owned fields. A new asset beyond the per-site limit is
// rejected with ErrCapacity (counted and logged once per site).
func (r *Registry) upsertAssetLocked(incoming domain.Asset) error {
	existing, known := r.assets[incoming.AssetID]
	if !known {
		if r.assetLimitReached(incoming.SiteID) {
			r.assetsDropped++
			warnCapacityOnce(r.warnedAssets, "asset", incoming.SiteID, r.assetLimit, r.assetsDropped)
			return fmt.Errorf("%w: asset limit %d reached for site %q", ErrCapacity, r.assetLimit, incoming.SiteID)
		}
		if incoming.FirstSeenAt.IsZero() {
			incoming.FirstSeenAt = r.clock.Now().UTC()
		}
		if incoming.LastSeenAt.IsZero() {
			incoming.LastSeenAt = incoming.FirstSeenAt
		}
		r.assets[incoming.AssetID] = copyAsset(incoming)
		r.assetCount[incoming.SiteID]++
		return nil
	}

	merged := existing
	merged.FirstSeenAt = minTime(existing.FirstSeenAt, incoming.FirstSeenAt)
	merged.LastSeenAt = maxTime(existing.LastSeenAt, incoming.LastSeenAt)
	if merged.Name == "" || merged.Name == string(merged.AssetID) {
		if incoming.Name != "" {
			merged.Name = incoming.Name
		}
	}
	if merged.Type == domain.AssetUnknown || merged.Type == "" {
		if incoming.Type != "" && incoming.Type != domain.AssetUnknown {
			merged.Type = incoming.Type
		}
	}
	if merged.ZoneID == "" {
		merged.ZoneID = incoming.ZoneID
	}
	if merged.Vendor == "" {
		merged.Vendor = incoming.Vendor
	}
	if merged.Model == "" {
		merged.Model = incoming.Model
	}
	if merged.FirmwareVersion == "" {
		merged.FirmwareVersion = incoming.FirmwareVersion
	}
	if merged.FirmwareSource == "" {
		merged.FirmwareSource = incoming.FirmwareSource
	}
	if incoming.Classification == domain.ClassificationManual {
		merged.Classification = incoming.Classification
	}
	if incoming.Confidence > merged.Confidence {
		merged.Confidence = incoming.Confidence
	}
	merged.NetworkIDs = mergeNetworkIDs(merged.NetworkIDs, incoming.NetworkIDs)
	merged.Protocols = mergeStrings(merged.Protocols, incoming.Protocols, maxProtocols)
	r.assets[merged.AssetID] = copyAsset(merged)
	return nil
}

// upsertSensorLocked stores a sensor, merging re-observations conservatively. A
// new sensor beyond the per-site limit is rejected with ErrCapacity.
func (r *Registry) upsertSensorLocked(incoming domain.Sensor) error {
	existing, known := r.sensors[incoming.SensorID]
	if !known {
		if r.sensorLimitReached(incoming.SiteID) {
			r.sensorsDropped++
			warnCapacityOnce(r.warnedSensors, "sensor", incoming.SiteID, r.sensorLimit, r.sensorsDropped)
			return fmt.Errorf("%w: sensor limit %d reached for site %q", ErrCapacity, r.sensorLimit, incoming.SiteID)
		}
		r.sensors[incoming.SensorID] = incoming
		r.sensorCount[incoming.SiteID]++
		return nil
	}
	merged := existing
	if merged.Name == "" || merged.Name == string(merged.SensorID) {
		if incoming.Name != "" {
			merged.Name = incoming.Name
		}
	}
	if merged.Metric == "" {
		merged.Metric = incoming.Metric
	}
	if merged.Unit == "" || merged.Unit == domain.UnitUnknown {
		if incoming.Unit != "" {
			merged.Unit = incoming.Unit
		}
	}
	if merged.AssetID == "" {
		merged.AssetID = incoming.AssetID
	}
	if merged.ZoneID == "" {
		merged.ZoneID = incoming.ZoneID
	}
	merged.LastSeenAt = maxTime(merged.LastSeenAt, incoming.LastSeenAt)
	r.sensors[merged.SensorID] = merged
	return nil
}

// observePeerLocked records one observed communication relationship.
func (r *Registry) observePeerLocked(src, dst, protocol string) {
	if src == "" || dst == "" {
		return
	}
	if len(r.peers) >= r.peerLimit {
		return
	}
	r.peers[peerKey(src, dst, protocol)] = struct{}{}
}

// mergeNetworkIDs unions two identifier lists, keeping the newest observation.
func mergeNetworkIDs(existing, incoming []domain.NetworkIdentifier) []domain.NetworkIdentifier {
	out := append([]domain.NetworkIdentifier(nil), existing...)
	for _, candidate := range incoming {
		if candidate.Value == "" {
			continue
		}
		found := false
		for i := range out {
			if out[i].Kind == candidate.Kind && out[i].Value == candidate.Value {
				out[i].LastSeen = maxTime(out[i].LastSeen, candidate.LastSeen)
				if candidate.Confidence > out[i].Confidence {
					out[i].Confidence = candidate.Confidence
				}
				found = true
				break
			}
		}
		if found {
			continue
		}
		if len(out) >= maxNetworkIDs {
			break
		}
		out = append(out, candidate)
	}
	return out
}

// mergeStrings appends values that are not yet present, bounded by limit.
func mergeStrings(existing, incoming []string, limit int) []string {
	out := append([]string(nil), existing...)
	for _, candidate := range incoming {
		if candidate == "" {
			continue
		}
		duplicate := false
		for _, value := range out {
			if value == candidate {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, candidate)
	}
	return out
}
