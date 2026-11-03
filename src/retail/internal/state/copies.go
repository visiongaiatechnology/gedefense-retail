package state

import (
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// copySite deep-copies a site including its zones.
func copySite(s domain.Site) domain.Site {
	out := s
	out.Zones = append([]domain.Zone(nil), s.Zones...)
	out.Tags = append([]string(nil), s.Tags...)
	return out
}

// copyAsset deep-copies an asset including its identifier slices.
func copyAsset(a domain.Asset) domain.Asset {
	out := a
	out.NetworkIDs = append([]domain.NetworkIdentifier(nil), a.NetworkIDs...)
	out.Protocols = append([]string(nil), a.Protocols...)
	return out
}

// copySample deep-copies a sample (including the optional setpoint pointer).
func copySample(s domain.Sample) domain.Sample {
	out := s
	if s.Setpoint != nil {
		setpoint := *s.Setpoint
		out.Setpoint = &setpoint
	}
	return out
}

// copyEvent deep-copies an event including every optional metadata block.
func copyEvent(e domain.Event) domain.Event {
	out := e
	if e.Measurement != nil {
		measurement := *e.Measurement
		if e.Measurement.Setpoint != nil {
			setpoint := *e.Measurement.Setpoint
			measurement.Setpoint = &setpoint
		}
		out.Measurement = &measurement
	}
	if e.Flow != nil {
		flow := *e.Flow
		out.Flow = &flow
	}
	if e.Device != nil {
		device := *e.Device
		out.Device = &device
	}
	if e.WriteAttempt != nil {
		attempt := *e.WriteAttempt
		out.WriteAttempt = &attempt
	}
	if e.Access != nil {
		access := *e.Access
		out.Access = &access
	}
	if e.Integrity != nil {
		integrity := *e.Integrity
		out.Integrity = &integrity
	}
	if e.PayloadMeta != nil {
		meta := make(map[string]string, len(e.PayloadMeta))
		for k, v := range e.PayloadMeta {
			meta[k] = v
		}
		out.PayloadMeta = meta
	}
	return out
}

// copyWindow deep-copies a maintenance window.
func copyWindow(w domain.MaintenanceWindow) domain.MaintenanceWindow {
	out := w
	out.ZoneIDs = append([]domain.ZoneID(nil), w.ZoneIDs...)
	out.TargetAssetIDs = append([]domain.AssetID(nil), w.TargetAssetIDs...)
	out.AllowedSourceCIDRs = append([]string(nil), w.AllowedSourceCIDRs...)
	return out
}

// copyIncident deep-copies an incident including notes and correlation.
func copyIncident(i domain.Incident) domain.Incident {
	out := i
	out.AlertIDs = append([]domain.AlertID(nil), i.AlertIDs...)
	out.ZoneIDs = append([]domain.ZoneID(nil), i.ZoneIDs...)
	out.AssetIDs = append([]domain.AssetID(nil), i.AssetIDs...)
	out.Notes = append([]domain.IncidentNote(nil), i.Notes...)
	if i.Correlation != nil {
		correlation := *i.Correlation
		correlation.ObservedFacts = append([]string(nil), i.Correlation.ObservedFacts...)
		correlation.AlternativeExplanations = append([]string(nil), i.Correlation.AlternativeExplanations...)
		correlation.RecommendedChecks = append([]string(nil), i.Correlation.RecommendedChecks...)
		correlation.Indicators = append([]string(nil), i.Correlation.Indicators...)
		out.Correlation = &correlation
	}
	return out
}

// copySamples deep-copies a sample slice.
func copySamples(samples []domain.Sample) []domain.Sample {
	out := make([]domain.Sample, len(samples))
	for i := range samples {
		out[i] = copySample(samples[i])
	}
	return out
}

// maxTime returns the later of a and b.
func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// minTime returns the earlier non-zero time of a and b.
func minTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	if b.Before(a) {
		return b
	}
	return a
}
