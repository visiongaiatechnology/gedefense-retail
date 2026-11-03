package domain

import "time"

// Sample is the compact telemetry form used by the in-memory registry, the
// detection rules, the cold-chain series API and the simulator. It is a
// projection of Event/Measurement and carries exactly the provenance the rules
// and the UI need – nothing more.
type Sample struct {
	SensorID SensorID  `json:"sensor_id"`
	SiteID   SiteID    `json:"site_id"`
	ZoneID   ZoneID    `json:"zone_id,omitempty"`
	AssetID  AssetID   `json:"asset_id,omitempty"`
	Metric   string    `json:"metric"`
	Unit     Unit      `json:"unit"`
	At       time.Time `json:"at"`
	Value    float64   `json:"value"`
	Quality  Quality   `json:"quality"`
	Mode     string    `json:"mode,omitempty"`
	Setpoint *float64  `json:"setpoint,omitempty"`
	Source   string    `json:"source,omitempty"`
}

// Validate mirrors the Measurement contract for the registry buffer.
func (s Sample) Validate() error {
	if err := s.SensorID.Validate(); err != nil {
		return err
	}
	if err := s.SiteID.Validate(); err != nil {
		return err
	}
	if s.Metric == "" {
		return errSampleMetric
	}
	if !s.Unit.Valid() {
		return errSampleUnit
	}
	if s.At.IsZero() {
		return errSampleTime
	}
	return nil
}

// SampleFromMeasurement builds a sample from a telemetry event. It returns
// ok=false for non-telemetry events so callers cannot accidentally fabricate a
// sample from unrelated data.
func SampleFromMeasurement(ev Event) (Sample, bool) {
	if ev.Kind != EventTelemetry || ev.Measurement == nil {
		return Sample{}, false
	}
	return Sample{
		SensorID: ev.SensorID,
		SiteID:   ev.SiteID,
		ZoneID:   ev.ZoneID,
		AssetID:  ev.AssetID,
		Metric:   ev.Measurement.Metric,
		Unit:     ev.Measurement.Unit,
		At:       ev.Measurement.ObservedAt.UTC(),
		Value:    ev.Measurement.Value,
		Quality:  ev.Measurement.Quality,
		Mode:     ev.Measurement.Mode,
		Setpoint: ev.Measurement.Setpoint,
		Source:   ev.Source,
	}, true
}

// TelemetryPoint is the compact series point used by the API.
type TelemetryPoint struct {
	At      time.Time `json:"at"`
	Value   float64   `json:"value"`
	Quality Quality   `json:"quality"`
}

var (
	errSampleMetric = errSample("sample: metric is required")
	errSampleUnit   = errSample("sample: invalid unit")
	errSampleTime   = errSample("sample: at is required")
)

type errSample string

func (e errSample) Error() string { return string(e) }
