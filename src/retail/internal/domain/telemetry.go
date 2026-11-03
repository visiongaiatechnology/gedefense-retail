package domain

import (
	"fmt"
	"math"
	"time"
)

// Quality expresses data confidence, not process safety. A "bad" reading must
// never be silently treated as a valid temperature measurement – the detection
// rules rely on this distinction to avoid false "everything is fine" states.
type Quality string

const (
	QualityGood           Quality = "good"
	QualityUncertain      Quality = "uncertain"
	QualityBad            Quality = "bad"
	QualityMissing        Quality = "missing"
	QualityFrozen         Quality = "frozen" // identical value for longer than policy allows
	QualityStale          Quality = "stale"  // received too long after observation
	QualityClockUncertain Quality = "clock_uncertain"
)

// Unit is the explicit measurement unit. Temperatures are Celsius by product
// rule; other units exist for adjacent telemetry (door state, energy, pressure).
type Unit string

const (
	UnitCelsius Unit = "celsius"
	UnitPercent Unit = "percent"
	UnitKelvin  Unit = "kelvin"
	UnitKWh     Unit = "kwh"
	UnitBar     Unit = "bar"
	UnitRPM     Unit = "rpm"
	UnitBoolean Unit = "boolean"
	UnitSeconds Unit = "seconds"
	UnitCount   Unit = "count"
	UnitUnknown Unit = "unknown"
)

func (u Unit) Valid() bool {
	switch u {
	case UnitCelsius, UnitPercent, UnitKelvin, UnitKWh, UnitBar, UnitRPM, UnitBoolean, UnitSeconds, UnitCount, UnitUnknown:
		return true
	}
	return false
}

// Measurement is a single normalized sensor reading with full provenance.
type Measurement struct {
	Value      float64   `json:"value"`
	Unit       Unit      `json:"unit"`
	Quality    Quality   `json:"quality"`
	Metric     string    `json:"metric"`             // e.g. "air_temperature", "setpoint", "door_state"
	Setpoint   *float64  `json:"setpoint,omitempty"` // only when the source exposes a target value
	Mode       string    `json:"mode,omitempty"`     // e.g. "cooling", "defrost", "heating"
	ObservedAt time.Time `json:"observed_at"`
	SourceTS   time.Time `json:"source_ts,omitempty"` // as stamped by the device
}

// Validate rejects NaN/Inf and unknown units. Values that are implausible for
// the metric (e.g. a 300 °C cold room) are handled by detection rules, not by
// dropping the measurement – dropped data hides sensor faults.
func (m Measurement) Validate() error {
	if math.IsNaN(m.Value) || math.IsInf(m.Value, 0) {
		return fmt.Errorf("measurement: non-finite value")
	}
	if !m.Unit.Valid() {
		return fmt.Errorf("measurement: invalid unit %q", m.Unit)
	}
	if m.Metric == "" {
		return fmt.Errorf("measurement: metric is required")
	}
	if m.ObservedAt.IsZero() {
		return fmt.Errorf("measurement: observed_at is required")
	}
	if m.Setpoint != nil && (math.IsNaN(*m.Setpoint) || math.IsInf(*m.Setpoint, 0)) {
		return fmt.Errorf("measurement: non-finite setpoint")
	}
	return nil
}

// Sensor is the physical or logical measurement point. sensor_id is stable;
// the binding to an asset may change during a service visit and is audited.
type Sensor struct {
	SensorID    SensorID  `json:"sensor_id"`
	SiteID      SiteID    `json:"site_id"`
	AssetID     AssetID   `json:"asset_id,omitempty"`
	ZoneID      ZoneID    `json:"zone_id,omitempty"`
	Name        string    `json:"name"`
	Metric      string    `json:"metric"`
	Unit        Unit      `json:"unit"`
	Kind        string    `json:"kind,omitempty"` // air, product, evaporator, door, energy
	Independent bool      `json:"independent"`    // second, independent probe in the same zone
	Critical    bool      `json:"critical"`
	LastSeenAt  time.Time `json:"last_seen_at,omitempty"`
}

// Validate checks identifier and unit invariants.
func (s Sensor) Validate() error {
	if err := s.SensorID.Validate(); err != nil {
		return fmt.Errorf("sensor: %w", err)
	}
	if err := s.SiteID.Validate(); err != nil {
		return fmt.Errorf("sensor %q: %w", s.SensorID, err)
	}
	if s.Metric == "" {
		return fmt.Errorf("sensor %q: metric is required", s.SensorID)
	}
	if !s.Unit.Valid() {
		return fmt.Errorf("sensor %q: invalid unit %q", s.SensorID, s.Unit)
	}
	return nil
}
