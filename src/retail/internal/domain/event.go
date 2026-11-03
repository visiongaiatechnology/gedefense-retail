package domain

import (
	"fmt"
	"time"
)

// EventKind is the discriminator of the normalized event stream. Every adapter
// must map its protocol data onto exactly one of these kinds; anything that
// cannot be normalized is counted as a parser/unsupported metric instead of
// being invented into a pseudo-event.
type EventKind string

const (
	EventTelemetry    EventKind = "telemetry"
	EventFlow         EventKind = "flow"
	EventAssetSeen    EventKind = "asset_seen"
	EventDeviceHealth EventKind = "device_health"
	EventAccess       EventKind = "access_session"
	EventWriteAttempt EventKind = "write_attempt"
	EventConfigChange EventKind = "config_change"
	EventIntegrity    EventKind = "integrity"
	EventClockSkew    EventKind = "clock_skew"
)

func (k EventKind) Valid() bool {
	switch k {
	case EventTelemetry, EventFlow, EventAssetSeen, EventDeviceHealth, EventAccess,
		EventWriteAttempt, EventConfigChange, EventIntegrity, EventClockSkew:
		return true
	}
	return false
}

// FlowMeta is passive communication metadata. No payload bytes are stored.
type FlowMeta struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Protocol  string `json:"protocol"` // modbus_tcp, bacnet_ip, mqtt, snmp, opcua, arp, ...
	Bytes     int64  `json:"bytes,omitempty"`
	Packets   int64  `json:"packets,omitempty"`
	Direction string `json:"direction,omitempty"` // inbound, outbound, internal
}

// DeviceMeta is what a passive observation can say about a device identity.
type DeviceMeta struct {
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Model    string `json:"model,omitempty"`
}

// WriteAttempt records that a controller write was OBSERVED on the wire. The
// observation is allowed; performing the write is not (see package guard).
type WriteAttempt struct {
	Protocol  string `json:"protocol"`
	Source    string `json:"source"`
	Target    string `json:"target"`
	Function  string `json:"function"` // e.g. "fc6_write_single_register"
	Register  string `json:"register,omitempty"`
	ValueHint string `json:"value_hint,omitempty"` // redacted or coarse hint only
	Allowed   bool   `json:"allowed"`              // per policy/allowlist; false => high signal
}

// AccessMeta describes an observed remote/service session.
type AccessMeta struct {
	Vendor       string              `json:"vendor,omitempty"`
	User         string              `json:"user,omitempty"`
	Method       string              `json:"method,omitempty"` // vpn, teamviewer, direct, modem, ssh
	TargetAsset  AssetID             `json:"target_asset,omitempty"`
	WindowID     MaintenanceWindowID `json:"maintenance_window_id,omitempty"`
	InWindow     bool                `json:"in_window"`
	SourceDevice string              `json:"source_device,omitempty"`
	SessionID    string              `json:"session_id,omitempty"`
}

// IntegrityMeta describes an observed configuration/firmware state, either
// exported by the operator or read via an approved read-only path.
type IntegrityMeta struct {
	Subject   string `json:"subject"` // e.g. "controller_parameters", "firmware"
	Version   string `json:"version,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Reference string `json:"reference,omitempty"` // approved baseline id
	Changed   bool   `json:"changed"`
	Approved  bool   `json:"approved"`
}

// Event is the normalized unit that flows through collectors, detection,
// storage, the local spool and the optional central forwarder. It is wide by
// design (one JSONL schema) but strictly validated: the Kind decides which
// optional block is mandatory.
type Event struct {
	EventID      EventID           `json:"event_id"`
	Kind         EventKind         `json:"kind"`
	SiteID       SiteID            `json:"site_id"`
	ZoneID       ZoneID            `json:"zone_id,omitempty"`
	AssetID      AssetID           `json:"asset_id,omitempty"`
	SensorID     SensorID          `json:"sensor_id,omitempty"`
	ObservedAt   time.Time         `json:"observed_at"`
	ReceivedAt   time.Time         `json:"received_at"`
	Source       string            `json:"source"`            // adapter/collector id
	Collection   string            `json:"collection_method"` // passive_tap, read_only_poll, operator_export
	Protocol     string            `json:"protocol,omitempty"`
	Confidence   float64           `json:"confidence"`
	Quality      Quality           `json:"quality,omitempty"`
	Measurement  *Measurement      `json:"measurement,omitempty"`
	Flow         *FlowMeta         `json:"flow,omitempty"`
	Device       *DeviceMeta       `json:"device,omitempty"`
	WriteAttempt *WriteAttempt     `json:"write_attempt,omitempty"`
	Access       *AccessMeta       `json:"access,omitempty"`
	Integrity    *IntegrityMeta    `json:"integrity,omitempty"`
	PayloadMeta  map[string]string `json:"payload_meta,omitempty"` // small, non-sensitive metadata only
}

// Validate is the single authoritative gate for events entering the pipeline.
// A failing event is rejected and counted, never silently repaired.
func (e Event) Validate() error {
	if err := e.EventID.Validate(); err != nil {
		return fmt.Errorf("event: %w", err)
	}
	if !e.Kind.Valid() {
		return fmt.Errorf("event %q: invalid kind %q", e.EventID, e.Kind)
	}
	if err := e.SiteID.Validate(); err != nil {
		return fmt.Errorf("event %q: %w", e.EventID, err)
	}
	if e.ObservedAt.IsZero() {
		return fmt.Errorf("event %q: observed_at is required", e.EventID)
	}
	if e.ReceivedAt.IsZero() {
		return fmt.Errorf("event %q: received_at is required", e.EventID)
	}
	if e.Source == "" {
		return fmt.Errorf("event %q: source is required", e.EventID)
	}
	if e.Collection == "" {
		return fmt.Errorf("event %q: collection_method is required", e.EventID)
	}
	if e.Confidence < 0 || e.Confidence > 1 {
		return fmt.Errorf("event %q: confidence %v outside [0,1]", e.EventID, e.Confidence)
	}
	switch e.Kind {
	case EventTelemetry:
		if e.Measurement == nil {
			return fmt.Errorf("event %q: telemetry requires measurement", e.EventID)
		}
		if err := e.Measurement.Validate(); err != nil {
			return fmt.Errorf("event %q: %w", e.EventID, err)
		}
	case EventFlow:
		if e.Flow == nil {
			return fmt.Errorf("event %q: flow requires flow metadata", e.EventID)
		}
		if e.Flow.Protocol == "" || e.Flow.DstPort < 0 || e.Flow.DstPort > 65535 {
			return fmt.Errorf("event %q: invalid flow metadata", e.EventID)
		}
	case EventWriteAttempt:
		if e.WriteAttempt == nil {
			return fmt.Errorf("event %q: write_attempt requires write metadata", e.EventID)
		}
	case EventAccess:
		if e.Access == nil {
			return fmt.Errorf("event %q: access_session requires access metadata", e.EventID)
		}
	case EventIntegrity:
		if e.Integrity == nil {
			return fmt.Errorf("event %q: integrity requires integrity metadata", e.EventID)
		}
	case EventConfigChange:
		if e.Integrity == nil && e.PayloadMeta == nil {
			return fmt.Errorf("event %q: config_change requires integrity or payload metadata", e.EventID)
		}
	}
	for k, v := range e.PayloadMeta {
		if len(k) > 64 || len(v) > 256 {
			return fmt.Errorf("event %q: payload_meta entry too large", e.EventID)
		}
	}
	return nil
}

// DedupKey is used by the spool and the central forwarder to guarantee
// at-least-once delivery without duplicating stored events.
func (e Event) DedupKey() string {
	return string(e.EventID)
}

// ClockSkew reports how far the device-provided timestamp deviates from the
// gateway clock. A large skew is itself a security signal (time manipulation)
// but only when the deviation exceeds the configured tolerance.
func (e Event) ClockSkew(now time.Time) time.Duration {
	if e.ObservedAt.IsZero() || now.IsZero() {
		return 0
	}
	return now.Sub(e.ObservedAt)
}
