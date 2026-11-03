package domain

import (
	"fmt"
	"time"
)

// AssetType is the operator-facing class of a discovered or onboarded device.
// "unknown" is a first-class value: passive discovery must never pretend to
// know a device it cannot prove.
type AssetType string

const (
	AssetRefrigerationController AssetType = "refrigeration_controller"
	AssetPL                      AssetType = "plc"
	AssetHMI                     AssetType = "hmi"
	AssetSensorGateway           AssetType = "sensor_gateway"
	AssetBMS                     AssetType = "bms"
	AssetNetworkDevice           AssetType = "network_device"
	AssetEdgeGateway             AssetType = "edge_gateway"
	AssetCoolingRack             AssetType = "cooling_rack"
	AssetColdRoom                AssetType = "cold_room"
	AssetUnknown                 AssetType = "unknown"
)

func (a AssetType) Valid() bool {
	switch a {
	case AssetRefrigerationController, AssetPL, AssetHMI, AssetSensorGateway, AssetBMS,
		AssetNetworkDevice, AssetEdgeGateway, AssetCoolingRack, AssetColdRoom, AssetUnknown:
		return true
	}
	return false
}

// Criticality is configured by the operator (policy), never inferred.
type Criticality string

const (
	CriticalityLow      Criticality = "low"
	CriticalityMedium   Criticality = "medium"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

func (c Criticality) Valid() bool {
	switch c {
	case CriticalityLow, CriticalityMedium, CriticalityHigh, CriticalityCritical:
		return true
	}
	return false
}

// ClassificationSource records whether a classification was entered by a human
// or produced by passive inference.
type ClassificationSource string

const (
	ClassificationManual ClassificationSource = "manual"
	ClassificationAuto   ClassificationSource = "auto"
)

// NetworkIDKind enumerates the observable network identifiers. Every value
// carries its own confidence and provenance: a MAC seen by OUI lookup is weaker
// evidence than an operator-entered asset record.
type NetworkIDKind string

const (
	NetIDIP       NetworkIDKind = "ip"
	NetIDMAC      NetworkIDKind = "mac"
	NetIDOUI      NetworkIDKind = "oui_vendor"
	NetIDHostname NetworkIDKind = "hostname"
	NetIDProtocol NetworkIDKind = "protocol_hint"
)

// NetworkIdentifier is one observable network fact about an asset.
type NetworkIdentifier struct {
	Kind       NetworkIDKind `json:"kind"`
	Value      string        `json:"value"`
	Source     string        `json:"source"`     // collector/adapter id, e.g. "pnf.flow"
	Confidence float64       `json:"confidence"` // 0..1
	FirstSeen  time.Time     `json:"first_seen,omitempty"`
	LastSeen   time.Time     `json:"last_seen,omitempty"`
}

// LifecycleStatus is the vendor lifecycle state of an asset, derived from the
// OT catalog (documented source) or set by the operator. It is a risk factor,
// never an attack indicator by itself.
type LifecycleStatus string

const (
	LifecycleActive         LifecycleStatus = "active"
	LifecycleApproachingEOL LifecycleStatus = "approaching_eol"
	LifecycleEOL            LifecycleStatus = "eol"
	LifecycleUnknown        LifecycleStatus = "unknown"
)

func (l LifecycleStatus) Valid() bool {
	switch l {
	case LifecycleActive, LifecycleApproachingEOL, LifecycleEOL, LifecycleUnknown:
		return true
	}
	return false
}

// Asset is a discovered or onboarded device in one store.
type Asset struct {
	AssetID             AssetID              `json:"asset_id"`
	SiteID              SiteID               `json:"site_id"`
	ZoneID              ZoneID               `json:"zone_id,omitempty"`
	Name                string               `json:"name"`
	Type                AssetType            `json:"asset_type"`
	Vendor              string               `json:"vendor,omitempty"`
	Model               string               `json:"model,omitempty"`
	FirmwareVersion     string               `json:"firmware_version,omitempty"`
	FirmwareSource      string               `json:"firmware_source,omitempty"` // e.g. "modbus:read_fc3" or "manual"
	FirmwareConfidence  float64              `json:"firmware_confidence,omitempty"`
	NetworkIDs          []NetworkIdentifier  `json:"network_identifiers,omitempty"`
	Protocols           []string             `json:"protocols,omitempty"`
	Criticality         Criticality          `json:"criticality"`
	Confidence          float64              `json:"confidence"` // confidence of the classification as a whole
	Classification      ClassificationSource `json:"classification_source"`
	Lifecycle           LifecycleStatus      `json:"lifecycle,omitempty"`
	LifecycleSource     string               `json:"lifecycle_source,omitempty"` // catalog entry id / reference
	ManagementInterface bool                 `json:"management_interface,omitempty"`
	Source              string               `json:"source,omitempty"`
	FirstSeenAt         time.Time            `json:"first_seen_at,omitempty"`
	LastSeenAt          time.Time            `json:"last_seen_at,omitempty"`
	OperatorNotes       string               `json:"operator_notes,omitempty"`
	Retired             bool                 `json:"retired"`
}

// Validate enforces the asset invariants. Called on every store write and API
// update; returns a typed error wrapping ErrInvalidID where identifiers fail.
func (a Asset) Validate() error {
	if err := a.AssetID.Validate(); err != nil {
		return fmt.Errorf("asset: %w", err)
	}
	if err := a.SiteID.Validate(); err != nil {
		return fmt.Errorf("asset %q: %w", a.AssetID, err)
	}
	if !a.Type.Valid() {
		return fmt.Errorf("asset %q: invalid type %q", a.AssetID, a.Type)
	}
	if !a.Criticality.Valid() {
		return fmt.Errorf("asset %q: invalid criticality %q", a.AssetID, a.Criticality)
	}
	if a.Confidence < 0 || a.Confidence > 1 {
		return fmt.Errorf("asset %q: confidence %v outside [0,1]", a.AssetID, a.Confidence)
	}
	for i := range a.NetworkIDs {
		n := a.NetworkIDs[i]
		if n.Value == "" {
			return fmt.Errorf("asset %q: network id %d has empty value", a.AssetID, i)
		}
		if n.Confidence < 0 || n.Confidence > 1 {
			return fmt.Errorf("asset %q: network id %d confidence %v outside [0,1]", a.AssetID, i, n.Confidence)
		}
	}
	return nil
}
