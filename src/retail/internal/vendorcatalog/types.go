// Package vendorcatalog loads the optional, research-backed OT vendor catalog.
//
// It reads three sibling JSON documents written by the research team:
//
//	vendors.json            vendors, device families, protocol vocabulary, OUIs
//	write-surface.json      documented write surfaces, change classes, evidence
//	regulatory-context.json regulatory frameworks and product-boundary statements
//
// The catalog is optional runtime knowledge. Missing, oversized, malformed or
// semantically invalid files never abort the daemon: the affected part is
// disabled (or the whole catalog, when vendors.json is unusable) and a human
// readable warning is recorded. Discovery and the monitoring API treat a
// disabled catalog as "no vendor knowledge" and keep working with their own
// passive evidence.
//
// The catalog is read-only advisory data. It never grants, approves or alters a
// gate decision; the Access Gate remains the only enforcement point.
package vendorcatalog

import "encoding/json"

// File and size limits. Each catalog document is bounded before it is decoded so
// a corrupted or malicious local file cannot exhaust memory.
const (
	// VendorsFileName is the catalog entry file inside a catalog directory.
	VendorsFileName = "vendors.json"
	// WriteSurfaceFileName documents write surfaces and change classes.
	WriteSurfaceFileName = "write-surface.json"
	// RegulatoryContextFileName documents the regulatory context.
	RegulatoryContextFileName = "regulatory-context.json"

	// MaxFileBytes bounds one catalog document (8 MiB).
	MaxFileBytes = 8 << 20

	// MaxVendors, MaxFamilies, MaxProtocols, MaxSurfaces, MaxChangeClasses and
	// MaxFrameworks bound the decoded collections.
	MaxVendors       = 512
	MaxFamilies      = 4096
	MaxProtocols     = 64
	MaxSurfaces      = 4096
	MaxOperations    = 512 // per write surface
	MaxChangeClasses = 256
	MaxFrameworks    = 256
)

// Evidence is the provenance block shared by catalog entries.
type Evidence struct {
	SourceURL         string   `json:"source_url,omitempty"`
	AdditionalSources []string `json:"additional_sources,omitempty"`
	Confidence        string   `json:"confidence,omitempty"`
	Verification      string   `json:"verification,omitempty"`
}

// CVE is one documented vulnerability entry of a device family.
type CVE struct {
	ID         string  `json:"id"`
	Type       string  `json:"type,omitempty"`
	CVSSv31    float64 `json:"cvss_v3_1,omitempty"`
	Affected   string  `json:"affected,omitempty"`
	FixedIn    string  `json:"fixed_in,omitempty"`
	SourceURL  string  `json:"source_url,omitempty"`
	Confidence string  `json:"confidence,omitempty"`
}

// Vendor is one manufacturer profile.
type Vendor struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	LegalName         string   `json:"legal_name,omitempty"`
	Country           string   `json:"country,omitempty"`
	Role              string   `json:"role,omitempty"`
	Focus             string   `json:"focus,omitempty"`
	SourceURL         string   `json:"source_url,omitempty"`
	AdditionalSources []string `json:"additional_sources,omitempty"`
	Confidence        string   `json:"confidence,omitempty"`
	Verification      string   `json:"verification,omitempty"`
	LastChecked       string   `json:"last_checked,omitempty"`
}

// DeviceFamily is one documented device family of a vendor. Lifecycle uses the
// catalog vocabulary ("current", "legacy_but_supported", "unknown" or an
// "eol_<date>" prefix); MapsToLifecycle moves that onto the domain enum.
type DeviceFamily struct {
	ID                  string   `json:"id"`
	VendorID            string   `json:"vendor_id"`
	Name                string   `json:"name"`
	Category            string   `json:"category"`
	Protocols           []string `json:"protocols,omitempty"`
	Ports               []int    `json:"ports,omitempty"`
	ManagementInterface string   `json:"management_interface,omitempty"`
	FirmwareUpdate      string   `json:"firmware_update,omitempty"`
	Lifecycle           string   `json:"lifecycle,omitempty"`
	Notes               string   `json:"notes,omitempty"`
	SourceURL           string   `json:"source_url,omitempty"`
	AdditionalSources   []string `json:"additional_sources,omitempty"`
	CVEs                []CVE    `json:"cves,omitempty"`
	Confidence          string   `json:"confidence,omitempty"`
	Verification        string   `json:"verification,omitempty"`
	LastChecked         string   `json:"last_checked,omitempty"`
}

// ProtocolInfo is one entry of the protocol vocabulary.
type ProtocolInfo struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Transport           string `json:"transport,omitempty"`
	DefaultPort         int    `json:"default_port,omitempty"`
	Direction           string `json:"direction,omitempty"`
	AuthenticatedNative bool   `json:"authenticated_native,omitempty"`
	EncryptedNative     bool   `json:"encrypted_native,omitempty"`
	ReadOnlyPossible    bool   `json:"read_only_possible,omitempty"`
	PassiveDetectable   bool   `json:"passive_detectable,omitempty"`
	SourceURL           string `json:"source_url,omitempty"`
	Confidence          string `json:"confidence,omitempty"`
	Verification        string `json:"verification,omitempty"`
	LastChecked         string `json:"last_checked,omitempty"`
	Notes               string `json:"notes,omitempty"`
}

// Operation is one documented read/write operation of a write surface.
type Operation struct {
	Kind         string `json:"kind,omitempty"`
	FunctionCode string `json:"function_code,omitempty"`
	Function     string `json:"function,omitempty"`
	Service      string `json:"service,omitempty"`
	Target       string `json:"target,omitempty"`
	Name         string `json:"name,omitempty"`
	Decision     string `json:"decision,omitempty"`
	ChangeClass  string `json:"change_class,omitempty"`
}

// WriteSurface documents one protocol/family write path and its evidence.
type WriteSurface struct {
	ID                    string      `json:"id"`
	Scope                 string      `json:"scope"`
	DeviceFamilyID        string      `json:"device_family_id,omitempty"`
	AdditionalFamilyIDs   []string    `json:"additional_family_ids,omitempty"`
	Protocol              string      `json:"protocol"`
	Transport             string      `json:"transport,omitempty"`
	Port                  int         `json:"port,omitempty"`
	Operations            []Operation `json:"operations,omitempty"`
	TargetPattern         string      `json:"target_pattern,omitempty"`
	CriticalChangeClasses []string    `json:"critical_change_classes,omitempty"`
	Enforcement           string      `json:"enforcement,omitempty"`
	Evidence              Evidence    `json:"evidence"`
	Notes                 string      `json:"notes,omitempty"`
}

// ChangeClass is one documented class of critical change (C-01, C-02, ...).
type ChangeClass struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Examples    []string `json:"examples,omitempty"`
	Criticality string   `json:"criticality,omitempty"`
	Evidence    Evidence `json:"evidence"`
	Notes       string   `json:"notes,omitempty"`
}

// RegulatoryFramework is one regulatory framework with its product boundary.
type RegulatoryFramework struct {
	ID                         string   `json:"id"`
	Name                       string   `json:"name"`
	Reference                  string   `json:"reference,omitempty"`
	Jurisdiction               string   `json:"jurisdiction,omitempty"`
	Status                     string   `json:"status,omitempty"`
	AppliesToFoodRetail        string   `json:"applies_to_food_retail,omitempty"`
	AppliesToSupermarketRetail string   `json:"applies_to_supermarket_retail,omitempty"`
	Thresholds                 string   `json:"thresholds,omitempty"`
	ObligationsSummary         string   `json:"obligations_summary,omitempty"`
	ProductRole                string   `json:"product_role,omitempty"`
	ProductConstraints         string   `json:"product_constraints,omitempty"`
	SourceURL                  string   `json:"source_url,omitempty"`
	AdditionalSources          []string `json:"additional_sources,omitempty"`
	Confidence                 string   `json:"confidence,omitempty"`
	Verification               string   `json:"verification,omitempty"`
	LastChecked                string   `json:"last_checked,omitempty"`
	Notes                      string   `json:"notes,omitempty"`
}

// RegulatoryContext is the product-boundary and framework document.
type RegulatoryContext struct {
	SchemaVersion          string                `json:"schema_version,omitempty"`
	LastChecked            string                `json:"last_checked,omitempty"`
	GeneratedBy            string                `json:"generated_by,omitempty"`
	Notes                  string                `json:"notes,omitempty"`
	ProductBoundarySummary []string              `json:"product_boundary_summary,omitempty"`
	Frameworks             []RegulatoryFramework `json:"frameworks,omitempty"`
}

// vendorsFile is the decoded vendors.json document.
type vendorsFile struct {
	SchemaVersion  string            `json:"schema_version"`
	LastChecked    string            `json:"last_checked"`
	GeneratedBy    string            `json:"generated_by"`
	Notes          string            `json:"notes"`
	Vendors        []Vendor          `json:"vendors"`
	DeviceFamilies []DeviceFamily    `json:"device_families"`
	Protocols      []ProtocolInfo    `json:"protocols"`
	OUIPrefixes    []json.RawMessage `json:"oui_prefixes"`
}

// writeSurfaceFile is the decoded write-surface.json document.
type writeSurfaceFile struct {
	SchemaVersion string         `json:"schema_version"`
	LastChecked   string         `json:"last_checked"`
	GeneratedBy   string         `json:"generated_by"`
	Notes         string         `json:"notes"`
	ChangeClasses []ChangeClass  `json:"change_classes"`
	WriteSurfaces []WriteSurface `json:"write_surfaces"`
}

// regulatoryFile is the decoded regulatory-context.json document.
type regulatoryFile struct {
	SchemaVersion          string                `json:"schema_version"`
	LastChecked            string                `json:"last_checked"`
	GeneratedBy            string                `json:"generated_by"`
	Notes                  string                `json:"notes"`
	ProductBoundarySummary []string              `json:"product_boundary_summary"`
	Frameworks             []RegulatoryFramework `json:"frameworks"`
}
