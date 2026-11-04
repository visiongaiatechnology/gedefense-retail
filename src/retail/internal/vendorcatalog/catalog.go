package vendorcatalog

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Catalog file failures are classified without any filesystem path detail. The
// warnings are part of the viewer API, so absolute paths or environment values
// must never leak (F-A8-06).
var (
	errCatalogFileMissing    = errors.New("Datei nicht vorhanden")
	errCatalogFileUnreadable = errors.New("Datei nicht lesbar")
	errCatalogFileSymlink    = errors.New("Symlink nicht erlaubt")
	errCatalogFileNotRegular = errors.New("keine regulaere Datei")
	errCatalogFileTooLarge   = errors.New("Datei zu gross")
)

// Catalog is the immutable, loaded OT vendor catalog. The zero value is a
// disabled catalog: it is safe to call every accessor on it.
type Catalog struct {
	path string

	enabled      bool
	vendors      []Vendor
	vendorByID   map[string]int
	families     []DeviceFamily
	familyByID   map[string]int
	protocols    []ProtocolInfo
	protocolByID map[string]int
	ouis         map[string]string // normalized 6-hex prefix -> vendor id

	surfaces           []WriteSurface
	surfacesByFamily   map[string][]int
	surfacesByProtocol map[string][]int
	changeClasses      []ChangeClass
	changeByID         map[string]int
	hasSurfaces        bool

	regulatory    RegulatoryContext
	hasRegulatory bool

	warnings []string
}

// Load reads the catalog referenced by path. path may point at vendors.json or
// at the directory that contains the three catalog documents. An empty path uses
// ResolvePath. Load never fails: a missing or unusable catalog is returned as a
// disabled Catalog with warnings, so callers keep serving without vendor
// knowledge.
func Load(path string) *Catalog {
	catalog := &Catalog{
		vendorByID:         make(map[string]int),
		familyByID:         make(map[string]int),
		protocolByID:       make(map[string]int),
		ouis:               make(map[string]string),
		surfacesByFamily:   make(map[string][]int),
		surfacesByProtocol: make(map[string][]int),
		changeByID:         make(map[string]int),
	}
	vendorsPath, ok := resolveVendorsPath(path)
	if !ok {
		catalog.warn("OT-Vendor-Katalog nicht konfiguriert; Vendor-Wissen, Write-Surface-Advisory und Regulatory-Kontext sind deaktiviert")
		return catalog
	}
	catalog.path = vendorsPath
	dir := filepath.Dir(vendorsPath)

	raw, err := readCatalogFile(vendorsPath)
	if err != nil {
		catalog.warn("vendors.json: " + err.Error() + "; Katalog deaktiviert")
		return catalog
	}
	var vf vendorsFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		catalog.warn("vendors.json ist kein gueltiges JSON; Katalog deaktiviert")
		return catalog
	}
	if err := validateVendorsFile(&vf); err != nil {
		catalog.warn("vendors.json unvollstaendig/inkonsistent: " + err.Error() + "; Katalog deaktiviert")
		return catalog
	}
	catalog.enabled = true
	catalog.loadVendors(&vf)
	catalog.loadOUIs(&vf)

	surfacesPath := filepath.Join(dir, WriteSurfaceFileName)
	if raw, err := readCatalogFile(surfacesPath); err != nil {
		catalog.warn("write-surface.json: " + err.Error() + "; Write-Surface-Advisory deaktiviert")
	} else {
		var wf writeSurfaceFile
		if err := json.Unmarshal(raw, &wf); err != nil {
			catalog.warn("write-surface.json ist kein gueltiges JSON; Write-Surface-Advisory deaktiviert")
		} else if err := validateWriteSurfaceFile(&wf, &vf); err != nil {
			catalog.warn("write-surface.json unvollstaendig/inkonsistent: " + err.Error() + "; Write-Surface-Advisory deaktiviert")
		} else {
			catalog.loadWriteSurfaces(&wf)
		}
	}

	regulatoryPath := filepath.Join(dir, RegulatoryContextFileName)
	if raw, err := readCatalogFile(regulatoryPath); err != nil {
		catalog.warn("regulatory-context.json: " + err.Error() + "; Regulatory-Kontext deaktiviert")
	} else {
		var rf regulatoryFile
		if err := json.Unmarshal(raw, &rf); err != nil {
			catalog.warn("regulatory-context.json ist kein gueltiges JSON; Regulatory-Kontext deaktiviert")
		} else if err := validateRegulatoryFile(&rf); err != nil {
			catalog.warn("regulatory-context.json unvollstaendig/inkonsistent: " + err.Error() + "; Regulatory-Kontext deaktiviert")
		} else {
			catalog.regulatory = RegulatoryContext{
				SchemaVersion:          rf.SchemaVersion,
				LastChecked:            rf.LastChecked,
				GeneratedBy:            rf.GeneratedBy,
				Notes:                  rf.Notes,
				ProductBoundarySummary: append([]string(nil), rf.ProductBoundarySummary...),
				Frameworks:             append([]RegulatoryFramework(nil), rf.Frameworks...),
			}
			catalog.hasRegulatory = true
		}
	}
	return catalog
}

// ResolvePath returns the catalog path from GEDEFENSE_OT_CATALOG or the first
// existing conventional location, or "" when no catalog is configured.
func ResolvePath() string {
	if p := strings.TrimSpace(os.Getenv("GEDEFENSE_OT_CATALOG")); p != "" {
		return p
	}
	candidates := []string{
		filepath.Join("data", "ot-catalog", VendorsFileName),
		filepath.Join("..", "..", "data", "ot-catalog", VendorsFileName),
		filepath.Join("..", "..", "..", "data", "ot-catalog", VendorsFileName),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// resolveVendorsPath turns a file/directory/empty path into a vendors.json path.
func resolveVendorsPath(path string) (string, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = ResolvePath()
	}
	if path == "" {
		return "", false
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = filepath.Join(path, VendorsFileName)
	}
	return path, true
}

// readCatalogFile reads one catalog document with a hard size bound. Symlinks
// and non-regular files are rejected; errors never carry the filesystem path
// (the resulting warning is served to API viewers, F-A8-06).
func readCatalogFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errCatalogFileMissing
		}
		return nil, errCatalogFileUnreadable
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errCatalogFileSymlink
	}
	if !info.Mode().IsRegular() {
		return nil, errCatalogFileNotRegular
	}
	if info.Size() > MaxFileBytes {
		return nil, errCatalogFileTooLarge
	}
	// Open + fstat keeps the size/regular check on the same file descriptor and
	// avoids path details in error values.
	handle, err := os.Open(path)
	if err != nil {
		return nil, errCatalogFileUnreadable
	}
	defer handle.Close()
	opened, err := handle.Stat()
	if err != nil {
		return nil, errCatalogFileUnreadable
	}
	if !opened.Mode().IsRegular() {
		return nil, errCatalogFileNotRegular
	}
	// The path must still refer to the file Lstat validated: a swap to a symlink
	// between the checks is rejected fail-safe instead of being followed.
	if !os.SameFile(info, opened) {
		return nil, errCatalogFileSymlink
	}
	if opened.Size() > MaxFileBytes {
		return nil, errCatalogFileTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(handle, MaxFileBytes+1))
	if err != nil {
		return nil, errCatalogFileUnreadable
	}
	if len(raw) > MaxFileBytes {
		return nil, errCatalogFileTooLarge
	}
	return raw, nil
}

// loadVendors copies the validated vendor/family/protocol collections.
func (c *Catalog) loadVendors(vf *vendorsFile) {
	c.vendors = append([]Vendor(nil), vf.Vendors...)
	for i := range c.vendors {
		c.vendorByID[c.vendors[i].ID] = i
	}
	c.families = append([]DeviceFamily(nil), vf.DeviceFamilies...)
	for i := range c.families {
		c.familyByID[c.families[i].ID] = i
	}
	c.protocols = append([]ProtocolInfo(nil), vf.Protocols...)
	for i := range c.protocols {
		c.protocolByID[c.protocols[i].ID] = i
	}
}

// loadOUIs parses the optional OUI prefixes. Invalid entries are skipped with a
// warning instead of invalidating the catalog.
func (c *Catalog) loadOUIs(vf *vendorsFile) {
	vendorNames := make(map[string]string, len(c.vendors))
	for _, vendor := range c.vendors {
		vendorNames[vendor.ID] = vendor.Name
	}
	for _, entry := range vf.OUIPrefixes {
		prefix, vendorID, ok := parseOUIEntry(entry)
		if !ok {
			c.warn("vendors.json: ungültiger oui_prefixes-Eintrag übersprungen")
			continue
		}
		name := vendorNames[vendorID]
		if name == "" {
			name = vendorID
		}
		if name == "" {
			continue
		}
		normalized := normalizeOUIPrefix(prefix)
		if len(normalized) != 6 {
			c.warn("vendors.json: OUI-Prefix " + prefix + " hat kein 24-Bit-Format; übersprungen")
			continue
		}
		c.ouis[normalized] = name
	}
}

// parseOUIEntry accepts both shapes used by research exports:
//
//	"AA:BB:CC"
//	{"prefix":"AA:BB:CC","vendor_id":"danfoss"}
func parseOUIEntry(entry json.RawMessage) (prefix, vendor string, ok bool) {
	var asString string
	if err := json.Unmarshal(entry, &asString); err == nil {
		return strings.TrimSpace(asString), "", asString != ""
	}
	var asObject struct {
		Prefix    string `json:"prefix"`
		OUIPrefix string `json:"oui_prefix"`
		VendorID  string `json:"vendor_id"`
		Vendor    string `json:"vendor"`
	}
	if err := json.Unmarshal(entry, &asObject); err != nil {
		return "", "", false
	}
	prefix = asObject.Prefix
	if prefix == "" {
		prefix = asObject.OUIPrefix
	}
	vendor = asObject.VendorID
	if vendor == "" {
		vendor = asObject.Vendor
	}
	return strings.TrimSpace(prefix), strings.TrimSpace(vendor), prefix != ""
}

// loadWriteSurfaces copies the validated write-surface collections.
func (c *Catalog) loadWriteSurfaces(wf *writeSurfaceFile) {
	c.changeClasses = append([]ChangeClass(nil), wf.ChangeClasses...)
	for i := range c.changeClasses {
		c.changeByID[c.changeClasses[i].ID] = i
	}
	c.surfaces = append([]WriteSurface(nil), wf.WriteSurfaces...)
	sort.SliceStable(c.surfaces, func(i, j int) bool { return c.surfaces[i].ID < c.surfaces[j].ID })
	for i := range c.surfaces {
		surface := c.surfaces[i]
		c.surfacesByProtocol[surface.Protocol] = append(c.surfacesByProtocol[surface.Protocol], i)
		if surface.DeviceFamilyID != "" {
			c.surfacesByFamily[surface.DeviceFamilyID] = append(c.surfacesByFamily[surface.DeviceFamilyID], i)
		}
		for _, familyID := range surface.AdditionalFamilyIDs {
			c.surfacesByFamily[familyID] = append(c.surfacesByFamily[familyID], i)
		}
	}
	c.hasSurfaces = len(c.surfaces) > 0
}

// warn records one human readable warning.
func (c *Catalog) warn(message string) { c.warnings = append(c.warnings, message) }
