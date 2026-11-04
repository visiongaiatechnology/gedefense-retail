package vendorcatalog

import (
	"sort"
	"strings"
)

// Enabled reports whether the vendor document was loaded and validated.
func (c *Catalog) Enabled() bool { return c != nil && c.enabled }

// Path returns the loaded vendors.json path ("" when the catalog is disabled).
func (c *Catalog) Path() string {
	if c == nil {
		return ""
	}
	return c.path
}

// Warnings returns the human readable load/validation warnings. The slice is a
// copy; callers must not mutate catalog state.
func (c *Catalog) Warnings() []string {
	if c == nil || len(c.warnings) == 0 {
		return nil
	}
	return append([]string(nil), c.warnings...)
}

// HasWriteSurfaces reports whether write-surface.json was loaded successfully.
func (c *Catalog) HasWriteSurfaces() bool { return c != nil && c.hasSurfaces }

// HasRegulatoryContext reports whether regulatory-context.json was loaded.
func (c *Catalog) HasRegulatoryContext() bool { return c != nil && c.hasRegulatory }

// Vendors returns all vendor profiles sorted by name, then id.
func (c *Catalog) Vendors() []Vendor {
	if c == nil {
		return nil
	}
	out := append([]Vendor(nil), c.vendors...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Vendor returns one vendor profile by id.
func (c *Catalog) Vendor(id string) (Vendor, bool) {
	if c == nil {
		return Vendor{}, false
	}
	index, ok := c.vendorByID[id]
	if !ok {
		return Vendor{}, false
	}
	return c.vendors[index], true
}

// Families returns all device families sorted by name, then id.
func (c *Catalog) Families() []DeviceFamily {
	if c == nil {
		return nil
	}
	out := append([]DeviceFamily(nil), c.families...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Family returns one device family by id.
func (c *Catalog) Family(id string) (DeviceFamily, bool) {
	if c == nil {
		return DeviceFamily{}, false
	}
	index, ok := c.familyByID[id]
	if !ok {
		return DeviceFamily{}, false
	}
	return c.families[index], true
}

// FamiliesForVendor returns the families of one vendor sorted by name.
func (c *Catalog) FamiliesForVendor(vendorID string) []DeviceFamily {
	if c == nil {
		return nil
	}
	out := make([]DeviceFamily, 0, 4)
	for _, family := range c.families {
		if family.VendorID == vendorID {
			out = append(out, family)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Protocols returns the protocol vocabulary sorted by id.
func (c *Catalog) Protocols() []ProtocolInfo {
	if c == nil {
		return nil
	}
	out := append([]ProtocolInfo(nil), c.protocols...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Protocol returns one protocol vocabulary entry by id.
func (c *Catalog) Protocol(id string) (ProtocolInfo, bool) {
	if c == nil {
		return ProtocolInfo{}, false
	}
	index, ok := c.protocolByID[id]
	if !ok {
		return ProtocolInfo{}, false
	}
	return c.protocols[index], true
}

// WriteSurfaces returns every documented write surface sorted by id.
func (c *Catalog) WriteSurfaces() []WriteSurface {
	if c == nil {
		return nil
	}
	return append([]WriteSurface(nil), c.surfaces...)
}

// WriteSurface returns one write surface by id.
func (c *Catalog) WriteSurface(id string) (WriteSurface, bool) {
	if c == nil {
		return WriteSurface{}, false
	}
	for i := range c.surfaces {
		if c.surfaces[i].ID == id {
			return c.surfaces[i], true
		}
	}
	return WriteSurface{}, false
}

// WriteSurfacesForFamily returns the surfaces documented for a family. Surfaces
// that list the family as an additional family are included.
func (c *Catalog) WriteSurfacesForFamily(familyID string) []WriteSurface {
	if c == nil {
		return nil
	}
	indexes := c.surfacesByFamily[familyID]
	out := make([]WriteSurface, 0, len(indexes))
	for _, index := range indexes {
		out = append(out, c.surfaces[index])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ChangeClasses returns every documented change class sorted by id.
func (c *Catalog) ChangeClasses() []ChangeClass {
	if c == nil {
		return nil
	}
	out := append([]ChangeClass(nil), c.changeClasses...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ChangeClass returns one change class by id.
func (c *Catalog) ChangeClass(id string) (ChangeClass, bool) {
	if c == nil {
		return ChangeClass{}, false
	}
	index, ok := c.changeByID[id]
	if !ok {
		return ChangeClass{}, false
	}
	return c.changeClasses[index], true
}

// RegulatoryContext returns a defensive copy of the regulatory document.
func (c *Catalog) RegulatoryContext() RegulatoryContext {
	if c == nil {
		return RegulatoryContext{}
	}
	out := c.regulatory
	out.ProductBoundarySummary = append([]string(nil), c.regulatory.ProductBoundarySummary...)
	out.Frameworks = append([]RegulatoryFramework(nil), c.regulatory.Frameworks...)
	return out
}

// SurfaceSummary reports how many write surfaces are documented for a family and
// the highest evidence confidence among them ("high", "medium", "low" or "").
func (c *Catalog) SurfaceSummary(familyID string) (int, string) {
	surfaces := c.WriteSurfacesForFamily(familyID)
	highest := ""
	highestRank := 0
	for _, surface := range surfaces {
		if rank := confidenceRank(surface.Evidence.Confidence); rank > highestRank {
			highestRank = rank
			highest = surface.Evidence.Confidence
		}
	}
	return len(surfaces), highest
}

// VendorForMAC resolves a MAC address to a catalog vendor name through the
// optional OUI list. OK is false without a verified prefix.
func (c *Catalog) VendorForMAC(mac string) (string, bool) {
	if c == nil || len(c.ouis) == 0 {
		return "", false
	}
	normalized := normalizeMAC(mac)
	if len(normalized) < 6 {
		return "", false
	}
	name, ok := c.ouis[normalized[:6]]
	return name, ok && name != ""
}

// normalizeMAC strips separators and upper-cases the hexadecimal MAC.
func normalizeMAC(mac string) string {
	var out strings.Builder
	for _, char := range strings.ToUpper(mac) {
		if (char >= '0' && char <= '9') || (char >= 'A' && char <= 'F') {
			out.WriteRune(char)
		}
	}
	return out.String()
}

// normalizeOUIPrefix keeps only hexadecimal characters and upper-cases them.
func normalizeOUIPrefix(prefix string) string {
	var out strings.Builder
	for _, char := range strings.ToUpper(prefix) {
		if (char >= '0' && char <= '9') || (char >= 'A' && char <= 'F') {
			out.WriteRune(char)
		}
	}
	return out.String()
}

// confidenceRank orders the confidence vocabulary (higher is better).
func confidenceRank(confidence string) int {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
