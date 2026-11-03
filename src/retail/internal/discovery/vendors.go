// Optional OT catalog enrichment (OUI vendor, device family lifecycle).
package discovery

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/netx"
)

// catalog is the optional subset of data/ot-catalog/vendors.json that passive
// discovery may use. It is nil when the file is missing or malformed.
type catalog struct {
	vendorNames map[string]string
	families    []catalogFamily
	ouis        map[string]string // normalized prefix -> vendor name
}

type catalogFamily struct {
	ID        string `json:"id"`
	VendorID  string `json:"vendor_id"`
	Name      string `json:"name"`
	Lifecycle string `json:"lifecycle"`
}

type catalogVendor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type catalogFile struct {
	Vendors        []catalogVendor   `json:"vendors"`
	DeviceFamilies []catalogFamily   `json:"device_families"`
	OUIPrefixes    []json.RawMessage `json:"oui_prefixes"`
}

// loadCatalog reads the catalog best-effort. A missing file is expected in
// deployments without research data and must not prevent discovery.
func loadCatalog(path string) *catalog {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 8<<20 {
		return nil
	}
	var file catalogFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil
	}
	cat := &catalog{
		vendorNames: make(map[string]string, len(file.Vendors)),
		families:    file.DeviceFamilies,
		ouis:        make(map[string]string),
	}
	for _, vendor := range file.Vendors {
		if vendor.ID == "" || vendor.Name == "" {
			continue
		}
		cat.vendorNames[vendor.ID] = vendor.Name
	}
	for _, entry := range file.OUIPrefixes {
		prefix, vendorID, ok := parseOUIEntry(entry)
		if !ok {
			continue
		}
		vendor := cat.vendorNames[vendorID]
		if vendor == "" {
			vendor = vendorID
		}
		if vendor != "" {
			cat.ouis[normalizePrefix(prefix)] = vendor
		}
	}
	return cat
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

// vendorForMAC looks up the OUI vendor. The confidence added to the asset is
// small: an OUI is a fabricator hint, not a device identity.
func (c *catalog) vendorForMAC(mac string) (string, float64, bool) {
	if c == nil || len(c.ouis) == 0 {
		return "", 0, false
	}
	prefix, err := netx.ParseMAC(mac)
	if err != nil {
		return "", 0, false
	}
	normalized := normalizePrefix(netx.OUI(prefix))
	vendor, ok := c.ouis[normalized]
	if !ok || vendor == "" {
		return "", 0, false
	}
	return vendor, 0.05, true
}

// lifecycleFor matches the vendor's device families against the observed
// model/hostname hint and returns the documented lifecycle state.
func (c *catalog) lifecycleFor(vendor, model, hostname string) (domain.LifecycleStatus, string, string) {
	if c == nil || vendor == "" {
		return domain.LifecycleUnknown, "", ""
	}
	vendorNorm := normalizeText(vendor)
	hintNorm := normalizeText(model + " " + hostname)
	best := catalogFamily{}
	bestLen := 0
	for _, family := range c.families {
		familyVendor := normalizeText(c.vendorNames[family.VendorID])
		if familyVendor == "" {
			familyVendor = normalizeText(family.VendorID)
		}
		if familyVendor == "" || (familyVendor != vendorNorm && !strings.Contains(vendorNorm, familyVendor) && !strings.Contains(familyVendor, vendorNorm)) {
			continue
		}
		familyName := normalizeText(family.Name)
		if familyName == "" || !strings.Contains(hintNorm, familyName) {
			continue
		}
		if len(familyName) > bestLen {
			best = family
			bestLen = len(familyName)
		}
	}
	if bestLen == 0 {
		return domain.LifecycleUnknown, "", ""
	}
	return lifecycleStatus(best.Lifecycle), "ot-catalog:" + best.ID, best.Name
}

// lifecycleStatus maps the catalog vocabulary onto the domain enum.
func lifecycleStatus(raw string) domain.LifecycleStatus {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case value == "":
		return domain.LifecycleUnknown
	case strings.HasPrefix(value, "eol"):
		return domain.LifecycleEOL
	case value == "current" || value == "active" || value == "supported":
		return domain.LifecycleActive
	case strings.Contains(value, "legacy"), strings.Contains(value, "approaching"), strings.Contains(value, "near_eol"):
		return domain.LifecycleApproachingEOL
	default:
		return domain.LifecycleUnknown
	}
}

func normalizePrefix(prefix string) string {
	var out strings.Builder
	for _, r := range strings.ToUpper(prefix) {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// normalizeText lower-cases and removes all separators so that
// "AK-SM 800" matches "ak_sm_800" and "storeview-ak-sm-800".
func normalizeText(value string) string {
	lower := strings.ToLower(value)
	var out strings.Builder
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			out.WriteRune(r)
		}
	}
	return out.String()
}
