package vendorcatalog

import (
	"strings"
)

// AdvisoryProtocol maps a gate target protocol name onto the catalog protocol
// vocabulary. The mapping is presentation-free: it never changes a gate
// decision, it only selects the documented write surface.
func advisoryProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "modbus", "modbus_tcp":
		return "modbus_tcp"
	case "http", "https", "http_https_management":
		return "http_https_management"
	case "bacnet", "bacnet_ip":
		return "bacnet_ip"
	case "mqtt":
		return "mqtt"
	case "snmp", "snmp_v3":
		return "snmp_v3"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

// Advisory reports whether the catalog documents write surfaces for a gate
// target protocol. It is strictly advisory: the returned note is suitable for
// the `retailgate check` warning list and must never be used to allow a write.
//
// known is true only when at least one documented surface with medium or high
// evidence exists. It is false when the catalog is not loaded, has no write
// surfaces, or only low-evidence entries: in that case the operator should treat
// the allowlist as undocumented and collect manufacturer documentation.
func (c *Catalog) Advisory(protocol string) (note string, known bool) {
	mapped := advisoryProtocol(protocol)
	if c == nil || !c.enabled {
		return "OT-Vendor-Katalog nicht geladen: fuer " + protocol + " ist keine dokumentierte WriteSurface verfuegbar; Allowlist gilt als unbelegt (Advisory nur lesend, keine automatische Freigabe)", false
	}
	if !c.hasSurfaces {
		return "OT-Vendor-Katalog ohne Write-Surface-Dokument: fuer " + protocol + " ist keine dokumentierte WriteSurface verfuegbar (Advisory nur lesend, keine automatische Freigabe)", false
	}
	indexes := c.surfacesByProtocol[mapped]
	if len(indexes) == 0 {
		return "keine dokumentierte WriteSurface fuer " + protocol + " im OT-Vendor-Katalog; Allowlist gilt als unbelegt (Advisory nur lesend, keine automatische Freigabe)", false
	}
	best := 0
	for _, index := range indexes {
		if rank := confidenceRank(c.surfaces[index].Evidence.Confidence); rank > best {
			best = rank
		}
	}
	switch best {
	case 3:
		return "dokumentierte WriteSurface fuer " + protocol + " mit hoher Evidence vorhanden; Advisory ist nur lesend und keine automatische Freigabe", true
	case 2:
		return "dokumentierte WriteSurface fuer " + protocol + " mit mittlerer Evidence vorhanden; Advisory ist nur lesend und keine automatische Freigabe", true
	default:
		return "nur WriteSurfaces fuer " + protocol + " mit niedriger Evidence dokumentiert; Allowlist gilt weiterhin als unbelegt (Advisory nur lesend, keine automatische Freigabe)", false
	}
}
