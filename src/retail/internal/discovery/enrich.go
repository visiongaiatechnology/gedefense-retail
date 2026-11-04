// Vendor-catalog enrichment: documented device families refine the passive
// hypothesis without inventing identity, firmware or lifecycle facts.
package discovery

import (
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/vendorcatalog"
)

// familyProtocolLabels maps the documented protocol vocabulary onto the labels
// used in the asset inventory. Only protocols with a stable, operator-readable
// label are added; raw port hints already live in Asset.Protocols.
var familyProtocolLabels = map[string]string{
	"http_https_management": "HTTP(S)",
	"bacnet_mstp":           "BACnet MSTP",
	"soap_xml":              "SOAP/XML",
}

// familyCategoryTypes maps documented family categories onto the asset type. A
// non-unknown category only wins when passive classification stayed unknown.
var familyCategoryTypes = map[string]domain.AssetType{
	"store_supervisor":    domain.AssetRefrigerationController,
	"controller_platform": domain.AssetRefrigerationController,
	"rack_controller":     domain.AssetCoolingRack,
}

// enrichFromFamily applies the catalog knowledge of one matched device family:
// type (only when still unknown), protocol labels, model, management-interface
// flag, a bounded confidence bonus and the documented lifecycle.
func enrichFromFamily(asset *domain.Asset, family vendorcatalog.DeviceFamily) {
	if asset == nil {
		return
	}
	if asset.Type == domain.AssetUnknown {
		if mapped, ok := familyCategoryTypes[family.Category]; ok {
			asset.Type = mapped
		}
	}
	labels := make([]string, 0, len(family.Protocols))
	for _, protocol := range family.Protocols {
		if label, ok := familyProtocolLabels[strings.ToLower(strings.TrimSpace(protocol))]; ok {
			labels = append(labels, label)
		}
	}
	if len(labels) > 0 {
		asset.Protocols = mergeProtocols(asset.Protocols, labels)
	}
	if strings.TrimSpace(asset.Model) == "" {
		asset.Model = family.Name
	}
	if family.HasManagementUI() {
		asset.ManagementInterface = true
	}
	// Family knowledge is a hint, not an identity: the bonus stays small and the
	// overall confidence stays bounded by the shared clamp.
	asset.Confidence = clampConfidence(asset.Confidence + 0.1)
	lifecycle := family.LifecycleStatus()
	if lifecycle != domain.LifecycleUnknown {
		asset.Lifecycle = lifecycle
		asset.LifecycleSource = "ot-catalog:" + family.ID
	}
}
