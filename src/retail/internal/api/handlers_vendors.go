package api

import (
	"net/http"
	"sort"

	"github.com/visiongaiatechnology/gedefense/retail/internal/vendorcatalog"
)

// catalogDisabledNote is the explicit statement served when no vendor catalog is
// loaded. The API stays 200 so the UI can render its empty state instead of an
// error page.
const catalogDisabledNote = "OT-Vendor-Katalog nicht geladen: Vendor-Wissen, Write-Surface-Advisory und Regulatory-Kontext sind deaktiviert."

// regulatoryNote is the binding product-boundary statement of the regulatory
// endpoint. It is never a compliance or legal advice.
const regulatoryNote = "Regulatorischer Kontext zur Einordnung. Keine Compliance-, Rechts- oder Zertifizierungsaussage; GeDefense Retail ersetzt weder HACCP noch NIS2-Pflichten des Betreibers."

// vendorFamilySummary is the family block shared by list and detail responses.
type vendorFamilySummary struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Category            string   `json:"category"`
	Lifecycle           string   `json:"lifecycle"`
	Protocols           []string `json:"protocols"`
	ManagementInterface string   `json:"management_interface,omitempty"`
}

// vendorListEntry is one family row of GET /api/v1/vendors. The vendor fields are
// repeated per row so the UI can group without a second request.
type vendorListEntry struct {
	VendorID        string              `json:"vendor_id"`
	VendorName      string              `json:"vendor_name"`
	Family          vendorFamilySummary `json:"family"`
	WriteSurfaces   int                 `json:"write_surfaces_count"`
	HighestEvidence string              `json:"highest_evidence,omitempty"`
}

// vendorsResponse is the payload of GET /api/v1/vendors.
type vendorsResponse struct {
	Enabled  bool              `json:"enabled"`
	Note     string            `json:"note,omitempty"`
	Items    []vendorListEntry `json:"items"`
	Total    int               `json:"total"`
	Warnings []string          `json:"warnings,omitempty"`
}

// vendorEvidence is the evidence block of a write surface.
type vendorEvidence struct {
	SourceURL    string `json:"source_url,omitempty"`
	Confidence   string `json:"confidence,omitempty"`
	Verification string `json:"verification,omitempty"`
}

// vendorChangeClass is one referenced change class of a write surface.
type vendorChangeClass struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Criticality string `json:"criticality,omitempty"`
}

// vendorWriteSurface is one documented write surface of a family detail.
type vendorWriteSurface struct {
	Protocol      string                    `json:"protocol"`
	Scope         string                    `json:"scope"`
	Operations    []vendorcatalog.Operation `json:"operations"`
	ChangeClasses []vendorChangeClass       `json:"change_classes"`
	Evidence      vendorEvidence            `json:"evidence"`
	Notes         string                    `json:"notes,omitempty"`
}

// vendorFamilyDetailResponse is the payload of GET /api/v1/vendors/{family_id}.
type vendorFamilyDetailResponse struct {
	Enabled       bool                 `json:"enabled"`
	Note          string               `json:"note,omitempty"`
	VendorID      string               `json:"vendor_id,omitempty"`
	VendorName    string               `json:"vendor_name,omitempty"`
	Family        *vendorFamilySummary `json:"family,omitempty"`
	WriteSurfaces []vendorWriteSurface `json:"write_surfaces"`
	Warnings      []string             `json:"warnings,omitempty"`
}

// regulatoryFrameworkSummary is one framework row of the regulatory endpoint.
type regulatoryFrameworkSummary struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Role  string `json:"role"`
	Notes string `json:"notes"`
}

// regulatoryContextResponse is the payload of GET /api/v1/regulatory-context.
type regulatoryContextResponse struct {
	Enabled                bool                         `json:"enabled"`
	Note                   string                       `json:"note"`
	ProductBoundarySummary []string                     `json:"product_boundary_summary"`
	Frameworks             []regulatoryFrameworkSummary `json:"frameworks"`
	Warnings               []string                     `json:"warnings,omitempty"`
}

// handleVendors serves GET /api/v1/vendors.
func (s *Server) handleVendors(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	catalog := s.deps.VendorCatalog
	if catalog == nil || !catalog.Enabled() {
		s.respondJSON(w, r, http.StatusOK, vendorsResponse{
			Enabled: false, Note: catalogDisabledNote, Items: []vendorListEntry{}, Warnings: catalogWarnings(catalog),
		})
		return
	}
	items := make([]vendorListEntry, 0, len(catalog.Families()))
	for _, vendor := range catalog.Vendors() {
		for _, family := range catalog.FamiliesForVendor(vendor.ID) {
			count, highest := catalog.SurfaceSummary(family.ID)
			items = append(items, vendorListEntry{
				VendorID: vendor.ID, VendorName: vendor.Name,
				Family: familySummary(family), WriteSurfaces: count, HighestEvidence: highest,
			})
		}
	}
	s.respondJSON(w, r, http.StatusOK, vendorsResponse{
		Enabled: true, Items: items, Total: len(items), Warnings: catalogWarnings(catalog),
	})
}

// handleVendorFamily serves GET /api/v1/vendors/{family_id}.
func (s *Server) handleVendorFamily(w http.ResponseWriter, r *http.Request, p params, _ identity) {
	catalog := s.deps.VendorCatalog
	if catalog == nil || !catalog.Enabled() {
		s.respondJSON(w, r, http.StatusOK, vendorFamilyDetailResponse{
			Enabled: false, Note: catalogDisabledNote, WriteSurfaces: []vendorWriteSurface{}, Warnings: catalogWarnings(catalog),
		})
		return
	}
	familyID := pathParam(p, "family_id")
	family, ok := catalog.Family(familyID)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "not_found", "vendor family not found")
		return
	}
	vendor, _ := catalog.Vendor(family.VendorID)
	surfaces := make([]vendorWriteSurface, 0, 4)
	for _, surface := range catalog.WriteSurfacesForFamily(family.ID) {
		classes := make([]vendorChangeClass, 0, len(surface.CriticalChangeClasses))
		for _, classID := range surface.CriticalChangeClasses {
			class, found := catalog.ChangeClass(classID)
			if !found {
				classes = append(classes, vendorChangeClass{ID: classID})
				continue
			}
			classes = append(classes, vendorChangeClass{ID: class.ID, Name: class.Name, Criticality: class.Criticality})
		}
		operations := append([]vendorcatalog.Operation(nil), surface.Operations...)
		surfaces = append(surfaces, vendorWriteSurface{
			Protocol: surface.Protocol, Scope: surface.Scope,
			Operations: operations, ChangeClasses: classes,
			Evidence: vendorEvidence{
				SourceURL: surface.Evidence.SourceURL, Confidence: surface.Evidence.Confidence,
				Verification: surface.Evidence.Verification,
			},
			Notes: surface.Notes,
		})
	}
	summary := familySummary(family)
	s.respondJSON(w, r, http.StatusOK, vendorFamilyDetailResponse{
		Enabled: true, VendorID: vendor.ID, VendorName: vendor.Name, Family: &summary,
		WriteSurfaces: surfaces, Warnings: catalogWarnings(catalog),
	})
}

// handleRegulatoryContext serves GET /api/v1/regulatory-context.
func (s *Server) handleRegulatoryContext(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	catalog := s.deps.VendorCatalog
	response := regulatoryContextResponse{
		Enabled: false, Note: regulatoryNote,
		ProductBoundarySummary: []string{}, Frameworks: []regulatoryFrameworkSummary{},
		Warnings: catalogWarnings(catalog),
	}
	if catalog == nil || !catalog.Enabled() || !catalog.HasRegulatoryContext() {
		s.respondJSON(w, r, http.StatusOK, response)
		return
	}
	context := catalog.RegulatoryContext()
	response.Enabled = true
	response.ProductBoundarySummary = append([]string{}, context.ProductBoundarySummary...)
	frameworks := make([]regulatoryFrameworkSummary, 0, len(context.Frameworks))
	for _, framework := range context.Frameworks {
		notes := framework.ProductConstraints
		if notes == "" {
			notes = framework.Notes
		}
		frameworks = append(frameworks, regulatoryFrameworkSummary{
			ID: framework.ID, Name: framework.Name, Role: framework.ProductRole, Notes: notes,
		})
	}
	sort.SliceStable(frameworks, func(i, j int) bool { return frameworks[i].ID < frameworks[j].ID })
	response.Frameworks = frameworks
	s.respondJSON(w, r, http.StatusOK, response)
}

// familySummary maps a catalog family onto the API summary shape.
func familySummary(family vendorcatalog.DeviceFamily) vendorFamilySummary {
	protocols := append([]string{}, family.Protocols...)
	return vendorFamilySummary{
		ID: family.ID, Name: family.Name, Category: family.Category, Lifecycle: family.Lifecycle,
		Protocols: protocols, ManagementInterface: family.ManagementInterface,
	}
}

// catalogWarnings returns the load warnings of a catalog (nil-safe).
func catalogWarnings(catalog *vendorcatalog.Catalog) []string {
	if catalog == nil {
		return nil
	}
	return catalog.Warnings()
}
