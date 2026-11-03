package api

import (
	"net/http"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// sitesResponse is the site list payload.
type sitesResponse struct {
	Items []domain.Site `json:"items"`
	Total int           `json:"total"`
}

// handleSites serves GET /api/v1/sites.
func (s *Server) handleSites(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	q := parseQuery(r)
	if !s.checkQuery(w, r, q) {
		return
	}
	sites := s.deps.Sites.Sites()
	s.respondJSON(w, r, http.StatusOK, sitesResponse{Items: sites, Total: len(sites)})
}

// siteCounts is the count block of the site detail response.
type siteCounts struct {
	Assets     int `json:"assets"`
	Sensors    int `json:"sensors"`
	OpenAlerts int `json:"open_alerts"`
}

// siteDetailResponse is the site detail payload.
type siteDetailResponse struct {
	Site          domain.Site             `json:"site"`
	Zones         []domain.Zone           `json:"zones"`
	Counts        siteCounts              `json:"counts"`
	Collectors    []ports.CollectorHealth `json:"collectors"`
	PolicyVersion int                     `json:"policy_version"`
}

// handleSite serves GET /api/v1/sites/{site_id}.
func (s *Server) handleSite(w http.ResponseWriter, r *http.Request, p params, _ identity) {
	siteID := domain.SiteID(pathParam(p, "site_id"))
	if err := siteID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "site_id is not a valid identifier")
		return
	}
	site, ok := s.deps.Sites.Site(siteID)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "not_found", "site not found")
		return
	}
	alerts, ok := s.snapshotAlerts(w, r)
	if !ok {
		return
	}
	openAlerts := 0
	for _, alert := range alerts {
		if alert.SiteID == siteID && isActiveAlert(alert) {
			openAlerts++
		}
	}
	s.respondJSON(w, r, http.StatusOK, siteDetailResponse{
		Site:  site,
		Zones: site.Zones,
		Counts: siteCounts{
			Assets:     len(s.deps.Sites.Assets(siteID)),
			Sensors:    len(s.deps.Sites.Sensors(siteID)),
			OpenAlerts: openAlerts,
		},
		Collectors:    s.collectorHealth(),
		PolicyVersion: s.deps.Policy.Current().Version,
	})
}

// handleAssets serves GET /api/v1/assets.
func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	q := parseQuery(r, "site_id", "type", "q", "limit", "offset")
	siteID := domain.SiteID(q.idValue("site_id", validateSiteID))
	assetType := q.parseAssetType("type")
	search := strings.ToLower(q.textValue("q", maxQueryTextLen))
	limit, offset := q.limit(), q.offset()
	if !s.checkQuery(w, r, q) {
		return
	}

	assets := s.deps.Sites.Assets(siteID)
	filtered := make([]domain.Asset, 0, len(assets))
	for _, asset := range assets {
		if assetType != "" && asset.Type != assetType {
			continue
		}
		if search != "" && !assetMatchesSearch(asset, search) {
			continue
		}
		filtered = append(filtered, asset)
	}
	page, total := paginate(filtered, limit, offset)
	s.respondJSON(w, r, http.StatusOK, newList(page, total, limit, offset))
}

// assetMatchesSearch reports whether name, vendor or model contains the term.
func assetMatchesSearch(asset domain.Asset, term string) bool {
	return strings.Contains(strings.ToLower(asset.Name), term) ||
		strings.Contains(strings.ToLower(asset.Vendor), term) ||
		strings.Contains(strings.ToLower(asset.Model), term)
}

// assetDetailResponse is the asset detail payload.
type assetDetailResponse struct {
	Asset        domain.Asset    `json:"asset"`
	Sensors      []domain.Sensor `json:"sensors"`
	Alerts       []domain.Alert  `json:"alerts"`
	RecentEvents []domain.Event  `json:"recent_events"`
}

// handleAsset serves GET /api/v1/assets/{asset_id}.
func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request, p params, _ identity) {
	assetID := domain.AssetID(pathParam(p, "asset_id"))
	if err := assetID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "asset_id is not a valid identifier")
		return
	}
	asset, ok := s.deps.Sites.Asset(assetID)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "not_found", "asset not found")
		return
	}

	sensors := make([]domain.Sensor, 0, 4)
	for _, sensor := range s.deps.Sites.Sensors(asset.SiteID) {
		if sensor.AssetID == assetID {
			sensors = append(sensors, sensor)
		}
	}

	alerts, ok := s.snapshotAlerts(w, r)
	if !ok {
		return
	}
	related := make([]domain.Alert, 0, 4)
	for _, alert := range alerts {
		if alertReferencesAsset(alert, assetID) {
			related = append(related, alert)
		}
	}
	sortAlertsBySeverity(related)
	if len(related) > 10 {
		related = related[:10]
	}

	events := s.deps.Sites.Events(ports.EventQuery{AssetID: assetID, Limit: 20})
	s.respondJSON(w, r, http.StatusOK, assetDetailResponse{
		Asset:        asset,
		Sensors:      sensors,
		Alerts:       related,
		RecentEvents: events,
	})
}

// alertReferencesAsset reports whether the alert links the asset directly or via
// a sensor bound to it.
func alertReferencesAsset(alert domain.Alert, assetID domain.AssetID) bool {
	for _, linked := range alert.AssetIDs {
		if linked == assetID {
			return true
		}
	}
	return false
}
