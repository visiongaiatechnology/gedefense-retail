package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestMeta(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{simulation: true})
	recorder := h.do(t, http.MethodGet, "/api/v1/meta", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	meta := decode[metaResponse](t, recorder)
	if meta.Product != "GeDefense Retail" || meta.HTTPAPI != "v1" {
		t.Errorf("meta = %+v", meta)
	}
	if !meta.Capabilities.ReadOnly || !meta.Capabilities.Simulation {
		t.Errorf("capabilities = %+v", meta.Capabilities)
	}
	if len(meta.Capabilities.NotInMVP) == 0 || len(meta.Roles) != 3 {
		t.Errorf("meta lists = %+v", meta)
	}
	assertSecurityHeaders(t, recorder)
}

func TestOverviewAggregates(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	h.seedAlert(t, "alr-open", "dedup-open", "critical", "Critical temperature")
	h.seedAlert(t, "alr-high", "dedup-high", "high", "High temperature")
	closed := h.seedAlert(t, "alr-closed", "dedup-closed", "critical", "Closed temperature")
	if _, err := h.engine.Close(context.Background(), closed.AlertID, "operator-1", "operator", "resolved", "done"); err != nil {
		t.Fatalf("close seeded alert: %v", err)
	}
	h.seedEvent(t, telemetryEvent("evt-1", baseTime, "sensor-1", 4.2))

	recorder := h.do(t, http.MethodGet, "/api/v1/overview", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	overview := decode[overviewResponse](t, recorder)
	if overview.Totals.Sites != 1 || overview.Totals.Peers != 0 {
		t.Errorf("totals = %+v", overview.Totals)
	}
	if overview.Totals.OpenAlerts != 2 || overview.Totals.Critical != 1 || overview.Totals.High != 1 {
		t.Errorf("alert totals = %+v", overview.Totals)
	}
	if overview.Totals.CollectorsRunning != 1 || overview.Totals.CollectorsFailed != 1 {
		t.Errorf("collector totals = %+v", overview.Totals)
	}
	if len(overview.Sites) != 1 {
		t.Fatalf("sites = %+v", overview.Sites)
	}
	site := overview.Sites[0]
	if site.Site.SiteID != "filiale-001" || site.OpenAlerts != 2 || site.Assets != 0 {
		t.Errorf("site row = %+v", site)
	}
	if site.Coldchain.Sensors != 1 {
		t.Errorf("coldchain = %+v", site.Coldchain)
	}
	if len(overview.RecentAlerts) == 0 || overview.RecentAlerts[0].Severity != domain.SeverityCritical {
		t.Errorf("recent alerts = %+v", overview.RecentAlerts)
	}
}

func TestSitesEndpoints(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	recorder := h.do(t, http.MethodGet, "/api/v1/sites", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	list := decode[sitesResponse](t, recorder)
	if len(list.Items) != 1 || list.Total != 1 || list.Items[0].Name != "Markt Nord" {
		t.Errorf("sites = %+v", list)
	}

	recorder = h.do(t, http.MethodGet, "/api/v1/sites/filiale-001", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("detail status = %d", recorder.Code)
	}
	detail := decode[siteDetailResponse](t, recorder)
	if detail.Site.SiteID != "filiale-001" || len(detail.Zones) != 1 {
		t.Errorf("detail = %+v", detail)
	}
	if detail.PolicyVersion != 1 {
		t.Errorf("policy version = %d", detail.PolicyVersion)
	}
	if len(detail.Collectors) != 2 {
		t.Errorf("collectors = %+v", detail.Collectors)
	}

	if recorder = h.do(t, http.MethodGet, "/api/v1/sites/filiale-missing", nil, viewerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("missing site = %d, want 404", recorder.Code)
	}
	if recorder = h.do(t, http.MethodGet, "/api/v1/sites/bad%20id", nil, viewerToken, nil); recorder.Code != http.StatusBadRequest {
		t.Errorf("invalid site id = %d, want 400", recorder.Code)
	}
}

func TestAssetsEndpoints(t *testing.T) {
	h := newApiWithAssets(t)
	recorder := h.do(t, http.MethodGet, "/api/v1/assets", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	all := decode[listEnvelope[domain.Asset]](t, recorder)
	if all.Total != 2 || len(all.Items) != 2 {
		t.Fatalf("assets = %+v", all)
	}
	if all.Items[0].AssetID != "asset-1" {
		t.Errorf("asset order = %+v", all.Items)
	}

	filtered := decode[listEnvelope[domain.Asset]](t, h.do(t, http.MethodGet, "/api/v1/assets?type=refrigeration_controller", nil, viewerToken, nil))
	if filtered.Total != 1 || filtered.Items[0].AssetID != "asset-1" {
		t.Errorf("type filter = %+v", filtered)
	}

	searched := decode[listEnvelope[domain.Asset]](t, h.do(t, http.MethodGet, "/api/v1/assets?q=testvendor", nil, viewerToken, nil))
	if searched.Total != 1 || searched.Items[0].AssetID != "asset-1" {
		t.Errorf("search = %+v", searched)
	}

	paged := decode[listEnvelope[domain.Asset]](t, h.do(t, http.MethodGet, "/api/v1/assets?limit=1&offset=1", nil, viewerToken, nil))
	if paged.Total != 2 || len(paged.Items) != 1 || paged.Items[0].AssetID != "asset-2" {
		t.Errorf("pagination = %+v", paged)
	}

	detail := decode[assetDetailResponse](t, h.do(t, http.MethodGet, "/api/v1/assets/asset-1", nil, viewerToken, nil))
	if detail.Asset.AssetID != "asset-1" || len(detail.Sensors) != 1 {
		t.Errorf("asset detail = %+v", detail)
	}

	if recorder = h.do(t, http.MethodGet, "/api/v1/assets/asset-missing", nil, viewerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("missing asset = %d, want 404", recorder.Code)
	}
}

// newApiWithAssets seeds two assets and one sensor.
func newApiWithAssets(t *testing.T) *apiHarness {
	t.Helper()
	h := newAPIHarness(t, apiTestOptions{})
	if err := h.registry.UpsertAsset(domain.Asset{
		AssetID: "asset-1", SiteID: "filiale-001", ZoneID: "zone-ot", Name: "Kühlregler Pool 1",
		Type: domain.AssetRefrigerationController, Vendor: "TestVendor", Criticality: domain.CriticalityCritical,
		Confidence: 1, Classification: domain.ClassificationManual,
	}); err != nil {
		t.Fatalf("seed asset-1: %v", err)
	}
	if err := h.registry.UpsertAsset(domain.Asset{
		AssetID: "asset-2", SiteID: "filiale-001", ZoneID: "zone-ot", Name: "Sensor Gateway",
		Type: domain.AssetSensorGateway, Vendor: "OtherVendor", Criticality: domain.CriticalityMedium,
		Confidence: 0.7, Classification: domain.ClassificationAuto,
	}); err != nil {
		t.Fatalf("seed asset-2: %v", err)
	}
	if err := h.registry.UpsertSensor(domain.Sensor{
		SensorID: "sensor-1", SiteID: "filiale-001", AssetID: "asset-1", ZoneID: "zone-ot",
		Name: "Air probe", Metric: "air_temperature", Unit: domain.UnitCelsius, Critical: true,
	}); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	return h
}

func TestStaticUI(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	recorder := h.do(t, http.MethodGet, "/", nil, "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("index status = %d", recorder.Code)
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("index content type = %q", contentType)
	}
	if !strings.Contains(recorder.Body.String(), "GeDefense") {
		t.Errorf("index body = %q", recorder.Body.String())
	}
	assertSecurityHeaders(t, recorder)
	if got := recorder.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("static cache control = %q", got)
	}

	css := h.do(t, http.MethodGet, "/css/app.css", nil, "", nil)
	if css.Code != http.StatusOK || !strings.HasPrefix(css.Header().Get("Content-Type"), "text/css") {
		t.Errorf("css = %d %q", css.Code, css.Header().Get("Content-Type"))
	}
	js := h.do(t, http.MethodGet, "/js/app.js", nil, "", nil)
	if js.Code != http.StatusOK || !strings.Contains(js.Header().Get("Content-Type"), "javascript") {
		t.Errorf("js = %d %q", js.Code, js.Header().Get("Content-Type"))
	}
	png := h.do(t, http.MethodGet, "/assets/logo.png", nil, "", nil)
	if png.Code != http.StatusOK || png.Header().Get("Content-Type") != "image/png" {
		t.Errorf("png = %d %q", png.Code, png.Header().Get("Content-Type"))
	}

	for _, target := range []string{"/missing.html", "/secret.go", "/../etc/passwd", "/js/", "/api/v1/../secret"} {
		recorder := h.do(t, http.MethodGet, target, nil, "", nil)
		if recorder.Code != http.StatusNotFound && recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 404", target, recorder.Code)
		}
	}

	head := h.do(t, http.MethodHead, "/", nil, "", nil)
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Errorf("HEAD = %d with %d body bytes", head.Code, head.Body.Len())
	}
	post := h.do(t, http.MethodPost, "/", nil, "", nil)
	if post.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST / = %d, want 405", post.Code)
	}
}

func TestStaticMissingFilesystem(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{static: fstest.MapFS{}})
	recorder := h.do(t, http.MethodGet, "/", nil, "", nil)
	if recorder.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 without embedded UI", recorder.Code)
	}
}
