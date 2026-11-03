package api

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// seedLimitPolicy installs a temperature limit for zone-ot/air_temperature.
func seedLimitPolicy(t *testing.T, h *apiHarness, minC, maxC float64) {
	t.Helper()
	current := h.manager.Current()
	current.Temperature.Limits = []domain.TemperatureLimit{{
		ZoneID: "zone-ot",
		Metric: "air_temperature",
		MinC:   &minC,
		MaxC:   &maxC,
	}}
	if _, err := h.manager.Update(current, "admin", "admin", "test limit"); err != nil {
		t.Fatalf("update policy: %v", err)
	}
}

func TestColdChainSeriesAndViolations(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	seedLimitPolicy(t, h, 2, 8)
	for i, value := range []float64{4.2, 5.0, 9.1} {
		at := baseTime.Add(time.Duration(i) * time.Minute)
		h.seedEvent(t, telemetryEvent("evt-"+strconv.Itoa(i+1), at, "sensor-1", value))
	}

	target := "/api/v1/coldchain?site_id=filiale-001&since=" + url.QueryEscape(baseTime.Add(-time.Hour).Format(time.RFC3339)) +
		"&until=" + url.QueryEscape(baseTime.Add(time.Hour).Format(time.RFC3339))
	recorder := h.do(t, http.MethodGet, target, nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	response := decode[coldChainResponse](t, recorder)
	if len(response.Items) != 1 {
		t.Fatalf("items = %+v", response.Items)
	}
	item := response.Items[0]
	if item.Sensor.SensorID != "sensor-1" || item.Series.Metric != "air_temperature" {
		t.Errorf("item = %+v", item)
	}
	if len(item.Series.Points) != 3 {
		t.Errorf("points = %+v", item.Series.Points)
	}
	if item.Limit.MaxC == nil || *item.Limit.MaxC != 8 || item.Limit.MinC == nil || *item.Limit.MinC != 2 {
		t.Errorf("limit = %+v", item.Limit)
	}
	if len(response.LimitViolations) != 1 {
		t.Fatalf("violations = %+v", response.LimitViolations)
	}
	violation := response.LimitViolations[0]
	if violation.Kind != "above_max" || violation.Value != 9.1 || violation.SensorID != "sensor-1" {
		t.Errorf("violation = %+v", violation)
	}
	if len(response.DataQuality) != 0 {
		t.Errorf("data quality = %+v", response.DataQuality)
	}
}

func TestColdChainValidation(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	now := time.Now().UTC()
	tooLong := "/api/v1/coldchain?since=" + url.QueryEscape(now.Add(-8*24*time.Hour).Format(time.RFC3339)) +
		"&until=" + url.QueryEscape(now.Format(time.RFC3339))
	if recorder := h.do(t, http.MethodGet, tooLong, nil, viewerToken, nil); recorder.Code != http.StatusBadRequest {
		t.Errorf("8-day window = %d, want 400", recorder.Code)
	}
	inverted := "/api/v1/coldchain?since=" + url.QueryEscape(now.Format(time.RFC3339)) +
		"&until=" + url.QueryEscape(now.Add(-time.Hour).Format(time.RFC3339))
	if recorder := h.do(t, http.MethodGet, inverted, nil, viewerToken, nil); recorder.Code != http.StatusBadRequest {
		t.Errorf("inverted window = %d, want 400", recorder.Code)
	}
}

func TestDataQualityFromAlerts(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	alert := domain.Alert{
		AlertID:     "alr-dq",
		SiteID:      "filiale-001",
		SensorIDs:   []domain.SensorID{"sensor-1"},
		Category:    domain.CategoryDataQuality,
		Severity:    domain.SeverityMedium,
		Confidence:  0.7,
		Title:       "Frozen sensor value",
		Summary:     "Sensor reported the identical value for 40 minutes.",
		RuleID:      domain.RuleID("retail.dq.frozen-value"),
		RuleVersion: "1",
		FirstSeenAt: baseTime,
		LastSeenAt:  baseTime,
		Status:      domain.AlertOpen,
		DedupKey:    "dq-1",
	}
	if err := h.engine.Observe(context.Background(), []domain.Alert{alert}); err != nil {
		t.Fatalf("observe: %v", err)
	}
	recorder := h.do(t, http.MethodGet, "/api/v1/data-quality?site_id=filiale-001", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	list := decode[listEnvelope[dataQualityIssue]](t, recorder)
	if list.Total != 1 || len(list.Items) != 1 {
		t.Fatalf("issues = %+v", list)
	}
	issue := list.Items[0]
	if issue.Kind != "frozen" || issue.SensorID != "sensor-1" {
		t.Errorf("issue = %+v", issue)
	}
}

func TestBuildSeriesDownsamples(t *testing.T) {
	sensor := domain.Sensor{SensorID: "sensor-1", Metric: "air_temperature", Unit: domain.UnitCelsius}
	samples := make([]domain.Sample, 0, 1200)
	for i := 0; i < 1200; i++ {
		samples = append(samples, domain.Sample{
			SensorID: "sensor-1",
			SiteID:   "filiale-001",
			Metric:   "air_temperature",
			Unit:     domain.UnitCelsius,
			At:       baseTime.Add(time.Duration(i) * time.Second),
			Value:    float64(i),
			Quality:  domain.QualityGood,
		})
	}
	series := buildSeries(sensor, samples)
	if len(series.Points) > maxSeriesPoints {
		t.Fatalf("points = %d, want <= %d", len(series.Points), maxSeriesPoints)
	}
	// A bucket mixes the qualities of its samples.
	samples[0].Quality = domain.QualityUncertain
	mixed := buildSeries(sensor, samples)
	if mixed.Points[0].Quality != "mixed" {
		t.Errorf("quality = %q, want mixed", mixed.Points[0].Quality)
	}
	if empty := buildSeries(sensor, nil); len(empty.Points) != 0 {
		t.Errorf("empty series = %+v", empty)
	}
}
