package api

import (
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// coldChainWindow is the resolved query window.
type coldChainWindow struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

// coldChainPoint is one series point. Quality is a string so the downsampled
// "mixed" marker of the contract is representable.
type coldChainPoint struct {
	At      time.Time `json:"at"`
	Value   float64   `json:"value"`
	Quality string    `json:"quality"`
}

// coldChainSeries is one sensor series.
type coldChainSeries struct {
	Metric string           `json:"metric"`
	Unit   domain.Unit      `json:"unit"`
	Points []coldChainPoint `json:"points"`
}

// coldChainLimit is the operator limit that applies to the sensor.
type coldChainLimit struct {
	MinC               *float64 `json:"min_c,omitempty"`
	MaxC               *float64 `json:"max_c,omitempty"`
	MaxRateCPerMin     *float64 `json:"max_rate_c_per_min,omitempty"`
	SetpointToleranceC *float64 `json:"setpoint_tolerance_c,omitempty"`
}

// coldChainItem is one sensor row of the cold-chain response.
type coldChainItem struct {
	Sensor     domain.Sensor   `json:"sensor"`
	Series     coldChainSeries `json:"series"`
	Limit      coldChainLimit  `json:"limit"`
	LastSeenAt time.Time       `json:"last_seen_at,omitempty"`
}

// limitViolation is one observed limit crossing.
type limitViolation struct {
	SensorID domain.SensorID `json:"sensor_id"`
	At       time.Time       `json:"at"`
	Kind     string          `json:"kind"`
	Value    float64         `json:"value"`
}

// dataQualityIssue is one derived data-quality finding.
type dataQualityIssue struct {
	SensorID domain.SensorID `json:"sensor_id"`
	Kind     string          `json:"kind"`
	Since    time.Time       `json:"since"`
	Detail   string          `json:"detail"`
}

// coldChainResponse is the cold-chain payload.
type coldChainResponse struct {
	Window          coldChainWindow    `json:"window"`
	Items           []coldChainItem    `json:"items"`
	LimitViolations []limitViolation   `json:"limit_violations"`
	DataQuality     []dataQualityIssue `json:"data_quality"`
}

// handleColdChain serves GET /api/v1/coldchain.
func (s *Server) handleColdChain(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	q := parseQuery(r, "site_id", "zone_id", "sensor_id", "since", "until")
	siteID := domain.SiteID(q.idValue("site_id", validateSiteID))
	zoneID := domain.ZoneID(q.idValue("zone_id", validateZoneID))
	sensorID := domain.SensorID(q.idValue("sensor_id", validateSensorID))
	since := q.timeValue("since")
	until := q.timeValue("until")
	if !s.checkQuery(w, r, q) {
		return
	}

	now := time.Now().UTC()
	if until.IsZero() {
		until = now
	}
	if since.IsZero() {
		since = until.Add(-6 * time.Hour)
	}
	if !since.Before(until) {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "since must be before until")
		return
	}
	if until.Sub(since) > maxColdChainSpan {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "the cold-chain window must not exceed 7 days")
		return
	}

	current := s.deps.Policy.Current()
	sensors := s.deps.Sites.Sensors(siteID)
	items := make([]coldChainItem, 0, len(sensors))
	violations := make([]limitViolation, 0, 8)
	for _, sensor := range sensors {
		if zoneID != "" && sensor.ZoneID != zoneID {
			continue
		}
		if sensorID != "" && sensor.SensorID != sensorID {
			continue
		}
		samples := filterSamplesBetween(s.deps.Sites.SamplesFor(sensor.SensorID, since), until)
		limit := limitForSensor(current, sensor)
		items = append(items, coldChainItem{
			Sensor:     sensor,
			Series:     buildSeries(sensor, samples),
			Limit:      limit,
			LastSeenAt: sensor.LastSeenAt,
		})
		violations = append(violations, findLimitViolations(sensor, samples, limit, maxSeriesPoints)...)
	}
	if len(violations) > maxSeriesPoints {
		violations = violations[:maxSeriesPoints]
	}

	dataQuality, ok := s.dataQualityIssues(w, r, siteID, sensorID, since)
	if !ok {
		return
	}

	s.respondJSON(w, r, http.StatusOK, coldChainResponse{
		Window:          coldChainWindow{Since: since, Until: until},
		Items:           items,
		LimitViolations: violations,
		DataQuality:     dataQuality,
	})
}

// handleDataQuality serves GET /api/v1/data-quality.
func (s *Server) handleDataQuality(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	q := parseQuery(r, "site_id")
	siteID := domain.SiteID(q.idValue("site_id", validateSiteID))
	if !s.checkQuery(w, r, q) {
		return
	}
	issues, ok := s.dataQualityIssues(w, r, siteID, "", time.Time{})
	if !ok {
		return
	}
	s.respondJSON(w, r, http.StatusOK, newList(issues, len(issues), 0, 0))
}

// dataQualityIssues derives the data-quality findings from data-quality alerts.
// Nothing is recomputed here: the detection rules are the single source of truth.
func (s *Server) dataQualityIssues(w http.ResponseWriter, r *http.Request, siteID domain.SiteID, sensorID domain.SensorID, since time.Time) ([]dataQualityIssue, bool) {
	alerts, ok := s.snapshotAlerts(w, r)
	if !ok {
		return nil, false
	}
	issues := make([]dataQualityIssue, 0, 8)
	for _, alert := range alerts {
		if !isActiveAlert(alert) || alert.Category != domain.CategoryDataQuality {
			continue
		}
		if siteID != "" && alert.SiteID != siteID {
			continue
		}
		if !since.IsZero() && alert.FirstSeenAt.Before(since) {
			continue
		}
		if sensorID != "" && !alertReferencesSensor(alert, sensorID) {
			continue
		}
		issue := dataQualityIssue{
			Kind:   dataQualityKind(alert),
			Since:  alert.FirstSeenAt,
			Detail: alert.Summary,
		}
		if len(alert.SensorIDs) > 0 {
			issue.SensorID = alert.SensorIDs[0]
		}
		issues = append(issues, issue)
	}
	return issues, true
}

// alertReferencesSensor reports whether a sensor is linked to the alert.
func alertReferencesSensor(alert domain.Alert, sensorID domain.SensorID) bool {
	for _, linked := range alert.SensorIDs {
		if linked == sensorID {
			return true
		}
	}
	return false
}

// dataQualityKind classifies a data-quality alert by its rule identifier.
func dataQualityKind(alert domain.Alert) string {
	rule := strings.ToLower(string(alert.RuleID))
	switch {
	case strings.Contains(rule, "frozen"):
		return "frozen"
	case strings.Contains(rule, "gap"):
		return "gap"
	case strings.Contains(rule, "clock"):
		return "clock_skew"
	case strings.Contains(rule, "divergence"):
		return "divergence"
	default:
		return "data_quality"
	}
}

// limitForSensor resolves the operator limit for a sensor's zone and metric.
func limitForSensor(policy domain.Policy, sensor domain.Sensor) coldChainLimit {
	for _, limit := range policy.Temperature.Limits {
		if limit.ZoneID == sensor.ZoneID && limit.Metric == sensor.Metric {
			return coldChainLimit{
				MinC:               limit.MinC,
				MaxC:               limit.MaxC,
				MaxRateCPerMin:     limit.MaxRateCPerMin,
				SetpointToleranceC: limit.SetpointToleranceC,
			}
		}
	}
	return coldChainLimit{}
}

// filterSamplesBetween keeps samples at or after since (already filtered) and
// before until.
func filterSamplesBetween(samples []domain.Sample, until time.Time) []domain.Sample {
	out := make([]domain.Sample, 0, len(samples))
	for _, sample := range samples {
		if !sample.At.Before(until) {
			continue
		}
		out = append(out, sample)
	}
	return out
}

// buildSeries downsamples the samples to at most maxSeriesPoints points. A bucket
// is represented by the mean value and marked "mixed" when the qualities differ.
func buildSeries(sensor domain.Sensor, samples []domain.Sample) coldChainSeries {
	series := coldChainSeries{
		Metric: sensor.Metric,
		Unit:   sensor.Unit,
		Points: make([]coldChainPoint, 0, len(samples)),
	}
	if len(samples) == 0 {
		return series
	}
	bucketSize := 1
	if len(samples) > maxSeriesPoints {
		bucketSize = int(math.Ceil(float64(len(samples)) / maxSeriesPoints))
	}
	for start := 0; start < len(samples); start += bucketSize {
		end := start + bucketSize
		if end > len(samples) {
			end = len(samples)
		}
		var sum float64
		quality := string(samples[start].Quality)
		mixed := false
		for _, sample := range samples[start:end] {
			sum += sample.Value
			if string(sample.Quality) != quality {
				mixed = true
			}
		}
		if mixed {
			quality = "mixed"
		}
		series.Points = append(series.Points, coldChainPoint{
			At:      samples[end-1].At,
			Value:   sum / float64(end-start),
			Quality: quality,
		})
	}
	return series
}

// findLimitViolations reports the samples that cross the configured limit.
func findLimitViolations(sensor domain.Sensor, samples []domain.Sample, limit coldChainLimit, maxViolations int) []limitViolation {
	out := make([]limitViolation, 0, 8)
	for _, sample := range samples {
		kind := ""
		if limit.MinC != nil && sample.Value < *limit.MinC {
			kind = "below_min"
		} else if limit.MaxC != nil && sample.Value > *limit.MaxC {
			kind = "above_max"
		}
		if kind == "" {
			continue
		}
		out = append(out, limitViolation{SensorID: sensor.SensorID, At: sample.At, Kind: kind, Value: sample.Value})
		if len(out) >= maxViolations {
			break
		}
	}
	return out
}
