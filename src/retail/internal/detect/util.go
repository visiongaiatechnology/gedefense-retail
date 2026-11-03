package detect

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

const (
	// maxQueryLimit bounds every EventStore/Registry read. The World enforces
	// its own hard default; asking for a fixed, bounded number keeps the
	// detection loop predictable under event storms.
	maxQueryLimit = 2000

	// eventLookback is the history window used to decide whether a peer pair or
	// an asset was observed before.
	eventLookback = 24 * time.Hour

	// inventoryLookback is the "known asset" window for the new-asset rule.
	inventoryLookback = 30 * 24 * time.Hour

	// rateWindow / rateMinSpan bound the sliding temperature-rate computation.
	rateWindow  = 10 * time.Minute
	rateMinSpan = 2 * time.Minute

	// divergenceWindowDefault is used when a divergence limit is configured but
	// no window is set. It is a plausibility window, not a safety limit.
	divergenceWindowDefault = 10 * time.Minute

	// frozenCoverage is the minimum share of the frozen-value window that must
	// be covered by observations before a constant series is judged.
	frozenCoverage = 0.8

	// frozenMinPoints is the minimum number of identical observations required
	// before the frozen-value rule reports a constant series.
	frozenMinPoints = 3

	// monotonicTolerance tolerates retransmissions/rounding when checking that
	// observation timestamps never move backwards.
	monotonicTolerance = 60 * time.Second

	// regressionLookback bounds the timestamp-monotonicity lookup.
	regressionLookback = 2 * time.Hour

	// setpointChangeSensitivityC is the minimum observed setpoint delta that is
	// treated as a change when the operator did not configure a tolerance. It is
	// a change sensitivity, not a universal temperature limit.
	setpointChangeSensitivityC = 0.5

	// comparisonMovementDefaultC is the movement above which a comparison
	// sensor counts as "moving" when no divergence limit is configured.
	comparisonMovementDefaultC = 0.5

	// maxEvidenceItems and maxSummaryLen bound alert size in the JSONL store.
	maxEvidenceItems = 12
	maxSummaryLen    = 1400

	// maxTickAlerts bounds one periodic tick so a broken telemetry path cannot
	// produce an unbounded alert burst.
	maxTickAlerts = 200
)

// otPorts are the well-known ports of the OT protocols supported by the MVP.
var otPorts = map[int]struct{}{
	502: {}, 47808: {}, 1883: {}, 161: {}, 4840: {}, 20000: {}, 102: {},
}

// managementUIPorts are the usual HTTP(S) management ports of refrigeration
// supervisors (Danfoss StoreView, Copeland/Dixell XWEB, generic web UIs).
var managementUIPorts = map[int]struct{}{
	80: {}, 443: {}, 8000: {}, 8080: {}, 8443: {},
}

// trustedTime returns the gateway-stamped instant of an event. Maintenance
// windows and access decisions are evaluated on gateway time; the device time
// stays in observed_at and is checked separately by the clock-skew rule.
func trustedTime(ev domain.Event) time.Time {
	if !ev.ReceivedAt.IsZero() {
		return ev.ReceivedAt.UTC()
	}
	if !ev.ObservedAt.IsZero() {
		return ev.ObservedAt.UTC()
	}
	return time.Time{}
}

// observedAtOf returns the measurement instant (device time) when available.
func observedAtOf(ev domain.Event) time.Time {
	if ev.Measurement != nil && !ev.Measurement.ObservedAt.IsZero() {
		return ev.Measurement.ObservedAt.UTC()
	}
	if !ev.ObservedAt.IsZero() {
		return ev.ObservedAt.UTC()
	}
	return trustedTime(ev)
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// lookbackSince returns the start instant and the RFC3339 query value of a
// lookback window relative to the World clock (never the wall clock).
func lookbackSince(w World, d time.Duration) (time.Time, string) {
	now := w.Now()
	if now.IsZero() {
		return time.Time{}, ""
	}
	since := now.Add(-d)
	return since, rfc3339(since)
}

func clampConfidence(v, low, high float64) float64 {
	if math.IsNaN(v) {
		return low
	}
	if v < low {
		return low
	}
	if v > high {
		return high
	}
	return v
}

// capSeverity limits a severity to an upper bound (used to keep normal defrost,
// door and loading cycles below critical).
func capSeverity(severity, ceiling domain.Severity) domain.Severity {
	if severity.Rank() > ceiling.Rank() {
		return ceiling
	}
	return severity
}

// escalateSeverity returns the higher of two severities.
func escalateSeverity(a, b domain.Severity) domain.Severity {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

func isOTPort(port int) bool {
	_, ok := otPorts[port]
	return ok
}

func isManagementUIPort(port int) bool {
	_, ok := managementUIPorts[port]
	return ok
}

func portListed(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// otProtocolName reports whether a normalized protocol name belongs to the OT
// protocol family supported by the MVP.
func otProtocolName(protocol string) bool {
	p := strings.ToLower(strings.TrimSpace(protocol))
	if p == "" {
		return false
	}
	for _, hint := range []string{"modbus", "bacnet", "mqtt", "snmp", "opc", "s7", "profinet", "ethernet_ip", "ethernet/ip", "dnp3", "iec104", "lonworks"} {
		if strings.Contains(p, hint) {
			return true
		}
	}
	return false
}

// humanDuration renders a duration for German alert texts.
func humanDuration(d time.Duration) string {
	if d <= 0 {
		return "0 s"
	}
	switch {
	case d >= 24*time.Hour:
		return formatFloat(d.Hours(), 0) + " h"
	case d >= time.Hour:
		return formatFloat(d.Hours(), 1) + " h"
	case d >= time.Minute:
		return formatFloat(d.Minutes(), 0) + " min"
	default:
		return formatFloat(d.Seconds(), 0) + " s"
	}
}

func formatFloat(v float64, decimals int) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "-"
	}
	return strconv.FormatFloat(v, 'f', decimals, 64)
}

// temperatureMetric reports whether a normalized metric name is a temperature
// measurement (setpoints and derived values are excluded).
func temperatureMetric(metric string) bool {
	m := strings.ToLower(strings.TrimSpace(metric))
	if m == "" || strings.Contains(m, "setpoint") || strings.Contains(m, "sollwert") {
		return false
	}
	return strings.Contains(m, "temperature") || strings.Contains(m, "temperatur") ||
		strings.HasSuffix(m, "_temp") || m == "temp"
}

// temperatureInC normalizes a temperature value to Celsius. Other units are
// rejected instead of being guessed.
func temperatureInC(value float64, unit domain.Unit) (float64, bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, false
	}
	switch unit {
	case domain.UnitCelsius:
		return value, true
	case domain.UnitKelvin:
		return value - 273.15, true
	default:
		return 0, false
	}
}

// qualityReliable gates process alarms on measurement quality: a frozen,
// missing, bad or clock-uncertain value is a data-quality issue and must not be
// presented as a valid temperature alarm.
func qualityReliable(quality domain.Quality) bool {
	switch quality {
	case "", domain.QualityGood, domain.QualityUncertain:
		return true
	default:
		return false
	}
}

// tempReading is a normalized temperature measurement with its provenance.
type tempReading struct {
	ValueC   float64
	Metric   string
	Quality  domain.Quality
	Mode     string
	At       time.Time
	Setpoint *float64
}

// temperatureValue extracts a normalized Celsius reading from a telemetry event.
func temperatureValue(ev domain.Event) (tempReading, bool) {
	if ev.Kind != domain.EventTelemetry || ev.Measurement == nil {
		return tempReading{}, false
	}
	m := ev.Measurement
	metric := strings.ToLower(strings.TrimSpace(m.Metric))
	if !temperatureMetric(metric) {
		return tempReading{}, false
	}
	valueC, ok := temperatureInC(m.Value, m.Unit)
	if !ok {
		return tempReading{}, false
	}
	reading := tempReading{
		ValueC:  valueC,
		Metric:  metric,
		Quality: m.Quality,
		Mode:    strings.ToLower(strings.TrimSpace(m.Mode)),
		At:      m.ObservedAt.UTC(),
	}
	if reading.At.IsZero() {
		reading.At = ev.ObservedAt.UTC()
	}
	if m.Setpoint != nil {
		if sp, ok := temperatureInC(*m.Setpoint, m.Unit); ok {
			reading.Setpoint = &sp
		}
	}
	return reading, true
}

// findTemperatureLimit resolves the operator-configured limit for a zone and
// metric. No universal limit exists: a missing or not-yet-valid limit yields
// ok=false and therefore no temperature alert.
func findTemperatureLimit(policy domain.Policy, zone domain.ZoneID, metric string, at time.Time) (domain.TemperatureLimit, bool) {
	for _, limit := range policy.Temperature.Limits {
		if limit.ZoneID != zone {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(limit.Metric), strings.TrimSpace(metric)) {
			continue
		}
		if !limit.ValidFrom.IsZero() && at.Before(limit.ValidFrom) {
			continue
		}
		return limit, true
	}
	return domain.TemperatureLimit{}, false
}
