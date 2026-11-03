package detect

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// operatingMode classifies the controller mode reported with a measurement. It
// exists to keep normal defrost, door and loading phases from being escalated:
// they are legitimate causes of fast temperature changes.
type operatingMode int

const (
	modeNormal operatingMode = iota
	modeDefrost
	modeDoorOpen
	modeLoading
)

func classifyMode(mode string) operatingMode {
	m := strings.ToLower(strings.TrimSpace(mode))
	switch {
	case m == "":
		return modeNormal
	case strings.Contains(m, "defrost"), strings.Contains(m, "abtau"), strings.Contains(m, "tauen"):
		return modeDefrost
	case strings.Contains(m, "door"), strings.Contains(m, "tür"), strings.Contains(m, "tuere"), strings.Contains(m, "open"):
		return modeDoorOpen
	case strings.Contains(m, "load"), strings.Contains(m, "belad"), strings.Contains(m, "ware"):
		return modeLoading
	default:
		return modeNormal
	}
}

func modeLabel(mode operatingMode) string {
	switch mode {
	case modeDefrost:
		return "Abtau"
	case modeDoorOpen:
		return "Türöffnung"
	case modeLoading:
		return "Warenbeladung"
	default:
		return "Normalbetrieb"
	}
}

// thermalLimitRule implements retail.thermal.limit. Hard product rule: without
// an operator-configured min/max limit, no temperature alert is produced.
type thermalLimitRule struct{ baseRule }

func newThermalLimitRule() *thermalLimitRule {
	return &thermalLimitRule{baseRule: baseFor(rules.IDThermalLimit)}
}

func (r *thermalLimitRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	reading, ok := temperatureValue(ev)
	if !ok || !qualityReliable(reading.Quality) {
		return nil
	}
	policy := w.Policy()
	limit, ok := findTemperatureLimit(policy, ev.ZoneID, reading.Metric, reading.At)
	if !ok || (limit.MinC == nil && limit.MaxC == nil) {
		return nil // no operator limit -> no thermal alerting (hard product rule)
	}

	var (
		side      string
		boundC    float64
		excursion float64
	)
	switch {
	case limit.MaxC != nil && reading.ValueC > *limit.MaxC:
		side = "max"
		boundC = *limit.MaxC
		excursion = reading.ValueC - boundC
	case limit.MinC != nil && reading.ValueC < *limit.MinC:
		side = "min"
		boundC = *limit.MinC
		excursion = boundC - reading.ValueC
	default:
		return nil
	}

	severity := domain.SeverityLow
	switch {
	case excursion > 2:
		severity = domain.SeverityHigh
	case excursion > 0.5:
		severity = domain.SeverityMedium
	}
	mode := classifyMode(reading.Mode)
	switch mode {
	case modeDefrost:
		if excursion > 2 {
			severity = capSeverity(severity, domain.SeverityMedium)
		} else {
			severity = capSeverity(severity, domain.SeverityLow)
		}
	case modeDoorOpen, modeLoading:
		severity = capSeverity(severity, domain.SeverityMedium)
	}

	confidence := 0.80
	if reading.Quality != "" && reading.Quality != domain.QualityGood {
		confidence = 0.60
	}
	at := trustedTime(ev)
	facts := []string{
		fmt.Sprintf("Messwert %s °C (%s) in Zone %s um %s liegt %s des Betreiber-Grenzwerts %s °C (Überschreitung %.2f °C).",
			formatFloat(reading.ValueC, 2), reading.Metric, zoneLabel(ev.ZoneID), reading.At.Format(time.RFC3339),
			outOfBoundsLabel(side), formatFloat(boundC, 2), excursion),
		fmt.Sprintf("Grenzwert aus Policy %s Version %d (Messqualität %q, Betriebsmodus %q).",
			policy.PolicyID, policy.Version, qualityLabel(reading.Quality), reading.Mode),
	}
	if mode != modeNormal {
		facts = append(facts, fmt.Sprintf("Der gemeldete Betriebsmodus (%s) erklärt Temperaturabweichungen; die Severity ist deshalb begrenzt.", modeLabel(mode)))
	}

	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   clampConfidence(confidence, 0.5, 0.9),
		dedupKey:     rules.DedupKey(rules.IDThermalLimit, string(ev.SiteID), string(ev.ZoneID), reading.Metric, string(ev.SensorID), side),
		title:        "Temperatur außerhalb des Betreiber-Grenzwerts",
		hypothesis:   "Mögliche Ursachen sind Türöffnung, Warenbeladung, Abtauzyklus, eine Anlagenstörung, ein Sensorfehler oder eine unbefugte Sollwertänderung; keine dieser Ursachen ist durch die Messung allein bewiesen.",
		alternatives: []string{"Abtauzyklus", "Türöffnung oder Warenbeladung", "Anlagenstörung (Kompressor, Ventil, Kältemittel)", "Sensorfehler oder Kalibrierabweichung", "Unbefugte Sollwert-/Modusänderung (nicht bewiesen)"},
		checks:       []string{"Ist-Temperatur mit unabhängiger Messung durch zuständiges Personal prüfen", "Türzustand, Warenbeladung, Abtauplan und Anlagenstörung prüfen", "Betreiber-Kühlketten-/Incident-Prozess auslösen"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	if ev.SensorID != "" {
		draft.sensorIDs = []domain.SensorID{ev.SensorID}
	}
	if ev.AssetID != "" {
		draft.assetIDs = []domain.AssetID{ev.AssetID}
	}
	for _, fact := range facts {
		draft.addFact(fact)
	}
	draft.addEvidence("measurement", string(ev.EventID), fmt.Sprintf("%s = %s °C", reading.Metric, formatFloat(reading.ValueC, 2)),
		ev.Source, fmt.Sprintf("limit_%s=%s excursion=%s", side, formatFloat(boundC, 2), formatFloat(excursion, 2)), reading.At, 0.85)
	draft.addEvidence("policy", string(policy.PolicyID), "Betreiber-Grenzwert", "detect:policy",
		fmt.Sprintf("policy_version=%d metric=%s zone=%s %s_c=%s", policy.Version, limit.Metric, limit.ZoneID, side, formatFloat(boundC, 2)), at, 0.9)
	return []domain.Alert{draft.build()}
}

// thermalRateRule implements retail.thermal.rate: a temperature change faster
// than the operator-configured maximum rate. Known defrost, door and loading
// modes suppress the rule because the change is operationally expected there.
type thermalRateRule struct{ baseRule }

func newThermalRateRule() *thermalRateRule {
	return &thermalRateRule{baseRule: baseFor(rules.IDThermalRate)}
}

func (r *thermalRateRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	reading, ok := temperatureValue(ev)
	if !ok || !qualityReliable(reading.Quality) {
		return nil
	}
	if classifyMode(reading.Mode) != modeNormal {
		return nil // defrost/door/loading explain fast changes; the limit rule still applies
	}
	policy := w.Policy()
	limit, ok := findTemperatureLimit(policy, ev.ZoneID, reading.Metric, reading.At)
	if !ok || limit.MaxRateCPerMin == nil || *limit.MaxRateCPerMin <= 0 {
		return nil // no operator rate limit -> no alerting
	}
	maxRate := *limit.MaxRateCPerMin

	now := w.Now()
	if now.IsZero() {
		now = reading.At
	}
	from := now.Add(-rateWindow)
	samples := w.SamplesFor(ev.SensorID, from)
	points := append(seriesFromSamples(samples, reading.Metric), seriesPoint{At: reading.At, ValueC: reading.ValueC})
	points = dedupeSeries(points)
	points = clampSeriesWindow(points, from, now.Add(time.Minute))
	if len(points) < 2 {
		return nil
	}
	first, last := points[0], points[len(points)-1]
	span := last.At.Sub(first.At)
	if span < rateMinSpan {
		return nil
	}
	rate := (last.ValueC - first.ValueC) / span.Minutes()
	if math.Abs(rate) <= maxRate {
		return nil
	}
	ratio := math.Abs(rate) / maxRate
	severity := domain.SeverityMedium
	confidence := 0.65
	if ratio >= 2 {
		severity = domain.SeverityHigh
	}
	if ratio >= 3 {
		confidence = 0.75
	}
	direction := "rising"
	directionLabel := "Anstieg"
	if rate < 0 {
		direction = "falling"
		directionLabel = "Abfall"
	}
	at := trustedTime(ev)

	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   clampConfidence(confidence, 0.5, 0.85),
		dedupKey:     rules.DedupKey(rules.IDThermalRate, string(ev.SiteID), string(ev.SensorID), reading.Metric, direction),
		title:        fmt.Sprintf("Zu schneller Temperatur%s über dem Betreiber-Grenzwert", directionLabel),
		hypothesis:   "Ein schneller Temperaturwechsel kann durch Abtauen, Türöffnung, Warenbeladung, eine Anlagenstörung oder eine Sollwert-/Modusänderung entstehen. Die Rate allein beweist keine Manipulation.",
		alternatives: []string{"Abtauzyklus (bei bekanntem Modus unterdrückt)", "Türöffnung oder Warenbeladung", "Kompressor-/Ventilschaltung", "Sollwert-/Modusänderung (nicht bewiesen)"},
		checks:       []string{"Temperaturverlauf und Sensorqualität prüfen", "Türzustand, Warenbeladung und Abtauplan abgleichen", "Bei zeitlichem Zusammenhang mit einem Wartungszugriff den Incident-Prozess prüfen"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	if ev.SensorID != "" {
		draft.sensorIDs = []domain.SensorID{ev.SensorID}
	}
	if ev.AssetID != "" {
		draft.assetIDs = []domain.AssetID{ev.AssetID}
	}
	draft.addFact(fmt.Sprintf("Temperatur %s fiel von %s °C auf %s °C bzw. stieg entsprechend: Änderung %s °C in %s (%.2f °C/min, Richtung %s).",
		reading.Metric, formatFloat(first.ValueC, 2), formatFloat(last.ValueC, 2), formatFloat(last.ValueC-first.ValueC, 2),
		humanDuration(span), rate, direction))
	draft.addFact(fmt.Sprintf("Betreiber-Grenzwert max_rate_c_per_min=%s aus Policy %s Version %d.", formatFloat(maxRate, 2), policy.PolicyID, policy.Version))
	draft.addEvidence("measurement", string(ev.EventID), fmt.Sprintf("%s = %s °C", reading.Metric, formatFloat(reading.ValueC, 2)),
		ev.Source, fmt.Sprintf("rate_c_per_min=%s max_rate=%s", formatFloat(rate, 2), formatFloat(maxRate, 2)), reading.At, 0.85)
	draft.addEvidence("baseline", "", fmt.Sprintf("Ausgangswert %s °C um %s", formatFloat(first.ValueC, 2), first.At.Format(time.RFC3339)),
		"detect:series", fmt.Sprintf("window=%s points=%d", humanDuration(rateWindow), len(points)), first.At, 0.75)
	draft.addEvidence("policy", string(policy.PolicyID), "Betreiber-Grenzwert für Temperaturänderungsrate", "detect:policy",
		fmt.Sprintf("policy_version=%d max_rate_c_per_min=%s", policy.Version, formatFloat(maxRate, 2)), at, 0.9)
	return []domain.Alert{draft.build()}
}

// dedupeSeries removes duplicate timestamps, keeping the last (current) value.
func dedupeSeries(points []seriesPoint) []seriesPoint {
	if len(points) < 2 {
		return points
	}
	out := points[:1]
	for _, point := range points[1:] {
		if point.At.Equal(out[len(out)-1].At) {
			out[len(out)-1] = point
			continue
		}
		out = append(out, point)
	}
	return out
}

// clampSeriesWindow keeps only points inside the rate window.
func clampSeriesWindow(points []seriesPoint, from, to time.Time) []seriesPoint {
	out := make([]seriesPoint, 0, len(points))
	for _, point := range points {
		if point.At.Before(from) || point.At.After(to) {
			continue
		}
		out = append(out, point)
	}
	return out
}

func outOfBoundsLabel(side string) string {
	if side == "min" {
		return "unterhalb"
	}
	return "oberhalb"
}

func zoneLabel(zone domain.ZoneID) string {
	if zone == "" {
		return "(ohne Zone)"
	}
	return string(zone)
}

func qualityLabel(quality domain.Quality) string {
	if quality == "" {
		return "unbekannt"
	}
	return string(quality)
}
