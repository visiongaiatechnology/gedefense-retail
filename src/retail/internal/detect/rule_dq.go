package detect

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// frozenValueRule implements retail.dq.frozen-value: a temperature series that
// is exactly constant for the operator-configured window while comparison
// sensors move. A constant value is never treated as "stable cooling is fine".
type frozenValueRule struct{ baseRule }

func newFrozenValueRule() *frozenValueRule {
	return &frozenValueRule{baseRule: baseFor(rules.IDDataQualityFrozen)}
}

func (r *frozenValueRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	reading, ok := temperatureValue(ev)
	if !ok {
		return nil
	}
	policy := w.Policy()
	windowSeconds := policy.DataQuality.FrozenValueWindowS
	if windowSeconds <= 0 {
		return nil
	}
	window := time.Duration(windowSeconds) * time.Second
	now := w.Now()
	if now.IsZero() {
		now = reading.At
	}
	from := now.Add(-window)
	samples := w.SamplesFor(ev.SensorID, from)
	points := append(seriesFromSamples(samples, reading.Metric), seriesPoint{At: reading.At, ValueC: reading.ValueC})
	sort.Slice(points, func(i, j int) bool { return points[i].At.Before(points[j].At) })
	points = dedupeSeries(points)
	points = clampSeriesWindow(points, from, now.Add(time.Minute))
	if len(points) < frozenMinPoints {
		return nil
	}
	first, last := points[0], points[len(points)-1]
	span := last.At.Sub(first.At)
	minSpan := time.Duration(float64(window) * frozenCoverage)
	if span < minSpan {
		return nil
	}
	if !allNearlyEqual(points, 1e-6) {
		return nil
	}
	movement, peerCount, peerID := comparisonMovement(w, ev, reading.Metric, window, now)
	threshold := comparisonMovementDefaultC
	if policy.Sensors.DivergenceC != nil && *policy.Sensors.DivergenceC > 0 {
		threshold = *policy.Sensors.DivergenceC
	}
	moving := peerCount > 0 && movement > threshold
	severity := domain.SeverityMedium
	confidence := 0.55
	if moving {
		severity = domain.SeverityHigh
		confidence += 0.20
	}
	at := trustedTime(ev)
	facts := []string{
		fmt.Sprintf("Sensor %s lieferte über %s exakt denselben Wert %s °C (%d Beobachtungen, Fenster %s).",
			ev.SensorID, humanDuration(span), formatFloat(first.ValueC, 2), len(points), humanDuration(window)),
	}
	if moving {
		facts = append(facts, fmt.Sprintf("Vergleichssensor %s bewegte sich im selben Fenster um %s °C.", peerID, formatFloat(movement, 2)))
	} else {
		facts = append(facts, "Kein belastbarer Vergleichssensor mit Bewegung im selben Fenster verfügbar.")
	}
	facts = append(facts, "Ein konstanter Wert ist keine Aussage über eine sichere Kühlkette.")

	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   clampConfidence(confidence, 0.5, 0.8),
		dedupKey:     rules.DedupKey(rules.IDDataQualityFrozen, string(ev.SiteID), string(ev.SensorID)),
		title:        "Konstantwert (eingefrorener Messwert) im Kühlbereich",
		hypothesis:   "Ein exakt konstanter Wert kann durch einen defekten Sensor, eine hängende Schnittstelle oder eine manipulierte/replayte Telemetrie entstehen; 'unverändert' bedeutet nicht 'sicher'.",
		alternatives: []string{"Defekter oder hängender Sensor", "Blockierte Übertragungsstrecke mit Wiederholung des letzten Werts", "Sehr stabile Temperatur in leerem geschlossenem Raum (bei Auflösung nahe der Messgenauigkeit)", "Manipulierte/replayte Telemetrie (nicht bewiesen)"},
		checks:       []string{"Sensor und Übertragungsweg durch zuständiges Personal prüfen", "Unabhängige Temperaturmessung durchführen", "Messwert bis zur Klärung nicht als 'in Ordnung' darstellen"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	draft.sensorIDs = []domain.SensorID{ev.SensorID}
	if ev.AssetID != "" {
		draft.assetIDs = []domain.AssetID{ev.AssetID}
	}
	for _, fact := range facts {
		draft.addFact(fact)
	}
	draft.addEvidence("measurement", string(ev.EventID), fmt.Sprintf("%s = %s °C", reading.Metric, formatFloat(reading.ValueC, 2)), ev.Source,
		fmt.Sprintf("constant_series points=%d span=%s window=%s", len(points), humanDuration(span), humanDuration(window)), at, 0.8)
	if moving {
		draft.addEvidence("baseline", peerID, fmt.Sprintf("Vergleichssensor bewegte sich um %s °C", formatFloat(movement, 2)), "detect:comparison",
			fmt.Sprintf("movement=%s", formatFloat(movement, 2)), now, 0.7)
	}
	draft.addEvidence("policy", string(policy.PolicyID), "Betreiber-Fenster für Konstantwerte", "detect:policy",
		fmt.Sprintf("policy_version=%d frozen_value_window_s=%d", policy.Version, windowSeconds), at, 0.9)
	return []domain.Alert{draft.build()}
}

// gapRule implements retail.dq.gap both event-driven (exact hole when telemetry
// resumes) and in the periodic tick (sensor currently silent).
type gapRule struct{ baseRule }

func newGapRule() *gapRule {
	return &gapRule{baseRule: baseFor(rules.IDDataQualityGap)}
}

func (r *gapRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if ev.Kind != domain.EventTelemetry || ev.Measurement == nil {
		return nil
	}
	policy := w.Policy()
	gapSeconds := policy.DataQuality.TelemetryGapS
	if gapSeconds <= 0 {
		return nil
	}
	threshold := time.Duration(gapSeconds) * time.Second
	at := observedAtOf(ev)
	previous, ok := previousSample(w, ev.SensorID, at)
	if !ok {
		return nil // no history yet -> no gap claim
	}
	hole := at.Sub(previous.At)
	if hole <= threshold {
		return nil
	}
	severity := domain.SeverityMedium
	if hole > 3*threshold {
		severity = domain.SeverityHigh
	}
	alert := buildGapAlert(r.spec, ev.SiteID, ev.ZoneID, ev.SensorID, ev.AssetID, previous.At, hole, threshold, ev, policy, at)
	alert.Severity = severity
	return []domain.Alert{alert}
}

func (r *gapRule) OnTick(ctx context.Context, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	policy := w.Policy()
	gapSeconds := policy.DataQuality.TelemetryGapS
	if gapSeconds <= 0 {
		return nil
	}
	threshold := time.Duration(gapSeconds) * time.Second
	now := w.Now()
	if now.IsZero() {
		return nil
	}
	out := make([]domain.Alert, 0, 8)
	since := now.Add(-eventLookback)
	for _, site := range w.Sites() {
		if err := ctx.Err(); err != nil {
			break
		}
		sensors := w.Sensors(site.SiteID)
		if len(sensors) == 0 {
			continue
		}
		samples := w.Samples(site.SiteID, since)
		latest := make(map[domain.SensorID]time.Time, len(sensors))
		for _, sample := range samples {
			if sample.SensorID == "" || sample.At.IsZero() {
				continue
			}
			if sample.At.After(latest[sample.SensorID]) {
				latest[sample.SensorID] = sample.At
			}
		}
		for _, sensor := range sensors {
			lastSeen := latest[sensor.SensorID]
			if lastSeen.IsZero() {
				lastSeen = sensor.LastSeenAt
			}
			if lastSeen.IsZero() {
				continue // never observed: do not storm the operator at startup
			}
			hole := now.Sub(lastSeen)
			if hole <= threshold {
				continue
			}
			severity := domain.SeverityMedium
			if hole > 3*threshold || sensor.Critical {
				severity = domain.SeverityHigh
			}
			event := domain.Event{
				SiteID:   site.SiteID,
				ZoneID:   sensor.ZoneID,
				SensorID: sensor.SensorID,
				AssetID:  sensor.AssetID,
			}
			alert := buildGapAlert(r.spec, site.SiteID, sensor.ZoneID, sensor.SensorID, sensor.AssetID, lastSeen, hole, threshold, event, policy, now)
			alert.Severity = severity
			out = append(out, alert)
			if len(out) >= maxTickAlerts {
				return out
			}
		}
	}
	return out
}

func buildGapAlert(spec rules.Spec, site domain.SiteID, zone domain.ZoneID, sensorID domain.SensorID, assetID domain.AssetID, lastSeen time.Time, hole, threshold time.Duration, ev domain.Event, policy domain.Policy, at time.Time) domain.Alert {
	source := ev.Source
	if source == "" {
		source = "detect:tick"
	}
	if at.IsZero() {
		at = lastSeen
	}
	draft := &alertDraft{
		spec:         spec,
		site:         site,
		severity:     domain.SeverityMedium,
		confidence:   0.75,
		dedupKey:     rules.DedupKey(rules.IDDataQualityGap, string(site), string(sensorID)),
		title:        "Datenlücke in der Telemetrie",
		hypothesis:   "Mögliche Ursachen sind ein Collector-/Gateway-Ausfall, ein Netzwerkproblem, die Sensor-Stromversorgung oder eine deaktivierte Meldestrecke; eine Manipulation ist möglich, aber nicht bewiesen.",
		alternatives: []string{"Collector-/Gateway-Ausfall oder Wartung", "Netzwerkunterbrechung zur Filiale", "Sensor-Stromversorgung/-Defekt", "Sensor im Deaktivierungs-/Standby-Modus", "Manipulation der Telemetriestrecke (nicht bewiesen)"},
		checks:       []string{"Sensor-/Gateway-Konnektivität und Collector-Health prüfen", "Fehlende Telemetrie als 'keine Aussage' dokumentieren, nicht als 'in Ordnung'", "Letzte valide Messung und Vergleichssensoren prüfen"},
		at:           at,
	}
	if zone != "" {
		draft.zoneIDs = []domain.ZoneID{zone}
	}
	if sensorID != "" {
		draft.sensorIDs = []domain.SensorID{sensorID}
	}
	if assetID != "" {
		draft.assetIDs = []domain.AssetID{assetID}
	}
	draft.addFact(fmt.Sprintf("Sensor %s lieferte seit %s keine Telemetrie (Lücke %s, Betreiber-Schwellwert %s).",
		sensorID, lastSeen.UTC().Format(time.RFC3339), humanDuration(hole), humanDuration(threshold)))
	draft.addFact("Fehlende Telemetrie ist keine Aussage über eine sichere Temperatur.")
	draft.addEvidence("measurement", string(sensorID), fmt.Sprintf("Letzte Beobachtung um %s", lastSeen.UTC().Format(time.RFC3339)), source,
		fmt.Sprintf("gap=%s threshold=%s", humanDuration(hole), humanDuration(threshold)), lastSeen, 0.8)
	draft.addEvidence("policy", string(policy.PolicyID), "Betreiber-Schwellwert für Telemetrielücken", "detect:policy",
		fmt.Sprintf("policy_version=%d telemetry_gap_s=%d", policy.Version, int(threshold.Seconds())), at, 0.9)
	return draft.build()
}

// clockSkewRule implements retail.dq.clock-skew: device/gateway time deviation,
// device source-timestamp deviation and non-monotonic observation timestamps.
type clockSkewRule struct{ baseRule }

func newClockSkewRule() *clockSkewRule {
	return &clockSkewRule{baseRule: baseFor(rules.IDDataQualityClockSkew)}
}

func (r *clockSkewRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if ev.ObservedAt.IsZero() || ev.ReceivedAt.IsZero() {
		return nil
	}
	policy := w.Policy()
	maxSeconds := policy.DataQuality.MaxClockSkewS
	if maxSeconds <= 0 {
		return nil
	}
	maxSkew := time.Duration(maxSeconds) * time.Second
	now := w.Now()
	if now.IsZero() {
		now = ev.ReceivedAt
	}
	out := make([]domain.Alert, 0, 3)
	skew := ev.ReceivedAt.Sub(ev.ObservedAt)
	if absDuration(skew) > maxSkew {
		out = append(out, r.deviationAlert(ev, "skew", skew, maxSkew, policy,
			"Zeitstempel-Abweichung zwischen Beobachtung und Empfang",
			fmt.Sprintf("Beobachtung %s, Empfang %s: Differenz %s über Toleranz %s.",
				ev.ObservedAt.UTC().Format(time.RFC3339), ev.ReceivedAt.UTC().Format(time.RFC3339), humanDuration(absDuration(skew)), humanDuration(maxSkew))))
	}
	if ev.Measurement != nil && !ev.Measurement.SourceTS.IsZero() {
		sourceSkew := ev.ReceivedAt.Sub(ev.Measurement.SourceTS)
		if absDuration(sourceSkew) > maxSkew {
			out = append(out, r.deviationAlert(ev, "source-timestamp", sourceSkew, maxSkew, policy,
				"Geräte-Zeitstempel weicht von der Gateway-Zeit ab",
				fmt.Sprintf("Geräte-Zeitstempel %s, Empfang %s: Differenz %s über Toleranz %s.",
					ev.Measurement.SourceTS.UTC().Format(time.RFC3339), ev.ReceivedAt.UTC().Format(time.RFC3339), humanDuration(absDuration(sourceSkew)), humanDuration(maxSkew))))
		}
	}
	if alert, ok := r.regressionAlert(ev, w, now, maxSkew, policy); ok {
		out = append(out, alert)
	}
	return out
}

func (r *clockSkewRule) deviationAlert(ev domain.Event, kind string, difference, maxSkew time.Duration, policy domain.Policy, title, fact string) domain.Alert {
	severity := domain.SeverityMedium
	if absDuration(difference) > 5*maxSkew {
		severity = domain.SeverityHigh
	}
	at := trustedTime(ev)
	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   0.70,
		dedupKey:     rules.DedupKey(rules.IDDataQualityClockSkew, string(ev.SiteID), string(ev.SensorID), ev.Source, kind),
		title:        title,
		hypothesis:   "Eine Zeitabweichung kann durch fehlende NTP-Synchronisation, einen Zeitzonen-/Sommerzeitfehler oder eine manipulierte Gerätezeit entstehen; eine Manipulation ist nicht bewiesen, verfälscht aber Wartungsfenster- und Korrelationslogik.",
		alternatives: []string{"Fehlende NTP-Synchronisation/Drift", "Zeitzonen- oder Sommerzeitfehler in der Gerätekonfiguration", "Gateway-Neustart mit kurzem Zeitversatz", "Retransmission mit älterem Gerätezeitstempel", "Manipulierte Gerätezeit (nicht bewiesen)"},
		checks:       []string{"NTP-/Zeitquelle von Gerät und Gateway prüfen", "Betroffene Ereignisse als zeitunsicher markieren, nicht verwerfen", "Wartungsfenster-Bewertung für den Zeitraum überprüfen"},
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
	draft.addFact(fact)
	draft.addFact(fmt.Sprintf("Betreiber-Toleranz max_clock_skew_s=%d (Policy %s Version %d).", int(maxSkew.Seconds()), policy.PolicyID, policy.Version))
	draft.addEvidence("event", string(ev.EventID), fact, ev.Source,
		fmt.Sprintf("kind=%s difference_s=%d", kind, int64(difference.Seconds())), at, 0.8)
	draft.addEvidence("policy", string(policy.PolicyID), "Betreiber-Toleranz für Zeitabweichungen", "detect:policy",
		fmt.Sprintf("policy_version=%d max_clock_skew_s=%d", policy.Version, int(maxSkew.Seconds())), at, 0.9)
	return draft.build()
}

func (r *clockSkewRule) regressionAlert(ev domain.Event, w World, now time.Time, maxSkew time.Duration, policy domain.Policy) (domain.Alert, bool) {
	if ev.SensorID == "" {
		return domain.Alert{}, false
	}
	since := now.Add(-regressionLookback)
	events := w.Events(ports.EventQuery{
		SiteID:   ev.SiteID,
		SensorID: ev.SensorID,
		Since:    rfc3339(since),
		Limit:    maxQueryLimit,
	})
	newest := time.Time{}
	for _, other := range events {
		if other.EventID == ev.EventID || other.Kind != domain.EventTelemetry || other.ObservedAt.IsZero() {
			continue
		}
		if other.ObservedAt.After(newest) {
			newest = other.ObservedAt
		}
	}
	if newest.IsZero() {
		return domain.Alert{}, false
	}
	if !ev.ObservedAt.Before(newest.Add(-monotonicTolerance)) {
		return domain.Alert{}, false
	}
	regression := newest.Sub(ev.ObservedAt)
	severity := domain.SeverityMedium
	if regression > 5*time.Minute {
		severity = domain.SeverityHigh
	}
	at := trustedTime(ev)
	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   0.65,
		dedupKey:     rules.DedupKey(rules.IDDataQualityClockSkew, string(ev.SiteID), string(ev.SensorID), ev.Source, "regression"),
		title:        "Rückläufiger Zeitstempel eines Sensors",
		hypothesis:   "Ein rückläufiger Zeitstempel kann durch Zeitmanipulation, einen Sensor-/Gateway-Neustart oder eine fehlerhafte Zeitquelle entstehen; die Ursache ist nicht bewiesen, die Ereignisreihenfolge ist aber unzuverlässig.",
		alternatives: []string{"Sensor-/Gateway-Neustart mit zurückgesetzter Uhr", "Zeitmanipulation (nicht bewiesen)", "Retransmission mit älterem Zeitstempel", "Sommer-/Winterzeitfehler"},
		checks:       []string{"Zeitquelle des Sensors und des Gateways prüfen", "Betroffene Ereignisse als zeitunsicher markieren", "Timeline im Incident mit Unsicherheitsflag exportieren"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	draft.sensorIDs = []domain.SensorID{ev.SensorID}
	if ev.AssetID != "" {
		draft.assetIDs = []domain.AssetID{ev.AssetID}
	}
	draft.addFact(fmt.Sprintf("Beobachtungszeit %s liegt vor dem jüngsten bereits beobachteten Zeitstempel %s (Rücksprung %s, Toleranz %s).",
		ev.ObservedAt.UTC().Format(time.RFC3339), newest.UTC().Format(time.RFC3339), humanDuration(regression), humanDuration(monotonicTolerance)))
	draft.addEvidence("event", string(ev.EventID), "Rückläufiger Beobachtungszeitstempel", ev.Source,
		fmt.Sprintf("observed_at=%s newest_observed=%s", rfc3339(ev.ObservedAt), rfc3339(newest)), at, 0.75)
	draft.addEvidence("policy", string(policy.PolicyID), "Toleranz für Zeitabweichungen", "detect:policy",
		fmt.Sprintf("policy_version=%d max_clock_skew_s=%d", policy.Version, int(maxSkew.Seconds())), at, 0.9)
	return draft.build(), true
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// allNearlyEqual reports whether every series point equals the first within
// tolerance.
func allNearlyEqual(points []seriesPoint, tolerance float64) bool {
	if len(points) == 0 {
		return false
	}
	base := points[0].ValueC
	for _, point := range points[1:] {
		if math.Abs(point.ValueC-base) > tolerance {
			return false
		}
	}
	return true
}

// comparisonMovement returns the largest temperature movement among comparison
// sensors of the same zone/metric inside the window.
func comparisonMovement(w World, ev domain.Event, metric string, window time.Duration, now time.Time) (movement float64, peerCount int, peerID string) {
	since := now.Add(-window)
	for _, sensor := range w.Sensors(ev.SiteID) {
		if sensor.SensorID == ev.SensorID || !sameMetric(sensor.Metric, metric) {
			continue
		}
		if sensor.ZoneID != "" && ev.ZoneID != "" && sensor.ZoneID != ev.ZoneID {
			continue
		}
		latest, ok := latestSample(w, sensor.SensorID, window)
		if !ok || now.Sub(latest.At) > window {
			continue
		}
		samples := w.SamplesFor(sensor.SensorID, since)
		if len(samples) < 2 {
			continue
		}
		minValue, maxValue := math.Inf(1), math.Inf(-1)
		for _, sample := range samples {
			valueC, ok := temperatureInC(sample.Value, sample.Unit)
			if !ok {
				continue
			}
			if valueC < minValue {
				minValue = valueC
			}
			if valueC > maxValue {
				maxValue = valueC
			}
		}
		if math.IsInf(minValue, 1) {
			continue
		}
		peerCount++
		if delta := maxValue - minValue; delta > movement {
			movement = delta
			peerID = string(sensor.SensorID)
		}
	}
	return movement, peerCount, peerID
}
