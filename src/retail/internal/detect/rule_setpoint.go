package detect

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// setpointDeviationRule implements retail.thermal.setpoint-deviation. It covers
// three observable facts that share the same operator question ("did somebody
// change the target or the operating mode?"):
//
//  1. a reported setpoint changed outside an approved maintenance window,
//  2. the measured value deviates from the reported setpoint beyond the
//     operator-configured tolerance,
//  3. the operating mode switched into a suspicious mode (off/heat/manual).
//
// Defrost/cooling mode changes are normal and never alerted. Without an
// operator-configured tolerance (or a known previous setpoint) the respective
// check stays silent.
type setpointDeviationRule struct{ baseRule }

func newSetpointDeviationRule() *setpointDeviationRule {
	return &setpointDeviationRule{baseRule: baseFor(rules.IDThermalSetpoint)}
}

func (r *setpointDeviationRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if ev.Kind != domain.EventTelemetry || ev.Measurement == nil {
		return nil
	}
	measurement := ev.Measurement
	metric := strings.ToLower(strings.TrimSpace(measurement.Metric))
	policy := w.Policy()
	at := trustedTime(ev)
	grace := time.Duration(policy.Maintenance.GracePeriodS) * time.Second
	target := ev.AssetID
	window, inWindow := coveringWindow(w, ev.SiteID, at, target, grace)
	asset, assetKnown := domain.Asset{}, false
	if target != "" {
		asset, assetKnown = w.Asset(target)
	}

	alerts := make([]domain.Alert, 0, 3)
	if alert, ok := r.setpointChange(w, ev, measurement, metric, policy, at, inWindow, window); ok {
		alerts = append(alerts, alert)
	}
	if alert, ok := r.valueDeviation(ev, measurement, metric, policy, at); ok {
		alerts = append(alerts, alert)
	}
	if alert, ok := r.modeChange(w, ev, measurement, metric, policy, at, inWindow, window, asset, assetKnown); ok {
		alerts = append(alerts, alert)
	}
	return alerts
}

func (r *setpointDeviationRule) setpointChange(w World, ev domain.Event, measurement *domain.Measurement, metric string, policy domain.Policy, at time.Time, inWindow bool, window domain.MaintenanceWindow) (domain.Alert, bool) {
	if !setpointMetric(metric) || inWindow {
		return domain.Alert{}, false // approved maintenance window may change setpoints
	}
	previous, ok := previousSample(w, ev.SensorID, measurement.ObservedAt)
	if !ok {
		return domain.Alert{}, false // no previous setpoint known -> no claim
	}
	previousSetpoint, ok := temperatureInC(previous.Value, previous.Unit)
	if !ok {
		return domain.Alert{}, false
	}
	currentSetpoint, ok := temperatureInC(measurement.Value, measurement.Unit)
	if !ok {
		return domain.Alert{}, false
	}
	delta := currentSetpoint - previousSetpoint
	threshold := setpointChangeSensitivityC
	if tolerance := zoneSetpointTolerance(policy, ev.ZoneID); tolerance != nil && *tolerance > 0 {
		threshold = *tolerance
	}
	if math.Abs(delta) < threshold {
		return domain.Alert{}, false
	}
	severity := domain.SeverityMedium
	if math.Abs(delta) >= 2*threshold {
		severity = domain.SeverityHigh
	}
	observedAt := measurement.ObservedAt
	if observedAt.IsZero() {
		observedAt = at
	}
	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   0.70,
		dedupKey:     rules.DedupKey(rules.IDThermalSetpoint, string(ev.SiteID), string(ev.SensorID), "setpoint-change"),
		title:        "Sollwertänderung außerhalb eines freigegebenen Wartungsfensters",
		hypothesis:   "Die Sollwertänderung kann durch eine freigegebene, aber nicht im Wartungsfenster gepflegte Wartung erfolgt sein; eine unbefugte Änderung ist möglich, aber nicht bewiesen.",
		alternatives: []string{"Freigegebene Wartung ohne aktiv gepflegtes Fenster", "Automatische Verbund-/Regelungsroutine", "Inbetriebnahme/Parametrierung", "Mess-/Übertragungsfehler des Sollwerts"},
		checks:       []string{"Sollwert am Controller read-only verifizieren (freigegebener Weg)", "Freigabe/Ticket für die Änderung prüfen", "Ist-Zustand durch Anlagenverantwortlichen bewerten lassen"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	draft.sensorIDs = []domain.SensorID{ev.SensorID}
	if ev.AssetID != "" {
		draft.assetIDs = []domain.AssetID{ev.AssetID}
	}
	draft.addFact(fmt.Sprintf("Beobachteter Sollwert %s wechselte von %s °C auf %s °C um %s (Änderung %s °C).",
		metric, formatFloat(previousSetpoint, 2), formatFloat(currentSetpoint, 2), at.Format(time.RFC3339), formatFloat(delta, 2)))
	draft.addFact("Kein freigegebenes Wartungsfenster deckt das Zielasset zum Zeitpunkt der Änderung ab.")
	draft.addEvidence("measurement", string(ev.EventID), fmt.Sprintf("Sollwert = %s °C", formatFloat(currentSetpoint, 2)), ev.Source,
		fmt.Sprintf("previous=%s delta=%s threshold=%s", formatFloat(previousSetpoint, 2), formatFloat(delta, 2), formatFloat(threshold, 2)), observedAt, 0.8)
	draft.addEvidence("baseline", "", fmt.Sprintf("Vorheriger Sollwert %s °C um %s", formatFloat(previousSetpoint, 2), previous.At.Format(time.RFC3339)),
		"detect:series", "previous_sample", previous.At, 0.75)
	draft.addEvidence("window", string(window.WindowID), "Kein deckendes Wartungsfenster", "detect:window", "in_window=false", at, 0.85)
	return draft.build(), true
}

func (r *setpointDeviationRule) valueDeviation(ev domain.Event, measurement *domain.Measurement, metric string, policy domain.Policy, at time.Time) (domain.Alert, bool) {
	if measurement.Setpoint == nil {
		return domain.Alert{}, false
	}
	reading, ok := temperatureValue(ev)
	if !ok || reading.Setpoint == nil || !qualityReliable(reading.Quality) {
		return domain.Alert{}, false
	}
	limit, ok := findTemperatureLimit(policy, ev.ZoneID, reading.Metric, reading.At)
	if !ok || limit.SetpointToleranceC == nil || *limit.SetpointToleranceC <= 0 {
		return domain.Alert{}, false // no operator tolerance -> no deviation claim
	}
	tolerance := *limit.SetpointToleranceC
	deviation := math.Abs(reading.ValueC - *reading.Setpoint)
	if deviation <= tolerance {
		return domain.Alert{}, false
	}
	severity := domain.SeverityMedium
	if deviation > 2*tolerance {
		severity = domain.SeverityHigh
	}
	severity = capSeverity(severity, modeCeiling(reading.Mode))
	observedAt := reading.At
	if observedAt.IsZero() {
		observedAt = at
	}
	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   0.65,
		dedupKey:     rules.DedupKey(rules.IDThermalSetpoint, string(ev.SiteID), string(ev.SensorID), "setpoint-deviation"),
		title:        "Messwert weicht vom Sollwert über die Betreiber-Toleranz ab",
		hypothesis:   "Die Abweichung kann durch Türöffnung, Warenbeladung, Abtauen, eine Anlagenstörung oder eine Sollwertänderung entstehen; die Ursache ist nicht bewiesen.",
		alternatives: []string{"Türöffnung oder Warenbeladung", "Abtauzyklus", "Anlagenstörung", "Sollwertänderung ohne Übernahme der Regelung", "Sensorfehler"},
		checks:       []string{"Ist-Temperatur und Sollwert read-only verifizieren", "Betriebsmodus und Abtauplan prüfen", "Anlagenverantwortlichen bei anhaltender Abweichung einschalten"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	draft.sensorIDs = []domain.SensorID{ev.SensorID}
	if ev.AssetID != "" {
		draft.assetIDs = []domain.AssetID{ev.AssetID}
	}
	draft.addFact(fmt.Sprintf("Messwert %s °C weicht um %s °C vom gemeldeten Sollwert %s °C ab; Betreiber-Toleranz %s °C (Policy %s Version %d).",
		formatFloat(reading.ValueC, 2), formatFloat(deviation, 2), formatFloat(*reading.Setpoint, 2), formatFloat(tolerance, 2), policy.PolicyID, policy.Version))
	draft.addEvidence("measurement", string(ev.EventID), fmt.Sprintf("%s = %s °C, Sollwert %s °C", reading.Metric, formatFloat(reading.ValueC, 2), formatFloat(*reading.Setpoint, 2)),
		ev.Source, fmt.Sprintf("deviation=%s tolerance=%s", formatFloat(deviation, 2), formatFloat(tolerance, 2)), observedAt, 0.8)
	draft.addEvidence("policy", string(policy.PolicyID), "Sollwert-Toleranz aus Betreiber-Policy", "detect:policy",
		fmt.Sprintf("policy_version=%d setpoint_tolerance_c=%s", policy.Version, formatFloat(tolerance, 2)), at, 0.9)
	return draft.build(), true
}

func (r *setpointDeviationRule) modeChange(w World, ev domain.Event, measurement *domain.Measurement, metric string, policy domain.Policy, at time.Time, inWindow bool, window domain.MaintenanceWindow, asset domain.Asset, assetKnown bool) (domain.Alert, bool) {
	mode := strings.ToLower(strings.TrimSpace(measurement.Mode))
	if mode == "" || !suspiciousMode(mode) || inWindow {
		return domain.Alert{}, false
	}
	previous, ok := previousSample(w, ev.SensorID, measurement.ObservedAt)
	if !ok {
		return domain.Alert{}, false
	}
	previousMode := strings.ToLower(strings.TrimSpace(previous.Mode))
	if previousMode == mode {
		return domain.Alert{}, false
	}
	if !suspiciousMode(mode) {
		return domain.Alert{}, false
	}
	severity := domain.SeverityMedium
	if assetKnown && assetCritical(asset) && (strings.Contains(mode, "off") || strings.Contains(mode, "aus")) {
		severity = domain.SeverityHigh
	}
	observedAt := measurement.ObservedAt
	if observedAt.IsZero() {
		observedAt = at
	}
	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   0.55,
		dedupKey:     rules.DedupKey(rules.IDThermalSetpoint, string(ev.SiteID), string(ev.SensorID), "mode-change"),
		title:        "Unerwarteter Betriebsmoduswechsel",
		hypothesis:   "Ein Wechsel in einen verdächtigen Betriebsmodus (Aus/Heizen/Hand) kann durch eine freigegebene Wartung, eine Anlagenstörung oder eine unbefugte Änderung entstehen; die Ursache ist nicht bewiesen.",
		alternatives: []string{"Freigegebene Wartung/Parametrierung", "Automatische Regelungs-/Verbundlogik", "Anlagenstörung", "Übertragung eines veralteten Moduswerts"},
		checks:       []string{"Betriebsmodus am Controller read-only verifizieren", "Freigabe/Ticket prüfen", "Anlagenverantwortlichen einschalten, wenn der Modus nicht freigegeben ist"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	draft.sensorIDs = []domain.SensorID{ev.SensorID}
	if ev.AssetID != "" {
		draft.assetIDs = []domain.AssetID{ev.AssetID}
	}
	draft.addFact(fmt.Sprintf("Betriebsmodus wechselte von %q auf %q um %s.", previousMode, mode, at.Format(time.RFC3339)))
	draft.addFact("Kein freigegebenes Wartungsfenster deckt das Zielasset zum Zeitpunkt des Moduswechsels ab.")
	draft.addEvidence("measurement", string(ev.EventID), fmt.Sprintf("Modus = %q", mode), ev.Source,
		fmt.Sprintf("previous_mode=%q policy_version=%d", previousMode, policy.Version), observedAt, 0.75)
	draft.addEvidence("window", string(window.WindowID), "Kein deckendes Wartungsfenster", "detect:window", "in_window=false", at, 0.85)
	return draft.build(), true
}

// sensorDivergenceRule implements retail.thermal.sensor-divergence: two sensors
// of the same zone/metric disagree beyond the operator limit. This is a
// data-quality signal, not a process alarm.
type sensorDivergenceRule struct{ baseRule }

func newSensorDivergenceRule() *sensorDivergenceRule {
	return &sensorDivergenceRule{baseRule: baseFor(rules.IDThermalSensorDivergence)}
}

func (r *sensorDivergenceRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	reading, ok := temperatureValue(ev)
	if !ok || !qualityReliable(reading.Quality) {
		return nil
	}
	policy := w.Policy()
	if policy.Sensors.DivergenceC == nil || *policy.Sensors.DivergenceC <= 0 {
		return nil // no operator threshold -> no alert (no universal limits)
	}
	threshold := *policy.Sensors.DivergenceC
	window := time.Duration(policy.Sensors.DivergenceWindowS) * time.Second
	if window <= 0 {
		window = divergenceWindowDefault
	}
	now := w.Now()
	if now.IsZero() {
		now = reading.At
	}

	type peerReading struct {
		sensor      domain.Sensor
		independent bool
		sample      domain.Sample
		valueC      float64
	}
	peers := make([]peerReading, 0, 4)
	currentSensor, currentKnown := sensorByID(w, ev.SiteID, ev.SensorID)
	for _, sensor := range w.Sensors(ev.SiteID) {
		if sensor.SensorID == ev.SensorID {
			continue
		}
		if !sameMetric(sensor.Metric, reading.Metric) {
			continue
		}
		if sensor.ZoneID != "" && ev.ZoneID != "" && sensor.ZoneID != ev.ZoneID {
			continue
		}
		sample, ok := latestSample(w, sensor.SensorID, window)
		if !ok || now.Sub(sample.At) > window {
			continue
		}
		valueC, ok := temperatureInC(sample.Value, sample.Unit)
		if !ok {
			continue
		}
		peers = append(peers, peerReading{sensor: sensor, independent: sensor.Independent, sample: sample, valueC: valueC})
	}
	if len(peers) == 0 {
		return nil
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].sensor.SensorID < peers[j].sensor.SensorID })
	best := peers[0]
	bestDivergence := math.Abs(reading.ValueC - best.valueC)
	for _, peer := range peers[1:] {
		divergence := math.Abs(reading.ValueC - peer.valueC)
		if divergence > bestDivergence {
			best = peer
			bestDivergence = divergence
		}
	}
	if bestDivergence <= threshold {
		return nil
	}
	severity := domain.SeverityMedium
	if bestDivergence > 2*threshold {
		severity = domain.SeverityHigh
	}
	confidence := 0.55
	if currentKnown && currentSensor.Independent && best.independent {
		confidence += 0.15
	}
	if best.sensor.Critical || (currentKnown && currentSensor.Critical) {
		confidence += 0.10
	}
	at := trustedTime(ev)
	pairA, pairB := string(ev.SensorID), string(best.sensor.SensorID)
	if pairB < pairA {
		pairA, pairB = pairB, pairA
	}
	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   clampConfidence(confidence, 0.5, 0.8),
		dedupKey:     rules.DedupKey(rules.IDThermalSensorDivergence, string(ev.SiteID), string(ev.ZoneID), pairA, pairB),
		title:        "Abweichung zwischen unabhängigen Temperatursensoren",
		hypothesis:   "Widersprüchliche Messwerte können durch Sensor-Drift/-Defekt, unterschiedliche Messpositionen, einen lokalen Abtauzyklus oder eine manipulierte Telemetrie entstehen; die Ursache ist nicht bewiesen.",
		alternatives: []string{"Sensor-Drift oder Defekt", "Unterschiedliche Messposition (Luft vs. Produkt)", "Lokaler Abtauzyklus eines Verdampfers", "Kalibrierfehler", "Manipulierte Telemetrie (nicht bewiesen)"},
		checks:       []string{"Beide Sensoren mit geeichtem Referenzthermometer prüfen", "Messposition, Sensorzuordnung und Kalibrierdatum abgleichen", "Keine Aussage über die Warensicherheit allein aus diesem Signal"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	draft.sensorIDs = []domain.SensorID{ev.SensorID, best.sensor.SensorID}
	if ev.AssetID != "" {
		draft.assetIDs = []domain.AssetID{ev.AssetID}
	}
	draft.addFact(fmt.Sprintf("Sensor %s (%s °C) und Sensor %s (%s °C) differieren um %s °C; Betreiber-Schwelle divergence_c=%s °C (Policy %s Version %d, Fenster %s).",
		ev.SensorID, formatFloat(reading.ValueC, 2), best.sensor.SensorID, formatFloat(best.valueC, 2), formatFloat(bestDivergence, 2),
		formatFloat(threshold, 2), policy.PolicyID, policy.Version, humanDuration(window)))
	draft.addEvidence("measurement", string(ev.EventID), fmt.Sprintf("Sensor %s = %s °C", ev.SensorID, formatFloat(reading.ValueC, 2)), ev.Source,
		fmt.Sprintf("metric=%s zone=%s", reading.Metric, ev.ZoneID), reading.At, 0.85)
	draft.addEvidence("measurement", string(best.sensor.SensorID), fmt.Sprintf("Vergleichssensor %s = %s °C um %s", best.sensor.SensorID, formatFloat(best.valueC, 2), best.sample.At.Format(time.RFC3339)),
		"detect:sensor", fmt.Sprintf("independent=%t critical=%t", best.independent, best.sensor.Critical), best.sample.At, 0.8)
	draft.addEvidence("policy", string(policy.PolicyID), "Sensor-Plausibilitätsgrenze aus Betreiber-Policy", "detect:policy",
		fmt.Sprintf("policy_version=%d divergence_c=%s divergence_window_s=%d", policy.Version, formatFloat(threshold, 2), policy.Sensors.DivergenceWindowS), at, 0.9)
	return []domain.Alert{draft.build()}
}

func setpointMetric(metric string) bool {
	m := strings.ToLower(strings.TrimSpace(metric))
	return m == "setpoint" || m == "sollwert" || strings.HasSuffix(m, "_setpoint") || strings.HasSuffix(m, "_sollwert")
}

func suspiciousMode(mode string) bool {
	m := strings.ToLower(strings.TrimSpace(mode))
	switch m {
	case "off", "aus", "stop", "stopped", "halt", "manual", "hand", "handbetrieb", "heating", "heat", "heizen", "force", "forced":
		return true
	}
	for _, hint := range []string{"off", "aus", "heiz", "heat", "manual", "hand"} {
		if strings.Contains(m, hint) {
			return true
		}
	}
	return false
}

// zoneSetpointTolerance returns the first setpoint tolerance configured for a
// zone, independent of the metric (setpoint telemetry often has its own metric
// name that does not match the limit entry).
func zoneSetpointTolerance(policy domain.Policy, zone domain.ZoneID) *float64 {
	for _, limit := range policy.Temperature.Limits {
		if limit.ZoneID != zone {
			continue
		}
		if limit.SetpointToleranceC != nil && *limit.SetpointToleranceC > 0 {
			tolerance := *limit.SetpointToleranceC
			return &tolerance
		}
	}
	return nil
}

// modeCeiling limits severity for known benign operating modes.
func modeCeiling(mode string) domain.Severity {
	switch classifyMode(mode) {
	case modeDefrost:
		return domain.SeverityLow
	case modeDoorOpen, modeLoading:
		return domain.SeverityMedium
	default:
		return domain.SeverityHigh
	}
}

func sameMetric(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return true
	}
	return strings.EqualFold(a, b)
}
