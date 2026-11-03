package detect

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// unknownPeerRule implements retail.net.unknown-peer: a communication pair that
// is not part of the passive/operator baseline. It is observe-first by default
// (policy.Network.BaselineRequired=false) and never claims an attack.
type unknownPeerRule struct{ baseRule }

func newUnknownPeerRule() *unknownPeerRule {
	return &unknownPeerRule{baseRule: baseFor(rules.IDUnknownPeer)}
}

func (r *unknownPeerRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if ev.Kind != domain.EventFlow || ev.Flow == nil {
		return nil
	}
	flow := ev.Flow
	src := strings.TrimSpace(flow.SrcIP)
	dst := strings.TrimSpace(flow.DstIP)
	protocol := strings.ToLower(strings.TrimSpace(flow.Protocol))
	if src == "" || dst == "" || protocol == "" || src == dst {
		return nil
	}
	policy := w.Policy()
	if len(policy.Network.MonitoredPorts) > 0 && !portListed(policy.Network.MonitoredPorts, flow.DstPort) {
		return nil
	}

	known := w.KnownPeer(src, dst, protocol)
	// Keep learning: every observed pair becomes part of the passive baseline,
	// independent of whether an alert is emitted.
	w.ObservePeer(src, dst, protocol)
	if known || pairAllowed(policy, ev) {
		return nil
	}

	lookback := eventLookback
	if policy.Network.LearnedBaselineWindowS > 0 {
		lookback = time.Duration(policy.Network.LearnedBaselineWindowS) * time.Second
	}
	since, _ := lookbackSince(w, lookback)
	if priorFlow(w, ev, since, src, dst, protocol) {
		return nil // already observed before the current event -> baseline exists
	}
	if !policy.Network.BaselineRequired {
		return nil // observe-first onboarding: no alert without an enforced baseline
	}
	if graceActive(w, ev, policy.Network.UnknownPeerGraceS) {
		return nil // still inside the onboarding learning phase
	}

	asset, assetKnown := assetByIP(w, ev.SiteID, dst)
	severity := domain.SeverityMedium
	confidence := 0.55
	if otProtocolName(protocol) || isOTPort(flow.DstPort) {
		severity = domain.SeverityHigh
		confidence += 0.15
	}
	if assetKnown {
		if assetCritical(asset) {
			severity = domain.SeverityHigh
			confidence += 0.10
		}
		if assetIsOTController(asset) {
			severity = domain.SeverityHigh
		}
	}

	at := trustedTime(ev)
	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   clampConfidence(confidence, 0.5, 0.8),
		dedupKey:     rules.DedupKey(rules.IDUnknownPeer, string(ev.SiteID), src, dst, protocol),
		title:        "Unbekannter Kommunikationspartner im Filialnetz",
		hypothesis:   "Ein nicht inventarisiertes oder nicht freigegebenes Quellgerät kann auf eine Neuinstallation, eine fehlende Inventarisierung oder eine unautorisierte Verbindung hindeuten. Eine einzelne Flow-Beobachtung beweist keinen Angriff.",
		alternatives: []string{"Neuinstallation oder Inbetriebnahme", "Temporäres Dienstleistergerät ohne Inventarisierung", "NAT/Proxy verändert die beobachtete Quelladresse", "Collector-Artefakt (Retransmission, doppeltes Flow-Event)"},
		checks:       []string{"Quellgerät physisch bzw. über das Inventar identifizieren", "Wartungsfenster und Ticketlage prüfen", "Netzwerksegmentierung und freigegebene Kommunikationspaare (Policy) prüfen"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	if assetKnown {
		draft.assetIDs = []domain.AssetID{asset.AssetID}
	}
	draft.addFact(fmt.Sprintf("Neue Kommunikationsbeziehung %s → %s (%s, Zielport %d) um %s.", src, dst, protocol, flow.DstPort, at.Format(time.RFC3339)))
	draft.addFact(fmt.Sprintf("Kein früherer Flow dieses Paares innerhalb von %s im Event-Verlauf oder in der Peer-Baseline.", humanDuration(lookback)))
	if assetKnown {
		draft.addFact(fmt.Sprintf("Zielasset: %s (%s), Kritikalität %s.", asset.AssetID, asset.Type, asset.Criticality))
	}
	draft.addEvidence("event", string(ev.EventID), fmt.Sprintf("Flow %s → %s (%s)", src, dst, protocol), ev.Source,
		fmt.Sprintf("dst_port=%d bytes=%d packets=%d", flow.DstPort, flow.Bytes, flow.Packets), at, 0.8)
	if assetKnown {
		draft.addEvidence("asset", string(asset.AssetID), fmt.Sprintf("Zielasset %s (%s)", asset.Name, asset.Type), asset.Source,
			string(asset.Type), at, clampConfidence(asset.Confidence, 0, 1))
	}
	draft.addEvidence("baseline", "", fmt.Sprintf("Kein bekanntes Peer-Paar in den letzten %s", humanDuration(lookback)),
		"detect:baseline", "known=false", at, 0.8)
	return []domain.Alert{draft.build()}
}

// writeAttemptRule implements retail.write-attempt. GeDefense only observes
// writes; the product never executes one (see internal/guard). A write outside
// an approved maintenance window is a high signal value, but explicitly not
// "attack proven".
type writeAttemptRule struct{ baseRule }

func newWriteAttemptRule() *writeAttemptRule {
	return &writeAttemptRule{baseRule: baseFor(rules.IDWriteAttempt)}
}

func (r *writeAttemptRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if ev.Kind != domain.EventWriteAttempt || ev.WriteAttempt == nil {
		return nil
	}
	attempt := ev.WriteAttempt
	policy := w.Policy()
	at := trustedTime(ev)
	grace := time.Duration(policy.Maintenance.GracePeriodS) * time.Second
	window, inWindow := coveringWindow(w, ev.SiteID, at, ev.AssetID, grace)
	if inWindow && attempt.Allowed {
		return nil // approved maintenance write inside its window; still stored as event
	}

	confidence := 0.70
	if !attempt.Allowed {
		confidence += 0.10
	}
	windowFact := "Kein freigegebenes Wartungsfenster deckt das Zielasset zum Zeitpunkt des Schreibzugriffs."
	windowValue := "in_window=false"
	if inWindow {
		windowFact = fmt.Sprintf("Freigegebenes Wartungsfenster %s (Dienstleister %s) war aktiv.", window.WindowID, window.Vendor)
		windowValue = fmt.Sprintf("in_window=true window_id=%s", window.WindowID)
	}
	allowedFact := "Die Operation ist laut Policy/Allowlist nicht erlaubt."
	if attempt.Allowed {
		allowedFact = "Die Operation ist laut Policy/Allowlist erlaubt, es fehlt jedoch ein deckendes Wartungsfenster."
	}

	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     domain.SeverityHigh,
		confidence:   clampConfidence(confidence, 0.5, 0.85),
		dedupKey:     rules.DedupKey(rules.IDWriteAttempt, string(ev.SiteID), attempt.Source, attempt.Target, attempt.Function, attempt.Register),
		title:        "Beobachteter Schreibzugriff auf ein OT-Gerät",
		hypothesis:   "Ein beobachteter Schreibzugriff ist ein hoher Signalwert, beweist aber keinen Angriff: Eine freigegebene Wartung ohne gepflegtes Fenster, eine automatisierte Anlagenfunktion oder ein kompromittiertes Werkzeug sind mögliche Erklärungen.",
		alternatives: []string{"Freigegebene Wartung ohne aktiv gepflegtes Wartungsfenster", "Automatisierte Verbund-/Regelungsroutine mit Schreibroutine", "Inbetriebnahme-/Testgerät", "Verschlüsselte oder proprietäre Protokolle bleiben ohne passive Lesbarkeit unsichtbar"},
		checks:       []string{"Freigabe/Ticket und Dienstleisterkontakt zum beobachteten Zugriff verifizieren", "Ist-Zustand der betroffenen Anlage durch den Anlagenverantwortlichen prüfen lassen (read-only)", "Konfigurations-Baseline mit freigegebenem Export vergleichen und Evidenz sichern"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	if ev.AssetID != "" {
		draft.assetIDs = []domain.AssetID{ev.AssetID}
	}
	draft.addFact(fmt.Sprintf("Beobachtete Schreiboperation %s/%s von %s auf %s (Register %s) um %s.", attempt.Protocol, attempt.Function, attempt.Source, attempt.Target, attempt.Register, at.Format(time.RFC3339)))
	draft.addFact(allowedFact)
	draft.addFact(windowFact)
	draft.addEvidence("event", string(ev.EventID), fmt.Sprintf("Write-Attempt %s/%s → %s", attempt.Protocol, attempt.Function, attempt.Target),
		ev.Source, fmt.Sprintf("allowed=%t source=%s register=%s", attempt.Allowed, attempt.Source, attempt.Register), at, 0.9)
	draft.addEvidence("window", string(window.WindowID), windowFact, "detect:window", windowValue, at, 0.85)
	draft.addEvidence("policy", string(policy.PolicyID), "Bewertung gegen Betreiber-Policy und Wartungsfenster", "detect:policy",
		fmt.Sprintf("policy_version=%d require_window=%t", policy.Version, policy.Maintenance.RequireWindow), at, 0.8)
	return []domain.Alert{draft.build()}
}
