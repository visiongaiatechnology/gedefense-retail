package detect

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// offWindowAccessRule implements retail.access.off-window: an observed external
// maintenance session without a covering, approved maintenance window.
type offWindowAccessRule struct{ baseRule }

func newOffWindowAccessRule() *offWindowAccessRule {
	return &offWindowAccessRule{baseRule: baseFor(rules.IDAccessOffWindow)}
}

func (r *offWindowAccessRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if ev.Kind != domain.EventAccess || ev.Access == nil {
		return nil
	}
	access := ev.Access
	policy := w.Policy()
	at := trustedTime(ev)
	grace := time.Duration(policy.Maintenance.GracePeriodS) * time.Second
	target := access.TargetAsset
	if target == "" {
		target = ev.AssetID
	}

	window, inWindow := coveringWindow(w, ev.SiteID, at, target, grace)
	if inWindow && (access.WindowID == "" || access.WindowID == window.WindowID) {
		return nil // approved window covers this access
	}
	mismatch := inWindow && access.WindowID != "" && access.WindowID != window.WindowID

	severity := domain.SeverityMedium
	confidence := 0.60
	if policy.Maintenance.RequireWindow {
		severity = domain.SeverityHigh
		confidence = 0.75
	}
	asset, assetKnown := w.Asset(target)
	if assetKnown && assetCritical(asset) {
		severity = domain.SeverityHigh
		confidence += 0.05
	}
	if mismatch {
		severity = domain.SeverityHigh
	}

	windowFact := fmt.Sprintf("Kein freigegebenes Wartungsfenster deckt das Zielasset zum Zeitpunkt des Zugriffs (inkl. Grace Period von %s).", humanDuration(grace))
	windowValue := "in_window=false"
	if mismatch {
		windowFact = fmt.Sprintf("Die Sitzung nennt Wartungsfenster %q, aktiv ist jedoch %q (Dienstleister %q).", access.WindowID, window.WindowID, window.Vendor)
		windowValue = fmt.Sprintf("in_window=true claimed=%s active=%s", access.WindowID, window.WindowID)
	}

	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   clampConfidence(confidence, 0.5, 0.8),
		dedupKey:     rules.DedupKey(rules.IDAccessOffWindow, string(ev.SiteID), access.Vendor, string(target), access.Method),
		title:        "Wartungszugriff außerhalb eines freigegebenen Wartungsfensters",
		hypothesis:   "Der Zugriff kann durch eine nicht dokumentierte oder kurzfristige Wartung erfolgt sein; ohne Freigabenachweis ist die Autorisierung unklar. Die Beobachtung beweist keine unbefugte Handlung.",
		alternatives: []string{"Kurzfristige Notfallwartung ohne dokumentiertes Fenster", "Zeitversatz oder Zeitzonenfehler im Wartungsplan", "Wartungsfenster in der Registry noch nicht aktiv", "Verschlüsselte Fernwartung erlaubt inhaltlich keine Einsicht, nur Sitzungsmetadaten"},
		checks:       []string{"Ticket-/Freigabereferenz und Dienstleisterkontakt verifizieren", "Sitzungsprotokoll und Zielsystem durch den Betreiber prüfen lassen", "Wartungsfensterpflege korrigieren, falls die Wartung freigegeben war"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	if target != "" {
		draft.assetIDs = []domain.AssetID{target}
	}
	if access.SessionID != "" {
		draft.addFact(fmt.Sprintf("Beobachtete Sitzung %q von %s über %s auf %s um %s.", access.SessionID, accessUserLabel(access), communicationMethod(access), assetLabel(target), at.Format(time.RFC3339)))
	} else {
		draft.addFact(fmt.Sprintf("Beobachteter Zugriff von %s über %s auf %s um %s.", accessUserLabel(access), communicationMethod(access), assetLabel(target), at.Format(time.RFC3339)))
	}
	draft.addFact(windowFact)
	draft.addFact(fmt.Sprintf("Betreiber-Policy: require_window=%t.", policy.Maintenance.RequireWindow))
	draft.addEvidence("event", string(ev.EventID), "Beobachteter Wartungszugriff", ev.Source,
		fmt.Sprintf("vendor=%s method=%s target=%s claimed_window=%s", access.Vendor, access.Method, target, access.WindowID), at, 0.8)
	draft.addEvidence("window", string(window.WindowID), windowFact, "detect:window", windowValue, at, 0.85)
	draft.addEvidence("policy", string(policy.PolicyID), "Bewertung der Fensterpflicht", "detect:policy",
		fmt.Sprintf("policy_version=%d require_window=%t grace_s=%d", policy.Version, policy.Maintenance.RequireWindow, policy.Maintenance.GracePeriodS), at, 0.8)
	if assetKnown {
		draft.addEvidence("asset", string(asset.AssetID), fmt.Sprintf("Zielasset %s (%s)", asset.Name, asset.Type), asset.Source,
			string(asset.Criticality), at, clampConfidence(asset.Confidence, 0, 1))
	}
	return []domain.Alert{draft.build()}
}

// untrustedVendorRule implements retail.access.untrusted-vendor: a vendor that
// is neither in the operator trust list nor named by the active window.
type untrustedVendorRule struct{ baseRule }

func newUntrustedVendorRule() *untrustedVendorRule {
	return &untrustedVendorRule{baseRule: baseFor(rules.IDAccessUntrustedVendor)}
}

func (r *untrustedVendorRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if ev.Kind != domain.EventAccess || ev.Access == nil {
		return nil
	}
	access := ev.Access
	vendor := strings.TrimSpace(access.Vendor)
	if vendor == "" {
		return nil // no vendor claim: nothing to verify against the trust baseline
	}
	policy := w.Policy()
	at := trustedTime(ev)
	grace := time.Duration(policy.Maintenance.GracePeriodS) * time.Second
	target := access.TargetAsset
	if target == "" {
		target = ev.AssetID
	}
	window, inWindow := coveringWindow(w, ev.SiteID, at, target, grace)
	trusted := vendorInList(policy.Maintenance.TrustedVendors, vendor)
	sameVendorWindow := inWindow && strings.EqualFold(strings.TrimSpace(window.Vendor), vendor)
	if trusted && !inWindow {
		return nil // trusted vendor; the off-window rule evaluates the missing window
	}
	if sameVendorWindow {
		return nil
	}
	mismatch := inWindow && !sameVendorWindow
	configured := len(policy.Maintenance.TrustedVendors) > 0
	if !mismatch && !configured {
		return nil // no trust baseline configured: the off-window rule owns the case
	}

	severity := domain.SeverityMedium
	confidence := 0.60
	if mismatch {
		severity = domain.SeverityHigh
		confidence += 0.10
	}
	asset, assetKnown := w.Asset(target)
	if assetKnown && assetCritical(asset) {
		severity = domain.SeverityHigh
		confidence += 0.05
	}
	facts := []string{fmt.Sprintf("Dienstleister %q ist nicht in der Betreiber-Vertrauensliste (maintenance.trusted_vendors) geführt.", vendor)}
	if mismatch {
		facts = append(facts, fmt.Sprintf("Das aktive Wartungsfenster %q ist für Dienstleister %q freigegeben, nicht für %q.", window.WindowID, window.Vendor, vendor))
	}

	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   clampConfidence(confidence, 0.5, 0.8),
		dedupKey:     rules.DedupKey(rules.IDAccessUntrustedVendor, string(ev.SiteID), vendor, string(target)),
		title:        "Zugriff eines nicht als vertraut geführten Dienstleisters",
		hypothesis:   "Der Dienstleister kann ein neuer, noch nicht onboardeter Partner sein oder die Sitzung kann von einem anderen Akteur unter fremdem Namen erfolgen. Die Beobachtung allein beweist keine unautorisierte Handlung.",
		alternatives: []string{"Neuer Dienstleister noch nicht in der Policy erfasst", "Subunternehmer eines freigegebenen Dienstleisters", "Schreibweise/Rechtsform weicht vom Fenster-Eintrag ab", "Fenster für einen anderen Dienstleister geöffnet"},
		checks:       []string{"Dienstleisteridentität und Freigabe durch Betreiber verifizieren", "Vertrauensliste (maintenance.trusted_vendors) nach Freigabeprozess pflegen", "Zielsystem und Sitzungszweck prüfen"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	if target != "" {
		draft.assetIDs = []domain.AssetID{target}
	}
	for _, fact := range facts {
		draft.addFact(fact)
	}
	draft.addEvidence("event", string(ev.EventID), "Beobachteter Dienstleisterzugriff", ev.Source,
		fmt.Sprintf("vendor=%s method=%s target=%s", vendor, access.Method, target), at, 0.8)
	draft.addEvidence("policy", string(policy.PolicyID), "Vertrauensliste der Betreiber-Policy", "detect:policy",
		fmt.Sprintf("trusted_vendors=%s", strings.Join(policy.Maintenance.TrustedVendors, ",")), at, 0.8)
	if inWindow {
		draft.addEvidence("window", string(window.WindowID), fmt.Sprintf("Aktives Fenster für Dienstleister %q", window.Vendor),
			"detect:window", fmt.Sprintf("window_vendor=%s", window.Vendor), at, 0.85)
	}
	return []domain.Alert{draft.build()}
}

// managementUIAccessRule implements retail.access.management-ui: an observed
// HTTP(S) access to the management interface of a refrigeration supervisor. This
// is the documented retail attack path (CERT-FR, 10/2026), but the observation
// stays a risk signal, not an attack proof.
type managementUIAccessRule struct{ baseRule }

func newManagementUIAccessRule() *managementUIAccessRule {
	return &managementUIAccessRule{baseRule: baseFor(rules.IDAccessManagementUI)}
}

func (r *managementUIAccessRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
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
	if src == "" || dst == "" || !managementUIFlow(protocol, flow.DstPort) {
		return nil
	}
	target, ok := managementUITarget(w, ev, dst)
	if !ok {
		return nil // unknown or non-supervisor target: no management-UI claim
	}
	policy := w.Policy()
	at := trustedTime(ev)
	grace := time.Duration(policy.Maintenance.GracePeriodS) * time.Second
	window, inWindow := coveringWindow(w, ev.SiteID, at, target.AssetID, grace)
	lookback := baselineLookback(policy)
	since, _ := lookbackSince(w, lookback)
	knownSource := priorFlow(w, ev, since, src, dst, protocol)

	severity := domain.SeverityLow
	switch {
	case !inWindow && (assetCritical(target) || !knownSource):
		severity = domain.SeverityHigh
	case !inWindow || !knownSource:
		severity = domain.SeverityMedium
	}
	confidence := 0.50
	if !inWindow {
		confidence += 0.15
	}
	if !knownSource {
		confidence += 0.10
	}
	if assetCritical(target) {
		confidence += 0.05
	}

	sourceFact := fmt.Sprintf("Quellgerät %s ist in der Baseline bekannt.", src)
	if !knownSource {
		sourceFact = fmt.Sprintf("Quellgerät %s ist in der Baseline unbekannt (keine frühere Beobachtung innerhalb von %s).", src, humanDuration(lookback))
	}
	windowFact := "Kein freigegebenes Wartungsfenster deckt die Management-Oberfläche zum Zugriffszeitpunkt ab."
	if inWindow {
		windowFact = fmt.Sprintf("Freigegebenes Wartungsfenster %s (Dienstleister %s) war aktiv.", window.WindowID, window.Vendor)
	}

	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   clampConfidence(confidence, 0.5, 0.8),
		dedupKey:     rules.DedupKey(rules.IDAccessManagementUI, string(ev.SiteID), src, string(target.AssetID)),
		title:        "Zugriff auf Management-Oberfläche eines Kälte-Supervisors",
		hypothesis:   "Ein UI-Zugriff auf einen Kälte-Supervisor kann legitime Dienstleister-/Betreiberwartung oder ein unautorisierter Zugriffsversuch sein. Web-Management-Oberflächen von Kälte-Supervisoren waren im Oktober 2026 Einstiegspunkt eines dokumentierten Angriffs auf mehrere hundert französische Supermärkte (CERT-FR); dieser Zugriff allein beweist keinen Angriff.",
		alternatives: []string{"Freigegebene Fernwartung außerhalb der Fensterpflege", "Automatisierte Firmware-/Konfigurationsprüfung durch Herstellerwerkzeug", "Betreiber-Monitoring oder Asset-Management-System", "NAT/Proxy verfälscht die beobachtete Quelladresse"},
		checks:       []string{"Quellgerät und Sitzungszweck über Betreiber bzw. Dienstleister verifizieren", "Zugriffsprotokoll des Supervisors durch den Betreiber prüfen lassen", "Management-Oberfläche nach Freigabe auf den dedizierten Management-Pfad beschränken (Segmentierung)"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	draft.assetIDs = []domain.AssetID{target.AssetID}
	draft.addFact(fmt.Sprintf("HTTP(S)-Zugriff von %s auf die Management-Oberfläche von %s (Port %d, Protokoll %s) um %s.", src, target.AssetID, flow.DstPort, protocol, at.Format(time.RFC3339)))
	draft.addFact(sourceFact)
	draft.addFact(windowFact)
	draft.addEvidence("event", string(ev.EventID), fmt.Sprintf("Flow %s → %s (%s, Port %d)", src, dst, protocol, flow.DstPort), ev.Source,
		fmt.Sprintf("dst_port=%d bytes=%d packets=%d", flow.DstPort, flow.Bytes, flow.Packets), at, 0.8)
	draft.addEvidence("asset", string(target.AssetID), fmt.Sprintf("Zielasset %s (%s), Management-Oberfläche", target.Name, target.Type), target.Source,
		fmt.Sprintf("management_interface=%t criticality=%s", target.ManagementInterface, target.Criticality), at, clampConfidence(target.Confidence, 0, 1))
	draft.addEvidence("baseline", "", sourceFact, "detect:baseline", fmt.Sprintf("known_source=%t", knownSource), at, 0.8)
	draft.addEvidence("window", string(window.WindowID), windowFact, "detect:window", fmt.Sprintf("in_window=%t", inWindow), at, 0.85)
	return []domain.Alert{draft.build()}
}

// managementUIFlow reports whether the flow looks like a web-management access.
func managementUIFlow(protocol string, port int) bool {
	p := strings.ToLower(strings.TrimSpace(protocol))
	if strings.HasPrefix(p, "http") {
		return true
	}
	if !isManagementUIPort(port) {
		return false
	}
	switch p {
	case "tcp", "tls", "ssl", "tcp_tls", "https", "http":
		return true
	default:
		return false
	}
}

// managementUITarget resolves the destination asset and verifies that it is a
// supervisor whose management interface matters.
func managementUITarget(w World, ev domain.Event, dstIP string) (domain.Asset, bool) {
	if asset, ok := assetByIP(w, ev.SiteID, dstIP); ok {
		if assetIsManagementUI(asset) {
			return asset, true
		}
		return domain.Asset{}, false
	}
	if ev.AssetID != "" {
		if asset, ok := w.Asset(ev.AssetID); ok && assetIsManagementUI(asset) {
			return asset, true
		}
	}
	return domain.Asset{}, false
}

func assetIsManagementUI(asset domain.Asset) bool {
	if asset.Retired {
		return false
	}
	if asset.ManagementInterface {
		return true
	}
	return assetIsOTController(asset)
}

func vendorInList(list []string, vendor string) bool {
	vendor = strings.TrimSpace(vendor)
	for _, entry := range list {
		if strings.EqualFold(strings.TrimSpace(entry), vendor) {
			return true
		}
	}
	return false
}

func accessUserLabel(access *domain.AccessMeta) string {
	switch {
	case strings.TrimSpace(access.Vendor) != "" && strings.TrimSpace(access.User) != "":
		return fmt.Sprintf("Dienstleister %q / Benutzer %q", access.Vendor, access.User)
	case strings.TrimSpace(access.Vendor) != "":
		return fmt.Sprintf("Dienstleister %q", access.Vendor)
	case strings.TrimSpace(access.User) != "":
		return fmt.Sprintf("Benutzer %q", access.User)
	default:
		return "unbekannter Quelle"
	}
}

func communicationMethod(access *domain.AccessMeta) string {
	if strings.TrimSpace(access.Method) == "" {
		return "unbekanntem Zugriffsweg"
	}
	return fmt.Sprintf("Zugriffsweg %q", access.Method)
}

func assetLabel(id domain.AssetID) string {
	if id == "" {
		return "ein unbekanntes Zielasset"
	}
	return fmt.Sprintf("Zielasset %s", id)
}
