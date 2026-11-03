package detect

import (
	"context"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// integrityChangeRule implements retail.integrity.change: an observed
// configuration/firmware change that is not approved or happened outside an
// approved maintenance window. GeDefense documents the change; it never reverts
// a plant configuration.
type integrityChangeRule struct{ baseRule }

func newIntegrityChangeRule() *integrityChangeRule {
	return &integrityChangeRule{baseRule: baseFor(rules.IDIntegrityChange)}
}

func (r *integrityChangeRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if ev.Kind != domain.EventIntegrity && ev.Kind != domain.EventConfigChange {
		return nil
	}
	policy := w.Policy()
	at := trustedTime(ev)
	grace := time.Duration(policy.Maintenance.GracePeriodS) * time.Second
	window, inWindow := coveringWindow(w, ev.SiteID, at, ev.AssetID, grace)
	asset, assetKnown := domain.Asset{}, false
	if ev.AssetID != "" {
		asset, assetKnown = w.Asset(ev.AssetID)
	}

	integrity := ev.Integrity
	if integrity == nil {
		// config_change with only payload metadata: the change is observed, but
		// there is no approved/change flag to judge it. Advisory only.
		if ev.Kind != domain.EventConfigChange {
			return nil
		}
		draft := &alertDraft{
			spec:         r.spec,
			site:         ev.SiteID,
			severity:     domain.SeverityLow,
			confidence:   0.45,
			dedupKey:     rules.DedupKey(rules.IDIntegrityChange, string(ev.SiteID), string(ev.AssetID), "config-change", "no-integrity-meta"),
			title:        "Konfigurationsänderung ohne Freigabemetadaten beobachtet",
			hypothesis:   "Die Änderung kann eine freigegebene Wartung oder ein unautorisierter Eingriff sein; ohne Integritäts-/Freigabemetadaten ist keine belastbare Bewertung möglich.",
			alternatives: []string{"Freigegebene Wartung ohne Freigabemetadaten", "Hersteller-/Servicewerkzeug", "Lokale Bedienung ohne Netzbezug", "Unvollständiger Collector-Export"},
			checks:       []string{"Freigabe/Ticket und Änderungszeitpunkt prüfen", "Vorher-/Nachher-Vergleich mit freigegebenem Export durchführen", "Integritätserfassung für dieses Asset nachrüsten"},
			at:           at,
		}
		if ev.ZoneID != "" {
			draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
		}
		if ev.AssetID != "" {
			draft.assetIDs = []domain.AssetID{ev.AssetID}
		}
		draft.addFact(fmt.Sprintf("Konfigurationsänderung am Asset %s um %s wurde ohne Integritäts-/Freigabemetadaten beobachtet.", assetLabel(ev.AssetID), at.Format(time.RFC3339)))
		draft.addEvidence("event", string(ev.EventID), "Konfigurationsänderung ohne Freigabemetadaten", ev.Source, "integrity_meta=absent", at, 0.6)
		return []domain.Alert{draft.build()}
	}

	if !integrity.Changed {
		return nil // unchanged state: nothing to report
	}
	if integrity.Approved && inWindow {
		return nil // approved change inside its maintenance window
	}

	severity := domain.SeverityMedium
	if !integrity.Approved && assetKnown && assetCritical(asset) {
		severity = domain.SeverityHigh
	}
	confidence := 0.80
	if integrity.SHA256 == "" && integrity.Version == "" {
		confidence = 0.45
	}
	if integrity.Reference == "" {
		confidence -= 0.10
	}
	approvalFact := "Die Änderung ist nicht freigegeben."
	if integrity.Approved {
		approvalFact = "Die Änderung ist freigegeben, liegt aber außerhalb eines aktiven Wartungsfensters."
	}
	windowFact := "Kein freigegebenes Wartungsfenster deckt das Asset zum Änderungszeitpunkt."
	windowValue := "in_window=false"
	if inWindow {
		windowFact = fmt.Sprintf("Freigegebenes Wartungsfenster %s war aktiv.", window.WindowID)
		windowValue = fmt.Sprintf("in_window=true window_id=%s", window.WindowID)
	}
	subject := integrity.Subject
	if subject == "" {
		subject = "unbekanntes Subjekt"
	}

	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   clampConfidence(confidence, 0.4, 0.85),
		dedupKey:     rules.DedupKey(rules.IDIntegrityChange, string(ev.SiteID), string(ev.AssetID), subject, integrity.SHA256),
		title:        "Unerwartete Integritäts-/Konfigurationsänderung",
		hypothesis:   "Die Änderung kann durch eine freigegebene Wartung, eine Firmware-Aktualisierung oder einen unautorisierten Eingriff erfolgt sein; ohne gültigen Freigabenachweis ist die Autorisierung unklar.",
		alternatives: []string{"Dokumentierte Wartung oder Firmware-Update ohne aktives Fenster", "Hersteller-/Servicewerkzeug mit eigener Änderungslogik", "Änderung über lokales HMI ohne Netzbezug", "Mess-/Lesefehler beim Konfigurationsexport"},
		checks:       []string{"Vorher-/Nachher-Vergleich mit freigegebenem read-only Export durchführen", "Freigabe/Ticket und Herstellerprozess prüfen", "Bei unautorisierter Änderung Anlagenverantwortlichen einschalten"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	if ev.AssetID != "" {
		draft.assetIDs = []domain.AssetID{ev.AssetID}
	}
	draft.addFact(fmt.Sprintf("Integritätsstatus von %q auf %s änderte sich um %s (Version %q, SHA256 %q).",
		subject, assetLabel(ev.AssetID), at.Format(time.RFC3339), integrity.Version, integrity.SHA256))
	draft.addFact(approvalFact)
	draft.addFact(windowFact)
	if integrity.Reference == "" {
		draft.addFact("Es ist keine freigegebene Referenz-Baseline hinterlegt; der Vorher-Stand ist nicht belegt.")
	} else {
		draft.addFact(fmt.Sprintf("Referenz-Baseline: %q.", integrity.Reference))
	}
	draft.addEvidence("event", string(ev.EventID), "Beobachtete Integritätsänderung", ev.Source,
		fmt.Sprintf("subject=%s version=%s changed=%t approved=%t", subject, integrity.Version, integrity.Changed, integrity.Approved), at, 0.85)
	if integrity.SHA256 != "" {
		draft.addEvidence("integrity", integrity.Reference, fmt.Sprintf("Neuer Stand SHA256 %s", integrity.SHA256), ev.Source,
			fmt.Sprintf("sha256=%s", integrity.SHA256), at, 0.8)
	}
	if assetKnown {
		draft.addEvidence("asset", string(asset.AssetID), fmt.Sprintf("Asset %s (%s), Kritikalität %s", asset.Name, asset.Type, asset.Criticality), asset.Source,
			string(asset.Criticality), at, clampConfidence(asset.Confidence, 0, 1))
	}
	draft.addEvidence("window", string(window.WindowID), windowFact, "detect:window", windowValue, at, 0.85)
	return []domain.Alert{draft.build()}
}
