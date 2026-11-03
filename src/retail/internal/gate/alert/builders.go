package alert

import (
	"fmt"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// NewDeniedWriteAlert builds the alert for one refused write attempt.
func NewDeniedWriteAlert(d domain.DeniedWriteAttempt, site domain.SiteID) Alert {
	severity, rationale := SeverityForDenyReason(strings.TrimSpace(d.Reason))
	if d.Severity.Valid() && d.Severity.Rank() > severity.Rank() {
		severity = d.Severity // the gate core may escalate, never downgrade
	}
	at := d.At.UTC()
	facts := []string{
		fmt.Sprintf("Schreibversuch %s/%s auf Ziel %s (Adresse %s) von Quelle %s um %s wurde abgelehnt (Grund: %s).",
			d.Protocol, d.Function, d.TargetID, valueOr(d.Address, "unbekannt"), valueOr(d.SourceIP, "unbekannt"), at.Format(time.RFC3339), valueOr(d.Reason, "unbekannt")),
	}
	if d.UserID != "" {
		facts = append(facts, fmt.Sprintf("Zugeordneter Gate-Nutzer: %s.", d.UserID))
	}
	if d.SessionID != "" {
		facts = append(facts, fmt.Sprintf("Betroffene Session %s (Plan %s).", d.SessionID, valueOr(string(d.PlanID), "unbekannt")))
	} else {
		facts = append(facts, "Es war keine Gate-Session zugeordnet.")
	}
	if d.ViaBypass {
		facts = append(facts, "Der Versuch wurde passiv außerhalb des Gate-Datenpfads beobachtet (via_bypass=true).")
	}

	evidence := []Evidence{{
		Kind:        "deny",
		RefID:       string(d.DenyID),
		Description: fmt.Sprintf("Abgelehnter Schreibversuch %s/%s", d.Protocol, d.Function),
		At:          at,
		Source:      "retailgate",
		Value:       fmt.Sprintf("reason=%s value_hint=%s", d.Reason, d.ValueHint),
		Confidence:  0.9,
	}}
	if d.SessionID != "" {
		evidence = append(evidence, Evidence{
			Kind: "session", RefID: string(d.SessionID),
			Description: "Session, gegen die der Schreibversuch geprüft wurde",
			At:          at, Source: "retailgate", Confidence: 0.85,
		})
	}
	if d.PlanID != "" {
		evidence = append(evidence, Evidence{
			Kind: "plan", RefID: string(d.PlanID),
			Description: "Plan, dessen Freigabe nicht ausreichte",
			At:          at, Source: "retailgate", Confidence: 0.85,
		})
	}

	confidence := 0.85
	if severity != domain.SeverityCritical {
		confidence = 0.75
	}
	alert := Alert{
		Kind:          domain.GateEventWriteDenied,
		RuleID:        RuleDeniedWrite,
		Severity:      severity,
		Confidence:    confidence,
		Title:         "Schreibversuch ohne gültige Freigabe abgelehnt",
		DedupKey:      DenyDedupKey(d),
		SiteID:        site,
		TargetID:      d.TargetID,
		SourceIP:      d.SourceIP,
		DenyID:        d.DenyID,
		SessionID:     d.SessionID,
		PlanID:        d.PlanID,
		UserID:        d.UserID,
		Reason:        d.Reason,
		Protocol:      d.Protocol,
		Function:      d.Function,
		Address:       d.Address,
		ValueHint:     d.ValueHint,
		Evidence:      evidence,
		ObservedFacts: facts,
		Hypothesis: "Die Ablehnung belegt, dass der Schreibversuch nicht durch einen gültigen, freigegebenen Plan gedeckt war (" + rationale +
			"). Ob es sich um Fehlbedienung, einen Test oder einen Angriffsversuch handelt, ist nicht bewiesen.",
		AlternativeExplanations: []string{
			"Fehlbedienung oder veraltete Client-Konfiguration",
			"Freigabe abgelaufen, bereits verbraucht oder falsch adressiert",
			"Test-/Inbetriebnahmegerät ohne Freigabe",
			"Kompromittiertes Werkzeug oder gestohlene Sitzung (nicht bewiesen)",
		},
		RecommendedChecks: []string{
			"Freigabe, Ticket und Plan-Status prüfen",
			"Quell-IP, Gerät und Gate-Nutzer identifizieren",
			"Deny- und Audit-Verlauf für den Zeitraum prüfen",
			"Bei ungeklärter Autorisierung Gate-Session widerrufen (Freigabe erforderlich)",
		},
		RecommendedActions: []domain.RecommendedAction{
			{Action: "Freigabe/Ticket und Sitzung durch Betreiber verifizieren", RequiresApproval: false},
			{Action: "Gate-Session widerrufen", RequiresApproval: true, SafetyNote: "Nur Gate-Session, nicht die OT-Prozesskommunikation."},
			{Action: "Anlagenverantwortlichen informieren", RequiresApproval: false},
		},
		SafetyConstraints: gateSafetyConstraints(),
	}
	alert.Summary = composeSummary(facts, alert.Hypothesis, alert.RecommendedChecks)
	return alert
}

// BypassDetails describes a passive write attempt outside the gate data path.
type BypassDetails struct {
	SiteID         domain.SiteID
	At             time.Time
	TargetID       domain.TargetID
	AssetID        domain.AssetID
	SourceIP       string
	Protocol       string
	Function       string
	Address        string
	ValueHint      string
	ObservedTarget string
	GateSources    []string
	Allowed        bool
	Confidence     float64
	Detail         string
}

// NewBypassAlert builds the "Bypass vermutet" alert (critical). The alert states
// the documented limit: passive observation cannot prove who wrote or whether it
// was authorized.
func NewBypassAlert(d BypassDetails) Alert {
	at := d.At.UTC()
	if at.IsZero() {
		at = time.Unix(0, 0).UTC()
	}
	confidence := d.Confidence
	if confidence <= 0 || confidence > 1 {
		confidence = 0.7
	}
	sourceLabel := valueOr(d.SourceIP, "unbekannt")
	targetLabel := valueOr(string(d.TargetID), valueOr(d.ObservedTarget, "unbekannt"))
	facts := []string{
		fmt.Sprintf("Passiv beobachteter Schreibversuch %s/%s auf %s (Adresse %s) von Quelle %s um %s.",
			valueOr(d.Protocol, "unbekannt"), valueOr(d.Function, "unbekannt"), targetLabel, valueOr(d.Address, "unbekannt"), sourceLabel, at.Format(time.RFC3339)),
	}
	if len(d.GateSources) > 0 {
		facts = append(facts, fmt.Sprintf("Quelle %s liegt außerhalb der konfigurierten Gate-Quellen (%s); der Schreibweg verlief damit nicht über den Gate-Datenpfad.",
			sourceLabel, strings.Join(d.GateSources, ", ")))
	} else {
		facts = append(facts, fmt.Sprintf("Quelle %s konnte keinem Gate-Pfad zugeordnet werden.", sourceLabel))
	}
	if d.Allowed {
		facts = append(facts, "Der passive Adapter markierte die Operation als erlaubt; ohne Gate-Audit ist diese Erlaubnis nicht überprüfbar.")
	}
	if strings.TrimSpace(d.Detail) != "" {
		facts = append(facts, "Detail: "+strings.TrimSpace(d.Detail))
	}
	alert := Alert{
		Kind:       domain.GateEventBypass,
		RuleID:     RuleBypass,
		Severity:   domain.SeverityCritical,
		Confidence: confidence,
		Title:      "Bypass vermutet: Schreibzugriff am Gate vorbei",
		DedupKey:   BypassDedupKey(targetLabel, sourceLabel, d.Function, d.Address),
		SiteID:     d.SiteID,
		TargetID:   d.TargetID,
		AssetID:    d.AssetID,
		SourceIP:   d.SourceIP,
		Protocol:   d.Protocol,
		Function:   d.Function,
		Address:    d.Address,
		ValueHint:  d.ValueHint,
		Reason:     "bypass_suspected",
		Evidence: []Evidence{{
			Kind:        "bypass",
			Description: "Passiv beobachteter Schreibversuch außerhalb des Gate-Pfads",
			At:          at,
			Source:      "retaild.passive",
			Value:       fmt.Sprintf("target=%s source=%s", targetLabel, sourceLabel),
			Confidence:  confidence,
		}},
		ObservedFacts: facts,
		Hypothesis:    "Ein Schreibzugriff außerhalb des Gate-Pfads kann eine umgangene Netzsegmentierung, ein nicht inventarisiertes Gate/Proxy oder einen direkten Gerätezugriff darstellen. Die passive Beobachtung beweist weder Urheber noch Autorisierung.",
		AlternativeExplanations: []string{
			"Segmentierungsfehler oder alter Wartungszugang am OT-Switch",
			"Nicht inventarisierte Gate-Instanz oder Proxy",
			"Direkter lokaler Zugang (HMI, Service-Laptop, RS-485)",
			"Passives Collector-Artefakt (NAT/SPAN-Spiegelung)",
		},
		RecommendedChecks: []string{
			"Netzwerkpfad und Segmentierung prüfen (Switch/VLAN/Firewall)",
			"Gate-Quell-CIDRs und Target-Registry abgleichen",
			"Betreiber/Dienstleister zur Herkunft befragen",
			"Gate-Audit für den Zeitraum prüfen (fehlender Eintrag ist ein starkes Indiz)",
		},
		RecommendedActions: []domain.RecommendedAction{
			{Action: "Netzwerkpfad und Segmentierung durch Betreiber verifizieren", RequiresApproval: false},
			{Action: "Bypass-Pfad nach Freigabe schließen (Segmentierung/Firewall)", RequiresApproval: true, SafetyNote: "Keine automatische Isolation der OT-Prozesskommunikation."},
			{Action: "Anlagenverantwortlichen und Betreiber informieren", RequiresApproval: false},
		},
		SafetyConstraints: gateSafetyConstraints(),
	}
	alert.Summary = composeSummary(facts, alert.Hypothesis, alert.RecommendedChecks)
	return alert
}

// severityForFailsafeReason maps a fail-safe reason to the alert severity.
func severityForFailsafeReason(reason string) domain.Severity {
	switch reason {
	case domain.DenyFailsafeStore, domain.DenyPolicyMissing:
		return domain.SeverityCritical
	default:
		return domain.SeverityHigh
	}
}

// NewFailsafeAlert builds the alert for an active fail-safe condition.
func NewFailsafeAlert(site domain.SiteID, at time.Time, reason, detail string) Alert {
	if at.IsZero() {
		at = time.Unix(0, 0).UTC()
	}
	at = at.UTC()
	severity := severityForFailsafeReason(reason)
	facts := []string{
		fmt.Sprintf("Der Gate-Datenpfad ist im Fail-safe-Zustand (Grund: %s).", valueOr(reason, "unbekannt")),
	}
	if detail != "" {
		facts = append(facts, "Detail: "+detail)
	}
	facts = append(facts, "Schreibzugriffe werden abgelehnt, bis die Voraussetzung wieder stabil ist.")
	alert := Alert{
		Kind:       domain.GateEventFailsafe,
		RuleID:     RuleFailsafe,
		Severity:   severity,
		Confidence: 0.95,
		Title:      "Fail-safe aktiv: Gate sperrt Schreibzugriffe",
		DedupKey:   dedupKey("gate.failsafe", reason),
		SiteID:     site,
		Reason:     reason,
		Evidence: []Evidence{{
			Kind:        "failsafe",
			RefID:       reason,
			Description: "Fail-safe-Bedingung aktiv",
			At:          at,
			Source:      "retailgate",
			Value:       detail,
			Confidence:  0.95,
		}},
		ObservedFacts: facts,
		Hypothesis:    "Der Gate-Datenpfad ist bewusst fail-closed gesperrt, weil eine Sicherheitsvoraussetzung fehlt oder unsicher ist. Eine Kompromittierung ist dadurch nicht bewiesen; die Kälteanlage läuft autonom weiter.",
		AlternativeExplanations: []string{
			"Speicher-/Audit-Problem oder volle Disk",
			"Zeitabweichung/NTP-Sprung",
			"Policy-/Konfigurationsfehler",
			"Betriebliche Wartung oder Neustart",
		},
		RecommendedChecks: []string{
			"Speicherzustand und Audit-Kette prüfen",
			"Zeitquelle/NTP prüfen und Stabilität abwarten",
			"Policy laden/validieren (master_admin + MFA)",
			"Betreiber über Management-Sperre informieren",
		},
		RecommendedActions: []domain.RecommendedAction{
			{Action: "Fail-safe-Ursache durch Betreiber/Admin prüfen", RequiresApproval: false},
			{Action: "Policy neu laden bzw. Fail-safe quittieren", RequiresApproval: true, SafetyNote: "Nur durch master_admin mit MFA; kein Bypass des Fail-safe."},
		},
		SafetyConstraints: gateSafetyConstraints(),
	}
	alert.Summary = composeSummary(facts, alert.Hypothesis, alert.RecommendedChecks)
	return alert
}

// NewApprovalAlert builds the alert for rejected or expired write plans.
// Self-approval attempts are high severity; other rejections/expiries are medium.
func NewApprovalAlert(site domain.SiteID, at time.Time, kind domain.GateEventKind, planID domain.PlanID, reason, actor string) Alert {
	if at.IsZero() {
		at = time.Unix(0, 0).UTC()
	}
	at = at.UTC()
	severity := domain.SeverityMedium
	if reason == ReasonSelfApproval {
		severity = domain.SeverityHigh
	}
	state := "abgelehnt"
	if kind == domain.GateEventPlanExpired {
		state = "abgelaufen"
	}
	facts := []string{
		fmt.Sprintf("Write-Plan %s wurde %s (Grund: %s).", valueOr(string(planID), "unbekannt"), state, valueOr(reason, "unbekannt")),
	}
	if actor != "" {
		facts = append(facts, fmt.Sprintf("Akteur: %s.", actor))
	}
	alert := Alert{
		Kind:       kind,
		RuleID:     RuleApproval,
		Severity:   severity,
		Confidence: 0.8,
		Title:      "Write-Plan " + state,
		DedupKey:   dedupKey("gate.plan", string(planID), string(kind), reason),
		SiteID:     site,
		PlanID:     planID,
		Reason:     reason,
		Evidence: []Evidence{{
			Kind:        "plan",
			RefID:       string(planID),
			Description: "Write-Plan " + state,
			At:          at,
			Source:      "retailgate",
			Value:       fmt.Sprintf("reason=%s actor=%s", reason, actor),
			Confidence:  0.85,
		}},
		ObservedFacts: facts,
		Hypothesis:    "Ablehnung oder Ablauf eines Write-Plans ist ein normaler, aber sicherheitsrelevanter Vorgang. Ein Angriffsversuch ist damit nicht bewiesen.",
		AlternativeExplanations: []string{
			"Unvollständiger oder fehlerhafter Antrag",
			"Fenster/Ticket nicht passend",
			"Vier-Augen-Anforderung nicht erfüllt",
			"Self-Approval-Versuch des Antragstellers (bei Grund self_approval)",
		},
		RecommendedChecks: []string{
			"Antragsteller, Ticket und Planinhalt prüfen",
			"Bei self_approval: Rollen- und Vier-Augen-Prozess prüfen",
			"Policy-/Fenster-Anforderungen prüfen und Betreiber informieren",
		},
		RecommendedActions: []domain.RecommendedAction{
			{Action: "Antragsteller und Freigabeprozess prüfen", RequiresApproval: false},
			{Action: "Bei wiederholtem Missbrauch Nutzer sperren", RequiresApproval: true, SafetyNote: "Nur Gate-Identität, kein Anlageneingriff."},
		},
		SafetyConstraints: gateSafetyConstraints(),
	}
	alert.Summary = composeSummary(facts, alert.Hypothesis, alert.RecommendedChecks)
	return alert
}

// UnknownWrite describes a write whose device outcome could not be determined
// (timeout, disconnect, read error, partial/unparseable response). It is neither
// allowed nor denied and therefore must never be reported as one of them.
type UnknownWrite struct {
	At        time.Time         `json:"at"`
	SessionID domain.SessionID  `json:"session_id,omitempty"`
	PlanID    domain.PlanID     `json:"plan_id,omitempty"`
	UserID    domain.GateUserID `json:"user_id,omitempty"`
	SourceIP  string            `json:"source_ip"`
	TargetID  domain.TargetID   `json:"target_id"`
	AssetID   domain.AssetID    `json:"asset_id,omitempty"`
	Protocol  string            `json:"protocol"`
	Function  string            `json:"function"`
	Address   string            `json:"address,omitempty"`
	ValueHint string            `json:"value_hint,omitempty"`
	// Outcome is the technical observation, e.g. "timeout", "disconnect",
	// "read_error", "partial_response".
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// NewWriteUnknownAlert builds the critical "gate.write.unknown" alert. It
// explicitly forbids an automatic retry and requires a read-back of the current
// device value through an approved read path.
func NewWriteUnknownAlert(u UnknownWrite, site domain.SiteID) Alert {
	at := u.At.UTC()
	if at.IsZero() {
		at = time.Unix(0, 0).UTC()
	}
	outcome := valueOr(u.Outcome, "unknown")
	facts := []string{
		fmt.Sprintf("Schreibversuch %s/%s auf Ziel %s (Adresse %s) von Quelle %s um %s wurde gesendet, die Geräteantwort ist jedoch unklar (Outcome: %s).",
			valueOr(u.Protocol, "unbekannt"), valueOr(u.Function, "unbekannt"), valueOr(string(u.TargetID), "unbekannt"),
			valueOr(u.Address, "unbekannt"), valueOr(u.SourceIP, "unbekannt"), at.Format(time.RFC3339), outcome),
		"Der Vorgang ist weder als erlaubt noch als verweigert bestätigt; der Ist-Zustand des Geräts ist unbekannt.",
	}
	if u.Detail != "" {
		facts = append(facts, "Detail: "+u.Detail)
	}
	if u.SessionID != "" {
		facts = append(facts, fmt.Sprintf("Betroffene Session %s (Plan %s).", u.SessionID, valueOr(string(u.PlanID), "unbekannt")))
	}
	if u.UserID != "" {
		facts = append(facts, fmt.Sprintf("Zugeordneter Gate-Nutzer: %s.", u.UserID))
	}
	alert := Alert{
		Kind:       KindWriteUnknown,
		RuleID:     RuleWriteUnknown,
		Severity:   domain.SeverityCritical,
		Confidence: 0.85,
		Title:      "Schreibversuch mit unbekanntem Ergebnis (Write-Unknown)",
		DedupKey:   dedupKey("gate.write.unknown", string(u.TargetID), u.SourceIP, u.Function, u.Address),
		SiteID:     site,
		TargetID:   u.TargetID,
		AssetID:    u.AssetID,
		SourceIP:   u.SourceIP,
		SessionID:  u.SessionID,
		PlanID:     u.PlanID,
		UserID:     u.UserID,
		Reason:     "write_unknown",
		Protocol:   u.Protocol,
		Function:   u.Function,
		Address:    u.Address,
		ValueHint:  u.ValueHint,
		Evidence: []Evidence{{
			Kind:        "write_unknown",
			RefID:       string(u.SessionID),
			Description: "Schreibversuch ohne eindeutige Geräteantwort",
			At:          at,
			Source:      "retailgate",
			Value:       fmt.Sprintf("outcome=%s detail=%s", outcome, u.Detail),
			Confidence:  0.85,
		}},
		ObservedFacts: facts,
		Hypothesis:    "Eine unklare Geräteantwort kann durch einen Timeout, einen Verbindungsabbruch, einen Geräte-Neustart oder einen tatsächlich ausgeführten Schreibvorgang mit verlorener Antwort entstehen. Ob der Wert geschrieben wurde, ist nicht bewiesen.",
		AlternativeExplanations: []string{
			"Netzwerk-Timeout oder Verbindungsabbruch zum Gerät",
			"Geräte-Neustart/Überlast während der Antwort",
			"Antwort wurde gesendet, ging aber verloren",
			"Teilweise ausgeführter Schreibvorgang",
		},
		RecommendedChecks: []string{
			"Ist-Wert über einen freigegebenen Lesepfad (Read-back) prüfen",
			"KEIN automatischer Retry vor dem Read-back (Gefahr eines doppelten Schreibvorgangs)",
			"Session-/Plan-Status prüfen und Session bei Unklarheit widerrufen",
			"Betreiber und Anlagenverantwortlichen informieren",
		},
		RecommendedActions: []domain.RecommendedAction{
			{Action: "Read-back des Ist-Werts über freigegebenen Lesepfad veranlassen", RequiresApproval: false},
			{Action: "Kein automatischer Retry; erneute Freigabe und manuelle Prüfung erforderlich", RequiresApproval: true, SafetyNote: "Verhindert doppelte Schreibvorgänge auf dem Gerät."},
			{Action: "Gate-Session widerrufen", RequiresApproval: true, SafetyNote: "Nur Gate-Session, nicht die OT-Prozesskommunikation."},
		},
		SafetyConstraints: gateSafetyConstraints(),
	}
	alert.Summary = composeSummary(facts, alert.Hypothesis, alert.RecommendedChecks)
	return alert
}
