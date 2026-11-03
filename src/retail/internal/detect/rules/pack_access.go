package rules

import "github.com/visiongaiatechnology/gedefense/retail/internal/domain"

// accessSpecs covers external maintenance access and management interfaces.
// The documented retail attack path (CERT-FR, 10/2026: compromise via the web
// management UIs of refrigeration supervisors) is represented by
// retail.access.management-ui; it is an observation, never proof of an attack.
var accessSpecs = []Spec{
	{
		ID:               IDAccessOffWindow,
		Version:          Version,
		Name:             "Wartungszugriff außerhalb eines freigegebenen Wartungsfensters",
		Category:         domain.CategoryAccess,
		Description:      "Meldet eine beobachtete externe Zugriffssitzung auf Filialtechnik, für die zum Zeitpunkt des Zugriffs kein freigegebenes Wartungsfenster das Zielasset abdeckt. Die Sitzung kann legitim (Notfallwartung, Fensterpflegefehler) oder unautorisiert sein.",
		Baseline:         "Ein Zugriff ist erwartbar, wenn ein Wartungsfenster (Status planned/active) das Zielasset abdeckt und der Zugriffszeitpunkt im Fenster liegt, zuzüglich der Policy-Grace-Period nach Fensterende. Bei maintenance.require_window=true ist ein Zugriff ohne Fenster mindestens High.",
		Confidence:       "0,75 Basis (das Fehlen eines Fensters ist ein belegter Fakt); 0,60 wenn die Betreiber-Policy kein Fenster verlangt; +0,05 wenn das Zielasset als kritisch konfiguriert ist; Deckel 0,80.",
		DedupKeyTemplate: "retail.access.off-window|<site>|<vendor>|<target_asset>|<method>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityMedium, "Zugriff ohne Fenster, Policy verlangt kein Fenster (require_window=false), Zielasset nicht kritisch."),
			level(domain.SeverityHigh, "Zugriff ohne Fenster bei require_window=true oder Zielasset mit Kritikalität high/critical."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Ticket-/Freigabereferenz und Dienstleisterkontakt zum Zugriff verifizieren", false, "Nur verifizieren; keine automatische Unterbrechung."),
			action("Sitzungsprotokoll und Zielsystem durch den Betreiber prüfen lassen", false, "Nur lesende Prüfung."),
			action("Dedizierten Fernwartungszugang nach Freigabeprozess sperren oder widerrufen", true, "Nur Management-/Fernwartungspfad; keine Unterbrechung der OT-Prozesskommunikation."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine automatische Sitzungsunterbrechung oder Netz-Isolation.",
			"Keine Zugangsdaten testen, erraten oder zurücksetzen.",
		),
		FalsePositiveBoundaries: []string{
			"Kurzfristige Notfallwartung ohne dokumentiertes Fenster.",
			"Zeitversatz zwischen Gateway und Freigabeplan bzw. falsche Zeitzone im Wartungsplan.",
			"Fenster in der Registry noch nicht aktiv, obwohl freigegeben.",
			"Verschlüsselte Fernwartung ist inhaltlich nicht einsehbar, nur die Sitzungsmetadaten.",
		},
		EventKinds: []domain.EventKind{domain.EventAccess},
	},
	{
		ID:               IDAccessUntrustedVendor,
		Version:          Version,
		Name:             "Zugriff eines nicht vertrauten Dienstleisters",
		Category:         domain.CategoryAccess,
		Description:      "Meldet einen beobachteten Wartungszugriff, dessen Dienstleister weder in der Betreiber-Policy als vertrauenswürdig geführt noch durch ein aktives Wartungsfenster freigegeben ist, oder dessen Dienstleisterangabe vom freigegebenen Fenster abweicht.",
		Baseline:         "Ein Dienstleister gilt als vertraut, wenn er in maintenance.trusted_vendors steht oder ein aktives, das Zielasset abdeckendes Wartungsfenster denselben Dienstleister nennt. Ist keine Vertrauensliste konfiguriert und existiert kein Fenster, übernimmt die Regel retail.access.off-window die Bewertung (keine Doppelmeldung).",
		Confidence:       "0,60 Basis; +0,10 wenn der Dienstleister von einem aktiven Fenster abweicht; +0,05 wenn das Zielasset kritisch ist; Deckel 0,80.",
		DedupKeyTemplate: "retail.access.untrusted-vendor|<site>|<vendor>|<target_asset>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityMedium, "Dienstleister nicht in der Vertrauensliste, Zielasset nicht kritisch."),
			level(domain.SeverityHigh, "Dienstleister weicht vom aktiven Wartungsfenster ab oder Zielasset ist high/critical."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Dienstleisteridentität und Freigabe durch Betreiber verifizieren", false, "Nur verifizieren."),
			action("Dienstleister nach Freigabeprozess in maintenance.trusted_vendors aufnehmen oder Zugang entziehen", true, "Vertrauensliste ist Betreiber-eigene Policy; Änderung auditiert."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine automatische Sperre des Dienstleisters.",
			"Keine Bewertung der Dienstleisterqualität außerhalb der Betreiber-Policy.",
		),
		FalsePositiveBoundaries: []string{
			"Neuer, noch nicht in der Policy erfasster Dienstleister (Onboarding-Lücke).",
			"Schreibweise/Rechtsform des Dienstleiternamens weicht vom Fenster ab.",
			"Subunternehmer eines freigegebenen Dienstleisters.",
		},
		EventKinds: []domain.EventKind{domain.EventAccess},
	},
	{
		ID:               IDAccessManagementUI,
		Version:          Version,
		Name:             "Zugriff auf Management-/Web-Oberfläche eines Kälte-Supervisors",
		Category:         domain.CategoryAccess,
		Description:      "Meldet einen beobachteten HTTP-/HTTPS-Zugriff auf die Management-Oberfläche eines Kälte-Supervisors (z. B. Danfoss AK-SM/AK-SC StoreView, Copeland/Dixell XWEB) durch ein Quellgerät, das nicht zur Baseline gehört, und/oder außerhalb eines freigegebenen Wartungsfensters. Web-Management-Oberflächen von Kälte-Supervisoren waren im Oktober 2026 Einstiegspunkt eines dokumentierten Angriffs auf mehrere hundert französische Supermärkte (CERT-FR); die einzelne Beobachtung beweist keinen Angriff.",
		Baseline:         "Ein UI-Zugriff ist erwartbar, wenn das Quellgerät in der Baseline bekannt ist, ein freigegebenes Wartungsfenster das Zielasset abdeckt und der Zugriff in dessen Zeitraum fällt. Bewertet werden nur Ziele, die als OT-Asset mit Management-Oberfläche bekannt sind (Asset.ManagementInterface oder Supervisor-/BMS-/HMI-Typ), damit allgemeiner HTTPS-Verkehr nicht alarmiert.",
		Confidence:       "0,50 Basis; +0,15 außerhalb eines Wartungsfensters; +0,10 wenn die Quelle in der Baseline unbekannt ist; +0,05 bei Asset-Kritikalität high/critical; Deckel 0,80.",
		DedupKeyTemplate: "retail.access.management-ui|<site>|<src_device>|<target_asset>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityLow, "Bekanntes Quellgerät im freigegebenen Wartungsfenster."),
			level(domain.SeverityMedium, "Unbekanntes Quellgerät im freigegebenen Wartungsfenster oder off-window bei nicht kritischem Ziel."),
			level(domain.SeverityHigh, "Off-window bei Asset-Kritikalität high/critical oder unbekannte Quelle außerhalb des Fensters."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Quellgerät, Betreiber/Dienstleister und Sitzungszweck verifizieren", false, "Nur verifizieren; keine aktive Gegenprobe."),
			action("Zugriffsprotokoll des Supervisors durch den Betreiber prüfen lassen", false, "Nur lesende Prüfung."),
			action("Management-Oberfläche nach Freigabe auf dedizierten Management-Pfad beschränken (Segmentierung)", true, "Keine automatische Isolation der OT-Prozesskommunikation; Betreiberfreigabe erforderlich."),
			action("Dedizierten Fernwartungszugang nach Freigabeprozess sperren oder widerrufen", true, "Nur Management-/Fernwartungspfad."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine automatische Sperre der Management-Oberfläche.",
			"Keine Zugangsdaten testen oder Login-Versuche gegen die UI senden.",
		),
		FalsePositiveBoundaries: []string{
			"Betreiber-Monitoring oder Asset-Management-System greift regulär auf die UI zu.",
			"Automatisierte Firmware-/Konfigurationsprüfung durch Herstellerwerkzeug.",
			"Segmentierung unvollständig: legitim erreichbare UI aus Retail-IT.",
			"NAT/Proxy verfälscht die beobachtete Quelladresse.",
			"Ziel ohne auflösbares Asset (dann wird nicht bewertet).",
		},
		EventKinds: []domain.EventKind{domain.EventFlow},
	},
}
