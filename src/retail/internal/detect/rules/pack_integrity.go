package rules

import "github.com/visiongaiatechnology/gedefense/retail/internal/domain"

// integritySpecs covers observed configuration/firmware changes. GeDefense
// documents the change; it never reverts a plant configuration.
var integritySpecs = []Spec{
	{
		ID:               IDIntegrityChange,
		Version:          Version,
		Name:             "Unerwartete Integritäts-/Konfigurationsänderung",
		Category:         domain.CategoryIntegrity,
		Description:      "Meldet eine beobachtete Änderung an Konfiguration oder Firmware eines Assets, die nicht freigegeben ist oder außerhalb eines freigegebenen Wartungsfensters stattgefunden hat. Die Änderung wird dokumentiert; ein automatisches Zurückschreiben findet niemals statt.",
		Baseline:         "Erwartbar ist eine Änderung nur mit Freigabenachweis (integrity.approved=true) und innerhalb eines freigegebenen Wartungsfensters. Unveränderte Stände sowie freigegebene Änderungen im Fenster werden nicht alarmiert. Änderungen ohne Freigabemetadaten werden als Beobachtung mit niedriger Severity gemeldet.",
		Confidence:       "0,80 bei Freigabeflag + Hash/Version; 0,45 ohne Freigabemetadaten; -0,10 wenn keine Referenz-Baseline vorhanden ist; Deckel 0,85.",
		DedupKeyTemplate: "retail.integrity.change|<site>|<asset>|<subject>|<sha256>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityLow, "Konfigurationsänderung ohne Freigabemetadaten (nicht bewertbar)."),
			level(domain.SeverityMedium, "Freigegebene Änderung außerhalb eines Wartungsfensters oder unerwartete Änderung an nicht kritischem Asset."),
			level(domain.SeverityHigh, "Nicht freigegebene Änderung an Asset mit Kritikalität high/critical."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Vorher-/Nachher-Vergleich mit freigegebenem read-only Export durchführen", false, "Nur lesend; kein Zurückschreiben."),
			action("Freigabe/Ticket und Herstellerprozess prüfen", false, "Nur verifizieren."),
			action("Anlagenverantwortlichen bei unautorisierter Änderung einschalten", false, "Prozess des Betreibers."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Kein automatisches Zurückschreiben von PLC-Programmen, Parametern oder Firmware.",
			"Wiederherstellung der Anlagenkonfiguration bleibt beim Hersteller-/Betreiberprozess.",
		),
		FalsePositiveBoundaries: []string{
			"Freigegebene Wartung ohne aktiv gepflegtes Fenster.",
			"Hersteller-/Servicewerkzeug mit eigener Änderungslogik.",
			"Änderung über lokales HMI ohne Netzbezug bleibt unsichtbar.",
			"Veraltete oder fehlende Referenz-Baseline.",
		},
		EventKinds: []domain.EventKind{domain.EventIntegrity, domain.EventConfigChange},
	},
}
