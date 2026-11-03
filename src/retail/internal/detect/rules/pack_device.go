package rules

import "github.com/visiongaiatechnology/gedefense/retail/internal/domain"

// deviceSpecs covers newly observed assets and the lifecycle/exposure advisory.
// Both are risk factors, not attack evidence.
var deviceSpecs = []Spec{
	{
		ID:               IDDeviceNewAsset,
		Version:          Version,
		Name:             "Neues Asset im Filialnetz",
		Category:         domain.CategoryDeviceHealth,
		Description:      "Meldet ein Asset, das erstmalig in der Filiale beobachtet wird (keine frühere asset_seen-Beobachtung im Inventarfenster). Neue Geräte können Inbetriebnahme, fehlende Inventarisierung oder unautorisierte Teilnehmer sein.",
		Baseline:         "Normal ist ein Asset, das mindestens einmal innerhalb der letzten 30 Tage beobachtet wurde. Ein Asset ohne frühere Beobachtung gilt als neu; die Regel behauptet keine Identität, die passive Daten nicht hergeben.",
		Confidence:       "0,60 Basis; +0,10 wenn das Asset ein OT-Typ/-Protokoll spricht; +0,10 bei Kritikalität high/critical; Deckel 0,80.",
		DedupKeyTemplate: "retail.device.new-asset|<site>|<asset>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityMedium, "Neues Asset ohne OT-Bezug/ohne kritische Klassifizierung."),
			level(domain.SeverityHigh, "Neues Asset mit OT-Protokoll/-Typ oder als high/critical klassifiziert."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Asset in das Inventar aufnehmen und klassifizieren", false, "Nur Inventarisierung."),
			action("Betreiber/Dienstleister zur Herkunft des Geräts befragen", false, "Nur verifizieren."),
			action("Netzwerksegmentierung und offene Ports prüfen", false, "Nur lesende Prüfung."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine aktive Identifikation (Scan, Banner-Grab, Login-Versuch) des neuen Geräts.",
		),
		FalsePositiveBoundaries: []string{
			"Neuinstallation/Inbetriebnahme.",
			"Bestandsgerät, das erst jetzt passiv sichtbar wird.",
			"Dienstleistergerät während einer Wartung.",
			"NAT/Routing-Artefakt verändert die beobachtete Identität.",
		},
		EventKinds: []domain.EventKind{domain.EventAssetSeen},
	},
	{
		ID:               IDAssetLifecycleExposed,
		Version:          Version,
		Name:             "Kritischer Kälte-Regler am Lebenszyklusende oder Management-UI exponiert",
		Category:         domain.CategoryDeviceHealth,
		Description:      "Advisory-Regel: meldet einen kritischen Kälte-Regler/BMS, der laut Asset-Datensatz am Lebenszyklusende (eol) steht, oder dessen Management-Oberfläche aus einer Zone außerhalb der Management-Zone erreichbar ist. Beides erhöht die Angriffsfläche, ist aber kein Angriffsnachweis.",
		Baseline:         "Erwartbar sind Assets mit Lifecycle active/approaching_eol bzw. 'unknown' (nicht bewertet) und Management-Oberflächen, die ausschließlich aus der Management-Zone oder dem freigegebenen externen Wartungspfad erreichbar sind. Die Regel läuft im periodischen Tick und bewertet keine unveränderten Stände erneut mit steigender Severity.",
		Confidence:       "0,90 für den Lebenszyklusstatus (Katalog-/Betreiberfakt, Quelle im Asset vermerkt); 0,60 für die beobachtete Erreichbarkeit aus einer anderen Zone; Deckel 0,90.",
		DedupKeyTemplate: "retail.asset.lifecycle-exposed|<site>|<asset>|<kind>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityLow, "Kritischer Kälte-Regler/BMS am Lebenszyklusende (eol)."),
			level(domain.SeverityMedium, "Management-Oberfläche aus einer Zone außerhalb der Management-Zone erreichbar."),
			level(domain.SeverityMedium, "Beide Faktoren gleichzeitig (zwei getrennte Advisory-Meldungen mit eigener DedupKey)."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Ersatz-/Update-Plan und Herstellerfreigabe mit Betreiber prüfen", false, "Keine automatische Firmware-Aktualisierung."),
			action("Management-Zugang nach Freigabe auf dedizierten Management-Pfad beschränken", true, "Netzwerk-/Segmentierungsänderung nur durch Betreiber; keine OT-Prozesskommunikation unterbrechen."),
			action("Kompensierende Maßnahmen dokumentieren (Segmentierung, Monitoring)", false, "Nur dokumentieren."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine automatische Firmware-Aktualisierung von OT-Geräten.",
			"Keine automatische Abschaltung oder Net-Isolation.",
			"Keine erfundene CVE-/Advisory-Behauptung ohne Quellenbeleg.",
		),
		FalsePositiveBoundaries: []string{
			"Veralteter Katalogstand (Lifecycle eol nicht mehr aktuell).",
			"Geplante Ersatzbeschaffung bereits in Umsetzung.",
			"Segmentierungs-Sonderfall (z. B. Betreiber-Monitoring in der Management-Zone).",
			"Management-Oberfläche ohne passende Flow-Metadaten nicht bewertbar => keine Meldung.",
		},
		Tick: true,
	},
}
