package correlate

import (
	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// chains returns the three contract chains. The order is fixed so evaluation and
// incident output are deterministic.
func chains() []chainDef {
	return []chainDef{thermalManipulationChain(), sensorIntegrityChain(), remoteIntrusionChain()}
}

// sharedSafety is the non-negotiable limit of every correlated incident. The
// correlation may escalate the priority, but it never authorizes an action on the
// plant.
func sharedSafety() []string {
	return []string{
		"GeDefense Retail ist passiv: keine Sollwertänderung, keine Anlagenabschaltung, kein Rückkühlen.",
		"Keine automatische Netz-Isolation; kritische Maßnahmen benötigen eine verantwortliche Person (RequiresApproval).",
		"Kritische Einstufung nur bei mindestens drei unabhängigen Indikatoren; die Korrelation beweist keinen Angriff.",
		"Keine Aussage über Lebensmittelsicherheit oder Compliance allein aus technischen Signalen.",
	}
}

func thermalManipulationChain() chainDef {
	return chainDef{
		id:            ChainThermalManipulation,
		name:          "Thermische Manipulationskette",
		title:         "Korrelierte thermische Manipulationskette",
		window:        chainWindow,
		minIndicators: 3,
		severity:      domain.SeverityCritical,
		category:      domain.CategoryThermal,
		indicators: []indicator{
			{
				key:     "off_window_access",
				label:   "Wartungszugriff außerhalb eines freigegebenen Fensters",
				ruleIDs: []domain.RuleID{rules.IDAccessOffWindow, rules.IDAccessUntrustedVendor},
			},
			{
				key:     "unknown_peer",
				label:   "Unbekannter Kommunikationspartner",
				ruleIDs: []domain.RuleID{rules.IDUnknownPeer},
			},
			{
				key:     "setpoint_deviation",
				label:   "Sollwert-/Betriebsmodusabweichung",
				ruleIDs: []domain.RuleID{rules.IDThermalSetpoint},
			},
			{
				key:     "thermal_trend",
				label:   "Thermischer Trend oder Grenzwertverletzung",
				ruleIDs: []domain.RuleID{rules.IDThermalRate, rules.IDThermalLimit},
			},
			{
				key:     "write_attempt",
				label:   "Beobachteter Schreibzugriff",
				ruleIDs: []domain.RuleID{rules.IDWriteAttempt},
			},
		},
		hypothesis: "Die zeitliche Nähe von externem Zugriff, unbekannter Kommunikation, Sollwert-/Modusänderung und thermischem Trend kann auf eine gezielte thermische Manipulation hindeuten. Ein Angriff ist damit nicht bewiesen: Anlagenstörung, Sensorfehler oder eine nicht dokumentierte Wartung können dieselben Indikatoren erzeugen.",
		alternatives: []string{
			"Nicht dokumentierte, aber freigegebene Wartung",
			"Abtau-, Tür- oder Beladevorgang mit zufälliger zeitlicher Nähe",
			"Sensorfehler oder Kommunikationsstörung",
			"Anlagenstörung (Kompressor, Ventil, Kältemittel)",
			"Zeitversatz verfälscht die Korrelation",
		},
		checks: []string{
			"Alle beteiligten Ereignisse mit Zeitstempeln, Quellen und Qualität prüfen",
			"Wartungsfenster, Ticket und Dienstleister verifizieren",
			"Temperaturverlauf mit unabhängiger Messung prüfen",
			"Ist-Zustand durch den Anlagenverantwortlichen bewerten lassen (keine automatische Rückänderung)",
		},
		safety: sharedSafety(),
	}
}

func sensorIntegrityChain() chainDef {
	return chainDef{
		id:            ChainSensorIntegrity,
		name:          "Sensor-/Datenintegritätskette",
		title:         "Korrelierte Sensor-/Datenintegritätskette",
		window:        chainWindow,
		minIndicators: 3,
		severity:      domain.SeverityHigh,
		category:      domain.CategoryDataQuality,
		indicators: []indicator{
			{
				key:     "frozen_value",
				label:   "Eingefrorener Messwert",
				ruleIDs: []domain.RuleID{rules.IDDataQualityFrozen},
			},
			{
				key:     "sensor_divergence",
				label:   "Abweichung zwischen unabhängigen Sensoren",
				ruleIDs: []domain.RuleID{rules.IDThermalSensorDivergence},
			},
			{
				key:     "telemetry_gap",
				label:   "Datenlücke in der Telemetrie",
				ruleIDs: []domain.RuleID{rules.IDDataQualityGap},
			},
			{
				key:     "clock_skew",
				label:   "Zeitstempel-Abweichung oder -Rücksprung",
				ruleIDs: []domain.RuleID{rules.IDDataQualityClockSkew},
			},
		},
		hypothesis: "Mehrere unabhängige Datenqualitätssignale derselben Messkette können auf eine manipulierte oder gestörte Telemetrie hindeuten (Replay, eingefrorene Werte, Zeitmanipulation, blockierte Übertragung). Ein Angriff ist nicht bewiesen; Sensor-/Gateway-Defekte und Netzwerkstörungen sind mindestens ebenso plausible Erklärungen.",
		alternatives: []string{
			"Sensor-/Gateway-Defekt oder Stromversorgungsproblem",
			"Collector-/Netzwerkstörung",
			"NTP-/Zeitproblem des Geräts",
			"Wartung oder Neustart mit kurzer Telemetrielücke",
			"Messposition/Kalibrierung weicht ab",
		},
		checks: []string{
			"Messkette mit unabhängiger Referenzmessung prüfen",
			"Collector-Health und Zeitquelle von Sensor und Gateway prüfen",
			"Betroffene Messwerte als 'keine Aussage' behandeln, nicht als 'in Ordnung'",
			"Keine Aussage über die Warensicherheit allein aus Datenqualitätssignalen",
		},
		safety: sharedSafety(),
	}
}

func remoteIntrusionChain() chainDef {
	return chainDef{
		id:            ChainRemoteIntrusion,
		name:          "Fernzugriffs-/Intrusionskette",
		title:         "Korrelierte Fernzugriffs-/Intrusionskette",
		window:        chainWindow,
		minIndicators: 3,
		severity:      domain.SeverityHigh,
		category:      domain.CategoryAccess,
		indicators: []indicator{
			{
				key:     "unknown_peer",
				label:   "Unbekannter Kommunikationspartner",
				ruleIDs: []domain.RuleID{rules.IDUnknownPeer},
			},
			{
				key:     "management_ui_access",
				label:   "Zugriff auf Management-Oberfläche eines Kälte-Supervisors",
				ruleIDs: []domain.RuleID{rules.IDAccessManagementUI},
			},
			{
				key:     "off_window_access",
				label:   "Wartungszugriff außerhalb eines freigegebenen Fensters",
				ruleIDs: []domain.RuleID{rules.IDAccessOffWindow, rules.IDAccessUntrustedVendor},
			},
			{
				key:     "new_asset",
				label:   "Neues Asset im Filialnetz",
				ruleIDs: []domain.RuleID{rules.IDDeviceNewAsset},
			},
			{
				key:     "write_attempt",
				label:   "Beobachteter Schreibzugriff",
				ruleIDs: []domain.RuleID{rules.IDWriteAttempt},
			},
			{
				key:     "setpoint_deviation",
				label:   "Sollwert-/Betriebsmodusabweichung",
				ruleIDs: []domain.RuleID{rules.IDThermalSetpoint},
			},
		},
		hypothesis: "Unbekannte Kommunikation, ein Management-UI-Zugriff außerhalb eines freigegebenen Wartungsfensters, ein neu beobachtetes Asset und gegebenenfalls ein beobachteter Schreibzugriff oder eine Sollwertabweichung können zusammen auf einen unautorisierten Fernzugriff hindeuten. Ein Angriff ist nicht bewiesen; Dienstleister-Notfälle, Firmware-Updates und Segmentierungslücken sind plausible Alternativerklärungen.",
		alternatives: []string{
			"Dienstleister-Notfallzugriff ohne aktiv gepflegtes Fenster",
			"Automatisiertes Firmware-/Konfigurationsupdate des Herstellers",
			"Neuinstallation/Inbetriebnahme eines Geräts",
			"Unvollständige Netzwerksegmentierung (Management-UI grundsätzlich erreichbar)",
			"NAT/Proxy verfälscht die beobachtete Quelladresse",
		},
		checks: []string{
			"Quellgerät, Dienstleister und Ticket/Freigabe verifizieren",
			"Zugriffsprotokoll des Supervisors durch den Betreiber prüfen lassen",
			"Netzwerksegmentierung und dedizierten Management-Pfad prüfen",
			"Bei bestätigtem unautorisiertem Zugriff Management-Zugang nach Freigabeprozess sperren oder widerrufen",
		},
		safety: sharedSafety(),
	}
}
