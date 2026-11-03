package rules

import "github.com/visiongaiatechnology/gedefense/retail/internal/domain"

// thermalSpecs covers cold-chain integrity. Hard product rule: there are no
// universal temperature limits. Temperature alerts depend exclusively on
// operator-configured limits; if a limit is missing, nothing is alerted.
var thermalSpecs = []Spec{
	{
		ID:               IDThermalLimit,
		Version:          Version,
		Name:             "Temperatur außerhalb des Betreiber-Grenzwerts",
		Category:         domain.CategoryThermal,
		Description:      "Meldet eine Temperaturmessung, die den von der Betreiber-Policy für Zone und Messgröße konfigurierten Min-/Max-Grenzwert überschreitet. Ohne konfigurierten Grenzwert wird nicht alarmiert.",
		Baseline:         "Normal ist ein Messwert innerhalb [min_c, max_c] des passenden TemperatureLimit (Zone + Messgröße, gültig ab valid_from). Fehlt ein Limit oder sind beide Grenzen leer, findet keine thermische Alarmierung statt. Messwerte mit Qualität bad/missing/frozen/stale/clock_uncertain erzeugen keinen Prozessalarm; sie werden von den Datenqualitätsregeln bewertet. Defrost-, Tür- und Belademodi degradieren die Severity (kein Critical).",
		Confidence:       "0,80 Basis bei Qualität good/uncertain; 0,60 bei abweichender Qualität; -0,10 wenn der Betreiber-Grenzwert älter als die Messung ist; Deckel 0,90. Die Confidence bewertet die Messung, nicht die Ursache.",
		DedupKeyTemplate: "retail.thermal.limit|<site>|<zone>|<metric>|<sensor>|<side>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityLow, "Überschreitung bis 0,5 °C im Normalbetrieb."),
			level(domain.SeverityMedium, "Überschreitung bis 2 °C oder während Defrost/Türöffnung/Warenbeladung."),
			level(domain.SeverityHigh, "Überschreitung über 2 °C im Normalbetrieb."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Ist-Temperatur mit unabhängiger Messung durch zuständiges Personal prüfen", false, "Nur lesende Prüfung; keine Anlagenänderung."),
			action("Türzustand, Warenbeladung, Abtauzyklus und Anlagenstörung prüfen", false, "Nur prüfen."),
			action("Betreiber-Kühlketten-/Incident-Prozess auslösen", false, "Prozess des Betreibers, nicht von GeDefense erfunden."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine Sollwertänderung, keine Anlagenabschaltung, kein Rückkühlen durch GeDefense.",
			"Keine Aussage, ob Ware sicher oder unsicher ist.",
		),
		FalsePositiveBoundaries: []string{
			"Falsch oder zu eng konfigurierte Betreiber-Grenzwerte.",
			"Abtauzyklus, Türöffnung oder Warenbeladung als legitime Ursache (Severity wird degradiert, nicht der Fakt verschwiegen).",
			"Sensorfehler/Drift wird durch retail.thermal.sensor-divergence und retail.dq.* bewertet.",
			"Fehlender Grenzwert => bewusst keine Alarmierung.",
		},
		EventKinds: []domain.EventKind{domain.EventTelemetry},
	},
	{
		ID:               IDThermalRate,
		Version:          Version,
		Name:             "Temperaturänderungsrate über dem Betreiber-Grenzwert",
		Category:         domain.CategoryThermal,
		Description:      "Meldet einen zu schnellen Temperaturanstieg oder -abfall über ein gleitendes Fenster, wenn die Betreiber-Policy für Zone und Messgröße eine maximale Änderungsrate (max_rate_c_per_min) festlegt.",
		Baseline:         "Normal ist eine Änderungsrate bis max_rate_c_per_min über mindestens zwei Minuten Messfenster. Fehlt max_rate_c_per_min, wird nicht alarmiert. Defrost-/Tür-/Belademodus unterdrückt die Regel, weil dort ein schneller Temperaturanstieg betrieblich erwartbar ist.",
		Confidence:       "0,65 Basis; 0,75 wenn die gemessene Rate mindestens das Dreifache des Grenzwerts beträgt; Cap 0,85.",
		DedupKeyTemplate: "retail.thermal.rate|<site>|<sensor>|<metric>|<direction>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityMedium, "Rate über Grenzwert bis zum Doppelten."),
			level(domain.SeverityHigh, "Rate über dem Doppelten des Grenzwerts."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Temperaturverlauf und Sensorqualität prüfen", false, "Nur lesende Prüfung."),
			action("Türzustand, Warenbeladung und Abtauplan abgleichen", false, "Nur prüfen."),
			action("Bei zeitlichem Zusammenhang mit Wartungszugriff Incident-Prozess prüfen", false, "Keine automatische Anlagenänderung."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine automatische Rückkühlung, keine Sollwertänderung.",
		),
		FalsePositiveBoundaries: []string{
			"Abtauzyklus (Regel wird unterdrückt, solange der Modus bekannt ist).",
			"Türöffnung oder Warenbeladung (Regel wird unterdrückt).",
			"Kompressor-/Ventilschaltvorgänge innerhalb des Betreiber-Limits.",
			"Fehlender Grenzwert => bewusst keine Alarmierung.",
		},
		EventKinds: []domain.EventKind{domain.EventTelemetry},
	},
	{
		ID:               IDThermalSetpoint,
		Version:          Version,
		Name:             "Sollwert- oder Betriebsmodusabweichung",
		Category:         domain.CategoryThermal,
		Description:      "Meldet eine beobachtete Sollwertänderung außerhalb eines freigegebenen Wartungsfensters, eine Messwert-Abweichung vom gemeldeten Sollwert über die Betreiber-Toleranz oder einen unerwarteten Wechsel in einen verdächtigen Betriebsmodus (z. B. Aus/Heizen).",
		Baseline:         "Erwartbar sind Sollwerte innerhalb der Betreiber-Toleranz (setpoint_tolerance_c) und Sollwert-/Modusänderungen innerhalb eines freigegebenen Wartungsfensters. Abtau- und Kühlmoduswechsel gelten als normal; Regel-/Moduswechsel in Aus/Heizen/Hand außerhalb eines Fensters sind auffällig. Ohne konfigurierte Toleranz bzw. bekannten vorherigen Sollwert wird nicht alarmiert.",
		Confidence:       "0,70 bei belegter Sollwertänderung; 0,55 bei Moduswechsel (Modi können betrieblich zyklisch sein); +0,05 bei kritischem Zielasset; Deckel 0,80.",
		DedupKeyTemplate: "retail.thermal.setpoint-deviation|<site>|<sensor>|<kind>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityMedium, "Messwert weicht vom Sollwert über Toleranz ab oder verdächtiger Moduswechsel im Fenster."),
			level(domain.SeverityHigh, "Sollwert-/Modusänderung außerhalb eines freigegebenen Wartungsfensters oder Abweichung über das Doppelte der Toleranz."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Sollwert und Betriebsmodus am Controller read-only verifizieren", false, "Nur lesende Prüfung über freigegebene Wege."),
			action("Freigabe/Ticket für die Änderung prüfen", false, "Nur verifizieren."),
			action("Ist-Zustand durch Anlagenverantwortlichen bewerten lassen", false, "Keine Rückänderung durch GeDefense."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Kein Zurückschreiben von Sollwerten oder Betriebsmodi.",
		),
		FalsePositiveBoundaries: []string{
			"Freigegebene Wartung ohne aktiv gepflegtes Fenster.",
			"Automatische Abtau-/Verbundregelung (Modus 'defrost' wird nicht alarmiert).",
			"Toleranz zu eng konfiguriert.",
			"Kein vorheriger Sollwert bekannt => bewusst keine Alarmierung.",
		},
		EventKinds: []domain.EventKind{domain.EventTelemetry},
	},
	{
		ID:               IDThermalSensorDivergence,
		Version:          Version,
		Name:             "Abweichung zwischen unabhängigen Sensoren",
		Category:         domain.CategoryDataQuality,
		Description:      "Meldet, dass zwei Sensoren derselben Zone und Messgröße über das Betreiber-Limit hinaus unterschiedliche Temperaturen liefern. Das Signal bewertet die Vertrauenswürdigkeit der Messkette, nicht den Prozesszustand.",
		Baseline:         "Normal ist eine Differenz bis divergence_c zwischen zwei Sensoren derselben Zone/Messgröße innerhalb von divergence_window_s. Ohne konfiguriertes divergence_c wird nicht alarmiert (keine universellen Grenzwerte). Bevorzugt werden unabhängige Sensoren.",
		Confidence:       "0,55 Basis; +0,15 wenn beide Sensoren als unabhängig markiert sind; +0,10 wenn der Vergleichssensor kritisch ist; Deckel 0,80.",
		DedupKeyTemplate: "retail.thermal.sensor-divergence|<site>|<zone>|<sensor_a>|<sensor_b>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityMedium, "Differenz über divergence_c."),
			level(domain.SeverityHigh, "Differenz über dem Doppelten von divergence_c."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Beide Sensoren mit geeichtem Referenzthermometer prüfen", false, "Nur Prüfung, keine Anlagenänderung."),
			action("Messposition, Sensorzuordnung und Kalibrierdatum abgleichen", false, "Nur lesende Prüfung."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine Aussage über die Warensicherheit allein aus diesem Signal.",
			"Keine automatische Anlagenänderung.",
		),
		FalsePositiveBoundaries: []string{
			"Unterschiedliche Messpositionen (Luft vs. Produkt, Verdampfer vs. Raum).",
			"Lokale Abtauphase eines Verdampfers.",
			"Kalibrierfehler/Drift eines Sensors.",
			"Fehlendes divergence_c => bewusst keine Alarmierung.",
		},
		EventKinds: []domain.EventKind{domain.EventTelemetry},
	},
}
