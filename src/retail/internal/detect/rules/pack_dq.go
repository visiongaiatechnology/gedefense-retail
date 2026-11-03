package rules

import "github.com/visiongaiatechnology/gedefense/retail/internal/domain"

// dataQualitySpecs separates "is the measurement trustworthy" from a process
// alarm. A frozen or missing value is never treated as "everything is fine".
var dataQualitySpecs = []Spec{
	{
		ID:               IDDataQualityFrozen,
		Version:          Version,
		Name:             "Konstantwert / eingefrorener Messwert",
		Category:         domain.CategoryDataQuality,
		Description:      "Meldet eine Messreihe, die über das Betreiber-Fenster (frozen_value_window_s) exakt denselben Wert liefert. Das kann ein defekter Sensor, eine hängende Schnittstelle oder eine manipulierte/replayte Telemetrie sein und darf nicht als stabile Kühlung missverstanden werden.",
		Baseline:         "Normal ist eine messbare Varianz über das Fenster, mindestens aber drei Beobachtungen über mindestens 80 % des Fensters. Bewegen sich Vergleichssensoren derselben Zone, ist ein exakt konstanter Wert besonders auffällig. Ohne frozen_value_window_s wird nicht bewertet.",
		Confidence:       "0,55 Basis; +0,20 wenn sich Vergleichssensoren in derselben Zone bewegen; +0,05 bei kritischem Sensor; Deckel 0,80.",
		DedupKeyTemplate: "retail.dq.frozen-value|<site>|<sensor>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityMedium, "Konstanter Wert über das Fenster, keine belastbare Vergleichsbewegung."),
			level(domain.SeverityHigh, "Konstanter Wert, während Vergleichssensoren derselben Zone sich bewegen."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Sensor und Übertragungsweg durch zuständiges Personal prüfen", false, "Nur lesende Prüfung."),
			action("Unabhängige Temperaturmessung durchführen", false, "Keine Anlagenänderung."),
			action("Messwert bis zur Klärung nicht als 'in Ordnung' darstellen", false, "Datenqualität bleibt sichtbar."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine Aussage 'Ware sicher/unsicher' aus einem Datenqualitätssignal.",
		),
		FalsePositiveBoundaries: []string{
			"Sehr stabile Temperatur in leerem, geschlossenem Kühlraum.",
			"Geringe Sensorauflösung (z. B. 0,5 °C) kann kurzfristig identische Werte liefern; daher Mindestanzahl und Mindestspanne.",
			"Gateway puffert und liefert Werte verzögert (siehe retail.dq.gap / retail.dq.clock-skew).",
		},
		EventKinds: []domain.EventKind{domain.EventTelemetry},
	},
	{
		ID:               IDDataQualityGap,
		Version:          Version,
		Name:             "Datenlücke in der Telemetrie",
		Category:         domain.CategoryDataQuality,
		Description:      "Meldet ausbleibende Telemetrie eines Sensors länger als der Betreiber-Schwellwert (telemetry_gap_s) — sowohl beim Wiederauftreten (exakte Lücke) als auch im periodischen Tick für aktuell schweigende Sensoren. Fehlende Telemetrie wird nie als 'Temperatur in Ordnung' interpretiert.",
		Baseline:         "Erwartet wird mindestens eine Telemetriemeldung je telemetry_gap_s. Sensoren ohne jede bisherige Beobachtung (kein LastSeenAt, keine Samples) werden nicht alarmiert, um einen Startsturm zu vermeiden.",
		Confidence:       "0,75 bei belegter Lücke zwischen zwei Beobachtungen (Fakt); 0,60 im Tick, wenn nur die Sensor-LastSeen-Zeit vorliegt; Deckel 0,85.",
		DedupKeyTemplate: "retail.dq.gap|<site>|<sensor>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityMedium, "Lücke über telemetry_gap_s."),
			level(domain.SeverityHigh, "Lücke über dem Dreifachen des Schwellwerts oder kritischer Sensor."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Sensor-/Gateway-Konnektivität und Collector-Health prüfen", false, "Nur lesende Prüfung."),
			action("Fehlende Telemetrie als 'keine Aussage' dokumentieren, nicht als 'in Ordnung'", false, "Datenqualität bleibt sichtbar."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine automatische Anlagenänderung; Ausfall von GeDefense beeinflusst die Anlage nicht.",
		),
		FalsePositiveBoundaries: []string{
			"Collector-Ausfall oder Wartung des Gateways (Health-Status zeigt die Ursache).",
			"Sensor im Deaktivierungs-/Standby-Modus.",
			"Startphase: Sensoren ohne bisherige Beobachtung werden ausgelassen.",
		},
		EventKinds: []domain.EventKind{domain.EventTelemetry},
		Tick:       true,
	},
	{
		ID:               IDDataQualityClockSkew,
		Version:          Version,
		Name:             "Zeitstempel-Abweichung oder -Rücksprung",
		Category:         domain.CategoryDataQuality,
		Description:      "Meldet eine Abweichung zwischen Geräte-/Beobachtungszeit und Gateway-Empfangszeit über die Betreiber-Toleranz (max_clock_skew_s) sowie rückläufige Zeitstempel eines Sensors. Beides kann Wartungsfenster-, Korrelations- und Aufbewahrungslogik verfälschen.",
		Baseline:         "Normal ist |received_at - observed_at| <= max_clock_skew_s und eine monotone Beobachtungszeit je Sensor (Monotonie-Toleranz 60 s für Rundung/Retransmission). Ohne max_clock_skew_s wird nicht bewertet.",
		Confidence:       "0,70 bei belegter Zeitdifferenz; 0,65 bei Rückläufigkeit; Deckel 0,85.",
		DedupKeyTemplate: "retail.dq.clock-skew|<site>|<sensor>|<source>|<kind>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityMedium, "Abweichung über Toleranz bzw. Rücksprung bis 5 Minuten."),
			level(domain.SeverityHigh, "Abweichung über dem Fünffachen der Toleranz bzw. Rücksprung über 5 Minuten."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("NTP-/Zeitquelle von Gerät und Gateway prüfen", false, "Nur lesende Prüfung."),
			action("Betroffene Ereignisse als zeitunsicher markieren, nicht verwerfen", false, "Evidenz bleibt erhalten."),
			action("Wartungsfenster-Bewertung für den Zeitraum überprüfen", false, "Nur prüfen."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine stille Korrektur von Zeitstempeln.",
		),
		FalsePositiveBoundaries: []string{
			"Geräte ohne NTP-Synchronisation (dauerhafte Drift).",
			"Sommer-/Winterzeit- oder Zeitzonenfehler in der Gerätekonfiguration.",
			"Gateway-Neustart mit kurzem Zeitversatz.",
			"Retransmissionen mit älteren Gerätezeitstempeln.",
		},
		EventKinds: []domain.EventKind{domain.EventTelemetry, domain.EventDeviceHealth, domain.EventClockSkew},
	},
}
