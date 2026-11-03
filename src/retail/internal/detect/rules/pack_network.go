package rules

import "github.com/visiongaiatechnology/gedefense/retail/internal/domain"

// networkSpecs covers passive communication-baseline rules and the observed
// (never executed) OT write attempt.
var networkSpecs = []Spec{
	{
		ID:               IDUnknownPeer,
		Version:          Version,
		Name:             "Unbekannter Kommunikationspartner",
		Category:         domain.CategoryNetwork,
		Description:      "Meldet ein Kommunikationspaar (Quelle, Ziel, Protokoll), das nicht in der passiv gelernten bzw. von der Betreiber-Policy freigegebenen Baseline der Filiale steht. Der Alarm belegt nur die Existenz der Verbindung, nicht deren Absicht.",
		Baseline:         "Ein Paar gilt als bekannt, wenn es in der Peer-Baseline der Site registriert ist oder innerhalb des Baseline-Fensters (Policy: learned_baseline_window_s, Fallback 24 h) bereits beobachtet wurde. Alarmiert wird nur, wenn die Betreiber-Policy network.baseline_required=true setzt; sonst wird die Beobachtung ausschließlich gelernt (observe-first). Während der Onboarding-Grace (unknown_peer_grace_s nach der ersten Flow-Beobachtung der Site) wird nicht alarmiert.",
		Confidence:       "0,55 Basis; +0,15 wenn Protokoll/Zielport ein OT-Protokoll ist (Modbus 502, BACnet/IP 47808, MQTT 1883, SNMP 161, OPC UA 4840); +0,10 wenn das Zielasset als high/critical konfiguriert ist; Deckel 0,80. Eine einzelne Flow-Beobachtung rechtfertigt keinen höheren Wert.",
		DedupKeyTemplate: "retail.net.unknown-peer|<site>|<src_ip>|<dst_ip>|<protocol>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityMedium, "Unbekanntes Paar, Ziel nicht als kritisch konfiguriert und kein OT-Protokoll/-Port."),
			level(domain.SeverityHigh, "Unbekanntes Paar mit OT-Protokoll/-Port oder Zielasset mit Kritikalität high/critical."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Quellgerät und Verbindungszweck durch Betreiber bzw. Dienstleister verifizieren", false, "Nur Beobachtung; keine Sperre der OT-Kommunikation."),
			action("Gerät inventarisieren oder in die freigegebene Kommunikations-Baseline aufnehmen", false, "Baseline-Änderung nur nach Betreiberfreigabe."),
			action("Dedizierten Fernwartungs-/Managementzugang nach Freigabeprozess sperren oder widerrufen", true, "Nur den Management-/Fernwartungspfad sperren, niemals die OT-Prozesskommunikation."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine aktive Sperrung oder Isolation von OT-Prozesskommunikation.",
			"Keine aktiven Gegenproben (Scan/Ping/Banner-Grab) gegen das unbekannte Gerät.",
		),
		FalsePositiveBoundaries: []string{
			"Neu installierte, noch nicht inventarisierte Geräte (Onboarding).",
			"Temporäre Dienstleistergeräte ohne Inventarisierung.",
			"NAT/Proxy/SPAN-Spiegelung verändert beobachtete IP-Adressen.",
			"Retransmissions oder doppelte Flow-Events des Collectors.",
		},
		EventKinds: []domain.EventKind{domain.EventFlow},
	},
	{
		ID:               IDWriteAttempt,
		Version:          Version,
		Name:             "Beobachteter Schreibzugriff auf ein OT-Gerät",
		Category:         domain.CategoryNetwork,
		Description:      "Meldet einen passiv beobachteten Schreibzugriff auf eine Anlage (z. B. Modbus FC5/6/15/16/22/23, BACnet writeProperty, SNMP SET, MQTT-Kommando-Publish), wenn die Operation nicht erlaubt ist oder außerhalb eines freigegebenen Wartungsfensters stattfindet. GeDefense führt niemals selbst einen Schreibzugriff aus.",
		Baseline:         "Ein beobachteter Schreibzugriff ist dann erwartbar, wenn die Betreiber-Policy die Operation erlaubt (write_attempt.allowed=true) und zum Zeitpunkt des Zugriffs ein freigegebenes Wartungsfenster das Zielasset abdeckt (inkl. Grace Period). Erlaubte Schreibzugriffe innerhalb eines Fensters werden nicht alarmiert, aber als Event gespeichert.",
		Confidence:       "0,70 Basis (die Beobachtung selbst ist ein Fakt); +0,10 wenn die Operation laut Policy/Allowlist nicht erlaubt ist; Deckel 0,85. Die Confidence beschreibt die Sicherheit der Beobachtung, nicht die Absicht.",
		DedupKeyTemplate: "retail.write-attempt|<site>|<source>|<target>|<function>|<register>",
		SeverityMatrix: []SeverityLevel{
			level(domain.SeverityHigh, "Schreibzugriff außerhalb eines freigegebenen Wartungsfensters oder als nicht erlaubt markiert (Allowed=false)."),
		},
		RecommendedActions: []domain.RecommendedAction{
			action("Freigabe, Ticket und Dienstleisterkontakt zum beobachteten Schreibzugriff verifizieren", false, "Nur verifizieren/dokumentieren."),
			action("Ist-Zustand der betroffenen Anlage durch den Anlagenverantwortlichen prüfen lassen", false, "Keine Rückänderung durch GeDefense."),
			action("Dedizierten Fernwartungszugang nach Freigabeprozess sperren oder widerrufen", true, "Nur Management-/Fernwartungspfad; keine Unterbrechung der OT-Prozesskommunikation."),
		},
		SafetyConstraints: combine(commonSafety(),
			"Keine automatische Rückänderung von Sollwerten, Registern oder Betriebsmodi.",
			"Keine Anlagenabschaltung aufgrund eines beobachteten Schreibzugriffs.",
		),
		FalsePositiveBoundaries: []string{
			"Freigegebene Wartung, deren Fenster nicht gepflegt wurde (Fensterpflege-Fehler).",
			"Automatisierte Verbund-/Regelungsroutinen, die regelmäßig schreiben.",
			"Inbetriebnahme-/Testgeräte im Wartungsfenster.",
			"Verschlüsselte oder proprietäre Protokolle bleiben ohne passive Lesbarkeit unsichtbar.",
		},
		EventKinds: []domain.EventKind{domain.EventWriteAttempt},
	},
}
