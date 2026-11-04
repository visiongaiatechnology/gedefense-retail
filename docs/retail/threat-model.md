# Threat Model — GeDefense Retail (ColdChain & Store Infrastructure Security)

| Feld | Wert |
|---|---|
| Dokument-ID | DOC-RETAIL-TM-001 |
| Version / Stand | 1.0 / 2026-11-03 |
| Produktlinie | VisionGaiaTechnology — GeDefense Retail |
| Scope | Filial-OT (Kälte, Gebäudeautomation, Sensorik), Edge Gateway, passive Collector/Adapter, lokale Detection, optionales zentrales Management |
| Nicht im Scope | Kassen-/Warenwirtschafts-Apps, Zahlungsverkehr, Betreiber-Cloud, physische Zutrittskontrolle, Kältemittel-/Drucktechnik (EN 378) |
| Methodik | STRIDE je Trust Boundary + Angriffskettenmodell (Voraussetzung → Schritt → Erkennung → Abbruchpunkt); qualitative Bewertung, keine erfundenen Eintrittswahrscheinlichkeiten |
| Referenz-Stil | `GeDefense_LinuxXWordPress/hotfix_2026-10-25/repo/THREAT-MODEL.md` |
| Grundlage | Baukonzept §2 (harte Grenzen), §5 (Module A–H), §6 Schritte 2–3, §7 (MVP), §10 (Abnahme) |

**Bewertungsskala (qualitativ, begründet):** Priorität **P0** = blockiert Pilotfreigabe · **P1** = muss im MVP erkannt werden · **P2** = dokumentiert, Behandlung in 0.2. Eintrittswahrscheinlichkeit wird **nicht** numerisch behauptet, sondern aus Voraussetzungen abgeleitet.

**Grundregel dieses Dokuments:** GeDefense Retail ist passives Monitoring, Detection und Audit. Es verhindert keinen Angriff auf die Anlagensteuerung. Jede „Schutzmaßnahme“ ist deshalb als *Erkennung, Nachvollziehbarkeit, Zugangserschwerung oder Reaktionsbefähigung* formuliert — nicht als Abwehrgarantie.

---

## 0.1 Belegte Angriffslage 2026 (Kontext, keine Produktbehauptung)

In der Nacht 11./12.10.2026 wurden in mehreren hundert französischen Supermärkten Kältesysteme manipuliert: Angreifer schalteten Abtau-/Heizbetrieb ein bzw. veränderten Sollwerte, Temperaturen stiegen laut Berichten auf bis zu ~50 °C. Es folgten Wellen in Belgien, Luxemburg, Schweden und Estland. **Belegt** ist: CERT-FR listet als betroffene Systeme Copeland/Dixell XWEB sowie Danfoss AK-SC/AK-SM; Censys maß 1.825 aus dem Internet erreichbare Danfoss-StoreView-Panels in Frankreich (11.10.2026) und 537 am 14.10.2026. **Nicht belegt** sind Täter, der genaue Einstiegsvektor und eine Rolle der 2025 gepatchten CVEs (CVE-2025-41450/41451/41452).

| Befund | Belegstatus | Konsequenz für dieses Threat Model |
|---|---|---|
| Angriff über die Management-Weboberfläche der Kälte-Supervisoren, nicht über den Feldbus | BELEGT (CERT-FR nennt Exposition als Kernproblem; Claroty/Censys) | Management-/Fernwartungszugang ist Pfad #1 → R-01/R-02 und neue Kette R-T-09 |
| Massenhafte Internet-Exposition dieser Oberflächen | BELEGT (Censys: 1.825 → 537) | Expositions-/Segmentierungsprüfung ist pilotrelevant (R-07) |
| Sollwert-/Modusmanipulation (Defrost/Heizung), teils extreme Werte | BERICHTET | Beobachtete Modus-/Sollwertänderung ist das zentrale Erkennungssignal (R-03, R-T-01) |
| Geteilte/Default-Credentials, EOL-Firmware | TEILS BELEGT (CERT-FR empfiehlt Default-Passwort-Änderung, Firmware-Update) | R-02; Lifecycle-/Firmware-Stand als Asset-Eigenschaft |
| Kein bestätigter Einstiegsvektor, keine offiziellen IOCs | BELEGT (Nicht-Bestätigung) | Detection muss verhaltensbasiert sein, nicht signaturbasiert |

Quellen (Abruf 2026-11-03): [CERT-FR CERTFR-2026-ALE-012](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/), [CISA ICSA-25-140-03](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03), [Claroty Team82](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers), [Censys](https://censys.com/blog/frostbitten-in-france-a-danfoss-storeview-internet-exposure-report/), [The Hacker News](https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html), [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su); Detailauswertung in `market-research.md`.

**Grenze:** Diese Vorfälle sind Priorisierungsgrundlage, kein Beweis, dass GeDefense sie verhindert hätte. Ein passives System kann eine laufende Manipulation erkennen und belegen, aber nicht rückgängig machen und nicht die Netzwerkexposition beseitigen.

---

## 0.2 Schwachstellen- und Lifecycle-Kontext (keine Kausalaussage)

Die 2025 gepatchten AK-SM-800A-Schwachstellen sind dokumentiert — **aber nicht als Einstiegsursache der Oktober-Angriffe belegt**:

| CVE | Typ (Kurz) | CVSS v3.1 | Fix | Beleg |
|---|---|---|---|---|
| CVE-2025-41450 | Auth-Bypass über zeitbasierte Passwortgenerierung („code of the day“) | 8.2 | R4.2 | CISA ICSA-25-140-03; Claroty Team82 |
| CVE-2025-41451 | Command Injection (Alarm-to-Mail-Konfiguration → OS-Shell, post-auth) | 7.6 | R4.3.1 | ebenda |
| CVE-2025-41452 | Externe Kontrolle der nginx-Konfiguration (DoS) | 5.4 | R4.3.1 | ebenda |

**Keine Kausalaussage:** Es ist **nicht** belegt, dass diese CVEs der Einstiegsvektor waren; vorläufige Einschätzungen deuten darauf hin, dass sie es nicht waren (BERICHTET). Sie sind **Schwachstellenkontext** für den Advisory-Katalog (Release 0.2) — kein Exploit-Pfad, keine Erklärung des Vorfalls, keine Grundlage für eine Produktaussage wie „verhindert CVE-Ausnutzung“.

**EOL als Restrisiko-Faktor:** Danfoss AK-SM 800 ist seit **05/2021** End-of-Life, AK-SC 355 seit **2016** (BERICHTET, Danfoss-Aussagen via The Hacker News); für diese Geräte sind keine Security-Updates mehr zu erwarten. Folgen: (a) Kompensation nur über Netz-/Zugangskontrolle und Sichtbarkeit, nicht über Patching; (b) GeDefense führt Lifecycle-/Firmware-Stand als Asset-Eigenschaft mit Quelle und Confidence — ohne Update-Anweisung, ohne Patch-Garantie; (c) EOL-Geräte bleiben ein **Restrisiko**, das der Betreiber akzeptieren, kompensieren oder ersetzen muss.

**DE-Analogie, kein DE-Vorfall:** Für Deutschland ist in der Recherche **kein** belegter Angriff auf Supermarkt-Kältetechnik dokumentiert. Die Übertragbarkeit ergibt sich aus derselben Geräte- und Dienstleisterlandschaft, nicht aus einem DE-Vorfall; externe Kommunikation darf das nicht als DE-Erfahrung darstellen.

---

## 1. Schutzgüter

| ID | Schutzgut | Warum kritisch | Rolle von GeDefense |
|---|---|---|---|
| SG-1 | Verfügbarkeit der Kühlkette (Kühlregale, Kühl-/Tiefkühlräume, Verbundanlagen) | Produktverlust, wirtschaftlicher Schaden, Betreiberpflichten | **beobachtet** — steuert nicht |
| SG-2 | Integrität von Sollwerten, Betriebsmodi und Steuerungsparametern | Manipulation kann unauffällig zu Erwärmung führen | **erkennt Änderungen** (passiv/read-only), schreibt nicht |
| SG-3 | Aussagekraft der Temperaturtelemetrie (Echtheit, Vollständigkeit, Zeitbezug) | Falsche „alles in Ordnung“-Anzeige ist gefährlicher als Datenausfall | **prüft Plausibilität/Qualität**, ersetzt keine geeichte Messung |
| SG-4 | Vertraulichkeit von Dienstleister- und Management-Zugangsdaten | Credential-Missbrauch ist der realistischste Fernangriff | **sieht Sitzungen/Auffälligkeiten**, verwahrt keine OT-Passwörter im Klartext |
| SG-5 | Nachvollziehbarkeit (Audit-Trail, Evidenz, Alarmtrennung) | Ohne Timeline kein belastbarer Incident-Prozess | **erzeugt und schützt Audit-/Evidenzdaten** |
| SG-6 | Verfügbarkeit der GeDefense-Komponenten selbst | Ausfall darf Anlagenbetrieb nicht beeinträchtigen | **fail-safe / graceful degradation** |
| SG-7 | Mandantentrennung und Datenminimierung | Standortübergreifende Fehlsichtbarkeit, Datenschutz | **serverseitig erzwungen**, standardmäßig keine Payloads |

**Nicht geschützt durch GeDefense:** physische Zerstörung, Kältemittel-Leckagen, Sensor-Kalibrierfehler ohne Netzsichtbarkeit, Manipulation durch Personen mit bereits legitimen Vollzugriff, Ausfall der Anlagensteuerung aus nicht-cyber Ursachen.

---

## 2. Angreifermodelle

| ID | Angreifer | Fähigkeiten | Relevanz |
|---|---|---|---|
| A1 | Externer Netzangreifer | Pakete/Ports/Protokollheader senden, Verbindungsraten, erreichbare Dienste | Nur wenn Filial-OT aus WAN/Internet erreichbar ist (Segmentierungsfehler) |
| A2 | Kompromittiertes Dienstleister-Endgerät | legitime Fernwartungs-Credentials, VPN/Portalfreigabe, volle Sitzungsrechte im freigegebenen Fenster | **höchste realistische Relevanz** für Sollwert-/Modusmanipulation |
| A3 | Gestohlene/wiederverwendete Zugangsdaten | Anmeldung ohne Gerätebindung, ggf. außerhalb Freigabefenster | Relevant bei fehlender MFA/Gerätebindung |
| A4 | Kompromittiertes Edge-Gateway | lokale Ausführung auf GeDefense-Host, Zugriff auf Puffer/Config, evtl. zentrale mTLS-Identität | Relevant für Alarmunterdrückung/Datenmanipulation |
| A5 | Missbrauch eines zentralen Managementkontos | Policy-/Schwellwert-/Site-Änderungen, Sichtbarkeit über Filialen | Relevant für „Blindmachen“ und Massenwirkung |
| A6 | Fehlerhafte/maliziöse OT-Konfiguration (kein Angreifer nötig) | Sollwert-/Modusänderung durch Fehlbedienung, Wartungsfehler | Muss von Angriff unterscheidbar bleiben |
| A7 | Lieferketten-/Update-Angreifer | manipulierte Adapter, Update-Artefakte, Abhängigkeiten | Relevant für Integrität der GeDefense-Kette |
| A8 | Physischer/baulicher Eingriff | Verkabelung, TAP-Zugang, USB am Gateway | Nur Erkennung/Restrisiko, nicht Abwehr |

Nicht modelliert als aufhebbar: Root-Angreifer auf dem GeDefense-Host kann lokal Daten und Logs verändern (vgl. Bestand: „keine Garantie gegen Root“). Dieses Modell wird **erkannt/erschwert**, nicht besiegt.

---

## 3. Trust Boundaries

| ID | Grenze | Beispielhafter Übergang | Zulässiger Datenfluss | Primärkontrolle (MVP) |
|---|---|---|---|---|
| TB-1 | **OT Process → OT Monitoring** | PLC/Regler/BMS ⇢ TAP/SPAN ⇢ Collector | ausschließlich Einweg (Kopie), keine Rückwirkung | TAP/SPAN, read-only Adapter, kein Routing, keine Schreib-Function-Codes |
| TB-2 | **OT Monitoring → Core (lokal)** | Collector → Detection → Puffer | lokal, einseitig | Parser-Isolation, Schema-Validierung, keine Roh-Payload-Persistenz |
| TB-3 | **Gateway → Retail IT** | Gateway ⇄ Filialnetz | nur Management-/Update-/UI-Pfad, **kein** Transit-Routing | Host-Firewall, keine Forwarding-Rolle, Least-Privilege |
| TB-4 | **Filiale → Zentral** | Edge ⇢ Central Console | outbound-only, gegenseitig authentisiert (mTLS), signierte Updates | mTLS, Zertifikatsbindung, Store-and-forward |
| TB-5 | **External Maintenance → Management/OT** | Dienstleister ⇢ Fernwartungspfad ⇢ Regler | nur freigegebenes Zeitfenster, Zielsystem, Ticketbezug | Wartungsfenster-Modell, MFA/Gerätebindung (soweit Access-Modul vorhanden), Sitzungs-Audit, Alarm außerhalb Fenster |
| TB-6 | **Admin/UI → Management** | Operator ⇢ Dashboard/API | RBAC, Session, Audit | Rollen, Site-Scoping, AuditEntry je Änderung |
| TB-7 | **GeDefense-Update → Host** | Update-Artefakt → Gateway | signiert, versionsgeprüft, rollbackfähig | Signaturprüfung, Integritätscheck, gestaffelter Rollout |
| TB-8 | **Internet/WAN → Management-Web-UI (Kälte-Supervisor)** | externer/ungeklärter Client ⇢ HTTPS ⇢ StoreView/XWEB (Danfoss AK-SM/AK-SC, Copeland/Dixell) | **kein** zulässiger Direktzugriff; Zugang nur über freigegebenen Management-/Wartungspfad | Expositions-Sichtbarkeit (Flow-/Header-Metadaten), Freigabe-/Audit-Prozess, Netzwerkzugangskontrolle durch Betreiber; **keine automatische Isolation** |

**Architektur-Invariante:** Das Gateway stellt **kein** Routing zwischen TB-1/TB-3/TB-4 her. Ein Gateway, das als Router oder NAT zwischen OT- und IT-Zone wirkt, verletzt die Segmentierungsannahme und ist ein Release-Blocker.

### 3.1 STRIDE-Kurzmatrix

| Boundary | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| TB-1 | gefälschte Geräte-/Sitzungsidentität | — | Schreib-Function-Codes werden nicht protokolliert | manipulierte Telemetrie | TAP-Ausfall = blinder Fleck | — |
| TB-2 | — | Event-/Zeitstempel-Manipulation | fehlende Herkunft (`source`) | Parser-Fehlinterpretation | Event-Sturm | — |
| TB-3 | — | — | — | — | DoS des Gateways | Gateway als Lateral-Pivot |
| TB-4 | Zertifikatsmissbrauch | Replay/Manipulation im Transit | — | Abfluss von Standortdaten | WAN-Ausfall | kompromittierte Zentrale |
| TB-5 | Credential-Diebstahl | Sollwert-/Modusänderung | fehlende Sitzungsprotokolle | Ausspähen von Anlagenzuständen | — | Dienstleister → volle OT-Rechte |
| TB-6 | Session-Hijack | Policy-/Schwellwertänderung | fehlendes Audit | Datenexfiltration | — | Rolleneskalation |
| TB-7 | — | manipulierte Update-Artefakte | fehlende Signaturprüfung | — | Update-Ausfall | Code-Ausführung auf Gateway |
| TB-8 | Default-/geteilte Credentials | Sollwert-/Config-Änderung über UI | fehlende Session-Protokolle | Anlagen-/Standortdaten im UI | UI-Ausfall/Überlast | Web-UI → OS-/Konfigurationsrechte (z. B. CVE-Kontext §0.2) |

---

## 4. Risiken R-01 … R-10 (Baukonzept §6 Schritt 2)

Format je Risiko: STRIDE-Klasse · Trust Boundary · Priorität · **Eintrittspfad · Erkennungsindikatoren · Auswirkung · Schutzmaßnahme (MVP) · Restrisiko · Sichere Reaktion**. „Erkennung“ heißt immer: *was GeDefense aus passiven Daten tatsächlich ableiten kann*; nicht Sichtbares wird ausdrücklich benannt.

### R-01 · Kompromittierter Fernwartungszugang eines Dienstleisters
`STRIDE: Spoofing/Elevation · TB-5 · Priorität P0`
- **Eintrittspfad:** Dienstleister-Laptop oder -Konto kompromittiert (Phishing/Malware) → Anmeldung über freigegebenen Fernwartungspfad → Sitzung innerhalb oder außerhalb des Wartungsfensters → Zugriff auf Kühlregler/Verbundanlage.
- **Indikatoren:** neue Quell-MAC/OUI, unbekanntes Gerät im Wartungspfad; Sitzung außerhalb `MaintenanceWindow`; Zielsystem außerhalb der Freigabe; ungewöhnliche Sitzungsdauer/-zeit; mehrere parallele Sitzungen; Abweichung zwischen Ticket-Referenz und Zielasset; erstmalige Kommunikation zuvor nie beobachteter Steuerung.
- **Auswirkung:** vollständige Kontrolle über freigegebenes Zielsystem; Sollwert-/Modusänderung möglich; hohes Schadenspotenzial bei minimalem Aufwand.
- **Schutz (MVP):** Wartungsfenster- und Dienstleistermodell, Sitzungsbeginn/-ende/Ziel/Freigabe auditieren, Anomalie-Alert (Fenster/Gerät/Ziel), Evidence-Snapshot, manuelle Reaktionsempfehlung.
- **Restrisiko:** Ein legitimes, aber kompromittiertes Dienstleister-Endgerät handelt innerhalb seiner Rechte; GeDefense erkennt die Sitzung, kann sie aber nicht verhindern. Verschlüsselte Fernwartung (RDP/VPN) ist inhaltlich nicht einsehbar.
- **Sichere Reaktion:** Dienstleisterkontakt verifizieren → Sitzung durch berechtigte Person beenden/widerrufen (nur Management-/Fernwartungspfad, nicht OT-Prozesskommunikation) → Evidenz sichern → Betreiber-Incident-Prozess.
- **Nachweis:** `TestDetect_MaintenanceOutsideWindow_EmitsHighAlert`, `TestAudit_MaintenanceSession_FullFields`.

### R-02 · Gestohlene oder wiederverwendete Zugangsdaten
`STRIDE: Spoofing · TB-5/TB-6 · Priorität P1`
- **Eintrittspfad:** Credential-Leak (Dienstleister, Techniker, Admin), Wiederverwendung aus anderem Kontext, fehlende MFA/Gerätebindung, kein Zeitfensterbezug.
- **Indikatoren:** Login ohne Gerätebindung; Anmeldung von untypischer Quelle/Geografie (soweit Metadaten vorhanden); gleichzeitige Sitzungen; Zugriff außerhalb Rollen-/Zeitprofil; Fehlversuchs-Cluster.
- **Auswirkung:** unautorisierter Fernzugriff; bei Admin-Konto auch Policy-/Schwellwertmanipulation (→ R-05).
- **Schutz (MVP):** Reuse des GeDefense-Access-Modells (Rollen/Sitzungen/MFA, soweit vorhanden), Zeitfenster, Sitzungs-Audit, Alarm bei untypischem Muster; keine Klartext-Secrets in Config/Logs.
- **Restrisiko:** Gültige Credentials mit MFA können bis zur Rotation missbraucht werden; GeDefense kann Ursprungsvertrauen nicht beweisen.
- **Sichere Reaktion:** Konto/Sitzung sperren (Managementpfad), Rotation, betroffene Assets prüfen, Audit-Export.
- **Nachweis:** `TestAccess_CredentialReusePattern_RaisesAlert`, `TestSecrets_NoPlaintextInConfigOrLogs`.

### R-03 · Unautorisierte Sollwert- oder Betriebsmodusänderung
`STRIDE: Tampering · TB-1/TB-5 · Priorität P0`
- **Eintrittspfad:** Schreibzugriff auf Regler (direkt, über Fernwartung oder fehlerhafte Automatik) → Sollwert, Modus (Kühlen/Abtauen/Heizen/Aus) oder Parameter ändern.
- **Indikatoren:** passiv beobachtete Schreiboperationen — Modbus TCP Function Codes 5, 6, 15, 16 (Coil/Register Write), 22/23 (Mask Write / Read-Write Multiple); BACnet/IP `writeProperty`, `writePropertyMultiple`, `reinitializeDevice`; OPC-UA `Write`/Method-Call auf Steuer-NodeIds; SNMP `SET`; MQTT-Publish auf Kommando-Topics. Zusätzlich: beobachteter Sollwert-Delta außerhalb Wartungsfenster, Moduswechsel außerhalb plausiblen Zyklus. Belegtes Symptomschema 2026: Umschalten auf Abtau-/Heizbetrieb, extreme Sollwerte (BERICHTET).
- **Auswirkung:** unmittelbare Prozessbeeinflussung ohne Alarm der Anlagensteuerung; potenziell schleichende Erwärmung.
- **Schutz (MVP):** Schreib-Function-Codes **werden passiv erkannt und als Ereignis erfasst**, aber **nie aktiv ausgelöst**; Abgleich gegen Wartungsfenster; Alert mit Kontext; keine Schreibfähigkeit im Code (→ `safety-boundaries.md` S-01/S-02).
- **Restrisiko:** Verschlüsselte oder proprietäre Protokolle ohne passive Lesbarkeit bleiben unsichtbar; Änderung über lokalem HMI ohne Netzsichtbarkeit wird nicht erkannt.
- **Sichere Reaktion:** Keine automatische Rückänderung. Betreiber/Anlagenverantwortlicher prüfen Ist-Zustand, entscheiden über Rücknahme nach Hersteller-/Betriebsprozess; GeDefense liefert Evidenz.
- **Nachweis:** `TestAdapter_RejectsWriteFunctionCodes` (statisch/Typ-Ebene), `TestDetect_ModbusWriteFunctionCode_EmitsTamperEvent` (Simulator-PCAP), `TestDetect_SetpointChangeOutsideWindow_Alert`.

### R-04 · Manipulierte oder fehlerhafte Temperaturtelemetrie
`STRIDE: Tampering/Repudiation · TB-1/TB-2 · Priorität P0`
- **Eintrittspfad:** Sensor/Gateway sendet falsche Werte (Spoofing, Replay, eingefrorene Werte, „schöne“ Konstantwerte), oder Sensor driftet/defekt; Daten erreichen GeDefense scheinbar legitim.
- **Indikatoren:** eingefrorener Wert (Varianz ≈ 0 über N Intervalle, während Vergleichssensoren sich bewegen); Replay identischer Werte/Zeitstempel; Sprung außerhalb physikalischer Grenzen; Zeitstempel-Rücksprung/Doppelzeit; Abweichung zwischen unabhängigen Sensoren derselben Zone; Datenlücke > 2× erwartetes Intervall; Qualitätsflag „unsicher“.
- **Auswirkung:** **Blindmachung** — Anzeige suggeriert sichere Kühlkette, während reale Erwärmung unentdeckt bleibt. Besonders gefährlich, weil kein Alarm entsteht.
- **Schutz (MVP):** Datenqualitätsregeln (Lücke, Konstantwert, Zeitstempel, Plausibilität, Sensorvergleich), `confidence` + `quality` je Messwert, explizite Herkunft, Alarmtrennung „Datenqualität“ von „Prozessalarm“; fehlende Telemetrie wird **nie** als „in Ordnung“ dargestellt.
- **Restrisiko:** Langsame, koordinierte Drift über Wochen kann jede statistische Baseline verschieben; Manipulation im Sensor selbst ist nicht erkennbar; redundante, netzgetrennte Sensorik bleibt Betreibersache.
- **Sichere Reaktion:** Datenqualitätsmeldung an Betreiber, Prüfung durch unabhängige Temperaturmessung/geeichtes Gerät; keine Aussage „Ware sicher“.
- **Nachweis:** `TestDetect_FrozenSensor_FlagsDataQuality`, `TestDetect_TelemetryGap_NotReportedAsOk`, `TestDetect_SensorDivergence_Alert`, `TestDetect_TimestampRegression_Flag`.

### R-05 · Kompromittiertes Edge-Gateway
`STRIDE: Tampering/Elevation/Repudiation · TB-2/TB-3/TB-4 · Priorität P0`
- **Eintrittspfad:** Schwachstelle im Gateway/Adapter (Parser, Webserver, Updatepfad), physischer Zugang, kompromittierter Update-Kanal → Codeausführung auf dem Gateway.
- **Indikatoren:** Integritätsprüfung der GeDefense-Konfiguration schlägt fehl; unerwartete Prozesse/Dienste (soweit Health-Check vorhanden); Heartbeat-/Telemetrie-Abweichung; unerwartete ausgehende Verbindungen; Audit-Kette unplausibel; Alarm-Unterdrückung (fehlende Alerts bei erwartbaren Ereignissen).
- **Auswirkung:** Manipulation von Alarmen/Daten, Unterdrückung von Detection, Evidenzverlust, potenziell Pivot in Retail IT/Zentrale (mTLS-Identität).
- **Schutz (MVP):** signierte Updates, Integritätsprüfung, minimale Dienste, Least-Privilege, Parser-Isolation, kein Transit-Routing, mTLS mit eigener, pro Standort gebundener Identität; Gateway-Kompromittierung muss sichtbar werden (Health/Heartbeat/Config-Integrität).
- **Restrisiko:** Root auf dem Gateway kann lokale Daten/Logs verändern; Erkennung ist nachgelagert, nicht präventiv.
- **Sichere Reaktion:** Gateway isolieren/neu aufsetzen (Managementpfad, nicht OT), Schlüssel/Zertifikat widerrufen, zentralen Alarm auslösen, Anlagenzustand unabhängig prüfen.
- **Nachweis:** `TestUpdate_RejectsUnsignedArtifact`, `TestGateway_TamperDetection_DegradedState`, `TestSecurity_NoRoutingBetweenZones`.

### R-06 · Missbrauch eines zentralen Managementkontos
`STRIDE: Elevation/Tampering/Repudiation · TB-6/TB-4 · Priorität P1`
- **Eintrittspfad:** Admin-/Servicekonto der zentralen Console kompromittiert oder überprivilegiert → Policy-, Schwellwert-, Site- oder Rollenänderung.
- **Indikatoren:** Policy-/Schwellwertänderung außerhalb Freigabeprozess; Änderung durch untypischen Akteur/Zeit; Rolleneskalation; Massenänderung über viele Sites; fehlende Begründung; Audit-Lücke.
- **Auswirkung:** **Blindmachung über alle Filialen** — z. B. Temperaturgrenzwerte oder Wartungsfenster so verändert, dass Angriffe nicht mehr alarmieren. Höchste Wirkung pro Aktion.
- **Schutz (MVP):** RBAC mit Site-/Rollen-Scoping, Vier-Augen-Prinzip für kritische Policy-Änderungen (0.2, sofern zentral vorhanden), Policy-Versionierung mit Akteur/Begründung/Vorher-Nachher, AuditEntry, Alarm bei kritischen Policy-Änderungen; kritische Schwellwerte nur mit Betreiberfreigabe änderbar.
- **Restrisiko:** Ein legitimes Admin-Konto mit Vollrechten bleibt wirkmächtig; Erkennung nur bei Protokollierung und Vergleich mit Freigabeprozess.
- **Sichere Reaktion:** Sitzung beenden, Rollen prüfen, Policy-Stand aus signiertem Backup vergleichen, alle betroffenen Sites auf Plausibilität prüfen.
- **Nachweis:** `TestPolicy_CriticalChangeRequiresApproval`, `TestAudit_PolicyChangeHasActorAndDiff`, `TestAuthz_CrossSiteAccessDenied`.

### R-07 · Netzwerksegmentierungsfehler
`STRIDE: Elevation/Tampering · TB-1/TB-3 · Priorität P0`
- **Eintrittspfad:** Flache Netzstruktur, Gateway als Router, Wartungszugang ohne Trennung, OT-Geräte mit Internetzugang, gemeinsame VLANs von OT und Retail IT.
- **Indikatoren:** unerwartete Kommunikationspartner zwischen Zonen; Broadcast-/Scan-Muster; Retail-IT-Geräte sprechen direkt mit Reglern; neue direkte Pfade zuvor nicht beobachtet; OT-Geräte mit ausgehendem Internetverkehr; **Management-Oberflächen (HTTP/HTTPS) direkt aus WAN erreichbar** (belegt wichtigster Expositionsbefund 2026).
- **Auswirkung:** Angreifer aus Retail IT/WAN erreicht OT ohne Hürde; jede Detection wird zum reinen Nachlauf.
- **Schutz (MVP):** Zonenmodell als **Annahme** dokumentieren und prüfen (nicht als Tatsache behaupten!), Baseline erlaubter Beziehungen, Alarm auf zonenzentrierte Abweichungen, Betriebs-/Segmentierungscheckliste für Pilotinstallation, keine Discovery über aktives Scannen.
- **Restrisiko:** Ohne Betreiber-/Netzwerkfreigabe ist Segmentierung nicht erzwingbar; GeDefense kann nur beobachten, nicht umbauen.
- **Sichere Reaktion:** Betreiber-Netzwerkverantwortliche informieren, Segmentierung nachziehen; keine automatische Blockade der OT-Prozesskommunikation.
- **Nachweis:** `TestDetect_CrossZoneFlow_Alert`, `TestDetect_NewCommunicationPartner_Event`, `TestDiscovery_PassiveOnly_NoActiveProbe`.

### R-08 · Falscher Alarm oder übersehene Anomalie
`STRIDE: DoS (Alert-Fatigue) / Repudiation · alle TB · Priorität P0`
- **Eintrittspfad:** zu empfindliche Regeln (Abtau, Türöffnung, Warenbeladung → Critical), fehlende Baseline, Sensorrauschen; oder zu grobe Regeln/fehlende Signale → echte Anomalie bleibt unentdeckt.
- **Indikatoren (Meta):** Alarmrate je Site/Regel; False-Positive-Quote aus Pilot-Negativfällen; Verhältnis Critical zu bestätigten Incidents; stille Regeln (nie ausgelöst = möglicherweise unwirksam); Alarme ohne Evidenz.
- **Auswirkung:** Alert-Fatigue → echte Anomalien werden übersehen; Vertrauensverlust; oder umgekehrt: Erkennungslücke bleibt unentdeckt.
- **Schutz (MVP):** Pflicht-Negativtests (Abtau, Türöffnung, Warenbeladung, Sensorrauschen), Confidence statt binärer Wahrheit, Schweregrad-Policy durch Betreiber, Trennung Beobachtung/Hypothese, dokumentierte False-Positive-Grenzen je Regel, Testdatensatz je Regel.
- **Restrisiko:** Heuristiken bleiben probabilistisch; „nie ausgelöst“ kann auch heißen: Regel ist falsch konfiguriert.
- **Sichere Reaktion:** Regelreview, Schwellwertanpassung mit Betreiberfreigabe, negative Testfälle ergänzen; keine stillschweigende Deaktivierung.
- **Nachweis:** `TestNegative_DefrostCycle_NoCriticalAlarm`, `TestNegative_DoorOpening_NoCriticalAlarm`, `TestNegative_LoadingPhase_NoCriticalAlarm`, `TestRule_MissingTestDataset_FailsCI`.

### R-09 · Ausfall der GeDefense-Komponente während des Anlagenbetriebs
`STRIDE: Denial of Service · TB-2/TB-3/TB-7 · Priorität P0`
- **Eintrittspfad:** Edge-/Gateway-Ausfall, Disk voll, Updatefehler, OOM durch Event-Sturm, WAN-Ausfall, fehlerhafte Konfiguration.
- **Indikatoren:** Heartbeat/Health fehlt, Puffer-/Queue-Wasserstand, Disk-Nutzung, Neustartzähler, fehlende Telemetrie im zentralen Sichtbild, degradierter Modus.
- **Auswirkung:** vorübergehende Blindheit; **keine** Beeinträchtigung der Anlagensteuerung (sofern Architektur-Invariante eingehalten).
- **Schutz (MVP):** keine Inline-Platzierung, keine Schreibpfade, kein Fail-Closed der OT, bounded Queues, Disk-Full-Schutz, graceful degradation mit sichtbarem Status, lokale Alarmierung ohne WAN, signiertes Update + Rollback.
- **Restrisiko:** Während Ausfall keine Erkennung; Wiederanlauf muss nachweislich ohne Anlagenwirkung sein (Test).
- **Sichere Reaktion:** Status „degradiert/blind“ sichtbar machen, Betreiber informieren, Recovery nach Runbook; keine Ad-hoc-Eingriffe in OT.
- **Nachweis:** `TestFailSafe_AgentStop_NoImpactOnSimulatedPlant`, `TestOffline_LocalAlarmStillWorks`, `TestDiskFull_NoCrash`, `TestRecovery_RestartWithoutPlantImpact`.

### R-10 · Zeitmanipulation oder fehlerhafte Zeitsynchronisation
`STRIDE: Tampering · TB-1/TB-2/TB-5 · Priorität P1`
- **Eintrittspfad:** NTP nicht erreichbar/ungesichert, Zeitzone verwechselt, Geräte liefern naive Zeit, Angreifer verstellt Gateway-/Gerätezeit, Sommerzeitwechsel.
- **Indikatoren:** Zeitstempel-Rücksprung, Drift zwischen `observed_at` und `received_at`, Gerätezeit vs. Gateway-Zeit, fehlende Monotonie, unsichere Zeitquelle, doppelte Zeitstempel.
- **Auswirkung:** falsche Korrelation/Reihenfolge, verpasste Wartungsfenster (Zugriff „innerhalb“ statt außerhalb), falsche Aufbewahrungs-/Evidenzbewertung, unbrauchbare Timeline im Incident.
- **Schutz (MVP):** intern UTC, getrennte Zeitfelder (`observed_at`, `received_at`, `source_ts` = Gerätezeit), `quality=clock_uncertain` bei unsicherer Zeit, Plausibilitätsalarm bei Drift/Rücksprung, keine stille Korrektur, lokale Anzeige nur in UI über `Site.Timezone`.
- **Restrisiko:** Manipulation an der Quelle (Gerätezeit) ist ohne vertrauenswürdige Referenz nicht immer erkennbar; Systemzeit des Gateways kann durch Root verändert werden.
- **Sichere Reaktion:** Zeitquelle prüfen, betroffene Ereignisse als „Zeit unsicher“ markieren, Evidenz nicht verwerfen, Timeline mit Unsicherheitsflag exportieren.
- **Nachweis:** `TestTime_TimestampRegression_Flagged`, `TestTime_AllTimesPersistedUTC`, `TestTime_DisplayLocalOnly`.

---

## 5. Angriffsketten (R-T-01 … R-T-08)

Legende: **V** = Voraussetzung, **S** = Schritt, **D** = Erkennungspunkt, **B** = Abbruchpunkt durch Betreiber/Architektur. „GeDefense-Grenze“ benennt ehrlich, was die Kette nicht verhindert.

### R-T-01 · Fernwartung → Sollwert-/Modusänderung → Temperaturanstieg
```text
V1  Dienstleister-Fernzugang existiert und ist freigegeben (TB-5)
V2  Dienstleister-Endgerät oder -Konto ist kompromittiert (A2/A3)
S1  Anmeldung über Fernwartungspfad (ggf. außerhalb Wartungsfenster)
S2  Kommunikation mit Kühlregler/Verbundanlage, Ziel außerhalb Freigabe
S3  Sollwert/Modus wird geändert (passiv als Schreib-FC sichtbar, wenn unverschlüsselt)
S4  Anlage regelt nicht mehr auf Sollbereich; Temperatur steigt
S5  Ware erwärmt sich; Anlagenalarm greift ggf. erst spät
D1  Sitzung außerhalb Fenster/unbekanntes Gerät          -> R-01/R-02 Alert
D2  neue Kommunikationsbeziehung zum Steuerungsgerät      -> R-07
D3  Schreib-Function-Code beobachtet                     -> R-03 Tamper-Event
D4  Sollwert-Delta außerhalb Wartungsfenster             -> R-03
D5  Temperatur-Rate/Grenzwert + Sensorvergleich          -> R-04/R-08
D6  Korrelation D1–D5 hebt Priorität                     -> Critical, Evidenzpaket
B1  Betreiber widerruft dedizierten Fernwartungszugang (nicht OT-Kommunikation)
B2  Anlagenverantwortlicher prüft Ist-Zustand und entscheidet Rücknahme
B3  Kühlketten-/Incident-Prozess des Betreibers läuft an
GeDefense-Grenze: erkennt die Kette und liefert Evidenz; verhindert S3 nicht,
schreibt nicht zurück, schaltet nicht ab.
```

### R-T-02 · Credential-Reuse → laterale Bewegung → Gateway-Kompromittierung
```text
V1  wiederverwendetes Passwort ohne MFA/Gerätebindung
S1  Login von untypischem Gerät/Netz
S2  laterale Bewegung im Retail-IT-/Managementnetz
S3  Zugriff auf Gateway-Konfiguration/Updatepfad
S4  Alarmunterdrückung oder Datenmanipulation
D1  Login-Anomalie, parallele Sitzungen                 -> R-02
D2  zonenzentrierte, neue Kommunikationspfade           -> R-07
D3  Integritäts-/Health-Abweichung des Gateways         -> R-05
B1  Sitzung/Konto sperren, Rotation, Zertifikat widerrufen
B2  Gateway aus Managementpfad neu aufsetzen
GeDefense-Grenze: erkennt Muster, kann gestohlene gültige Credentials nicht
von legitimen unterscheiden.
```

### R-T-03 · Telemetrie-Manipulation → falsches „alles OK“
```text
V1 Sensor/Gateway oder Übertragung manipulierbar (schwache Auth, Klartext)
S1  Werte werden eingefroren, gefälscht oder ersetzt (Replay)
S2  Anzeige/Dashboard zeigt scheinbar stabile Temperatur
S3  reale Erwärmung bleibt unentdeckt, kein Anlagenalarm
D1  Varianz ≈ 0 bei bewegten Vergleichssensoren         -> R-04
D2  Werte-/Zeitstempel-Replay, Duplikate                 -> R-04
D3  Sensor-Divergenz, Lücke, Sprung                      -> R-04
B1  Betreiber prüft mit unabhängiger Messung
GeDefense-Grenze: Datenqualität ist erkennbar, Wahrheit der Messung nicht beweisbar.
```

### R-T-04 · Gateway-Kompromittierung → Alarmunterdrückung
```text
V1  Codeausführung auf dem Edge-Gateway
S1  Detection-Regeln/Queues manipulieren
S2  Alerts zurückhalten oder verfälschen
S3  Zentrale sieht „normal“, während Anomalien laufen
D1  Heartbeat/Health/Config-Integrität                  -> R-05
D2  Alarmrate bricht unplausibel ein                    -> R-08
D3  Audit-Kette/Sequenz unplausibel                     -> R-05
B1  Gateway isolieren, Zertifikat widerrufen, neu aufsetzen
GeDefense-Grenze: kompromittierter Host kann lokale Daten verändern; Erkennung
ist nachgelagert (Zentrale/Health), nicht präventiv.
```

### R-T-05 · Zentrales Managementkonto → Schwellwert-/Policy-Blindmachung
```text
V1  Admin-/Servicekonto mit Policy-Rechten
S1  Temperaturgrenzwerte/Wartungsfenster/Alarmregeln ändern
S2  alle Sites alarmieren nicht mehr wie vorgesehen
S3  Angriff (z. B. R-T-01) läuft ohne Critical-Alert
D1  kritische Policy-Änderung ohne Freigabe/Akteur        -> R-06
D2  Massenänderung über Sites                              -> R-06
D3  plötzlich sinkende Critical-Rate                       -> R-08
B1  Vier-Augen-Freigabe, signiertes Policy-Backup, Rollback
GeDefense-Grenze: Audit und Versionierung machen die Änderung sichtbar,
verhindern sie aber nicht.
```

### R-T-06 · Segmentierungsfehler → Retail IT → OT
```text
V1  flaches Netz/Gateway als Router/Wartungszugang ohne Trennung
S1  Angreifer in Retail IT oder WAN erreicht OT direkt
S2  Discovery/Exploit gegen Regler/PLC (außerhalb GeDefense-Sichtbarkeit)
S3  Manipulation oder Ausfall der Anlage
D1  Cross-Zone-Flow, neue Kommunikationspartner            -> R-07
D2  Retail-IT-Gerät spricht Regler-Protokoll               -> R-07
B1  Betreiber zieht Segmentierung nach, Betriebsprozess
GeDefense-Grenze: beobachtet Fehlkonfiguration; baut Netz nicht um,
scannt nicht aktiv.
```

### R-T-07 · Zeitmanipulation → Korrelation und Fensterlogik brechen
```text
V1  ungesicherte NTP-/Gerätezeit oder Root auf Gateway
S1  Zeit zurückspringen/verschieben
S2  Wartungsfenster falsch bewertet, Timeline falsch sortiert
S3  Evidenz/Aufbewahrung/Reporting unbrauchbar
D1  Drift/Rücksprung/fehlende Monotonie                    -> R-10
B1  Zeitquelle prüfen, Ereignisse als „Zeit unsicher“ markieren
GeDefense-Grenze: Quelle manipulierte Zeit bleibt begrenzt vertrauenswürdig.
```

### R-T-08 · Alarmflut → Alert-Fatigue → echte Anomalie übersehen
```text
V1  zu empfindliche Regeln oder Sensorrauschen
S1  viele Low/Medium-Alarme bei Abtau/Tür/Warenbeladung
S2  Betreiber gewöhnt sich an Rauschen, bestätigt oberflächlich
S3  echte Critical-Kette (R-T-01) geht im Rauschen unter
D1  False-Positive-Quote in Pilot-Negativfällen            -> R-08
D2  Critical/Info-Verhältnis, unbestätigte Alarme          -> R-08
B1  Regelreview + Negativtests + Schwellwertfreigabe
GeDefense-Grenze: Priorisierung reduziert Rauschen, beseitigt es nicht.
```

### R-T-09 · Exposed Management UI → Session → Setpoint/Config-Änderung → Temperature Drift
`TB-8 · belegtes reales Angriffsmuster 2026 (FR; für DE nur Analogie) · Priorität P0`
```text
V1  Kälte-Supervisor (StoreView/XWEB) ist aus WAN/Internet erreichbar (Exposition)
V2  Default-/geteilte Credentials oder fehlende Netz-/Zugriffskontrolle
S1  Fremdzugriff auf die Management-Weboberfläche (HTTPS)
S2  Session ohne Wartungsfenster/Freigabe
S3  Sollwert-/Config- oder Modusänderung über die UI (Defrost/Heizung, extreme Werte)
S4  Anlage regelt nicht mehr auf Sollbereich; Temperatur driftet
Passiv beobachtbar (ohne Login, ohne Inhalts-DPI):
 I1 unbekanntes Quellgerät/-IP im Management-Segment (nie zuvor gesehen)
 I2 Management-UI-Nutzung außerhalb Freigabe-/Wartungsfenster
 I3 neue HTTP(S)-UI-Nutzung: erstmaliger Flow zu Port 80/443 des Supervisors,
    neuer TLS-SNI/Host-Header, neue Session-Dauer/-Volumen
 I4 Session ohne MaintenanceWindow-Bezug bzw. Fenster-Mismatch
 I5 beobachteter Modus-/Sollwertwechsel kurz nach I3 (RC3/Write-FC/BACnet write)
Erkennungspfad: I1–I4 -> R-01/R-02/R-07; I5 -> R-03; Trend -> R-04 -> Korrelation R-T-01
Mitigation: Sichtbarkeit + Freigabe + Audit, KEINE automatische Isolation:
 M1 Expositions-/Zugriffs-Sichtbarkeit im Dashboard (wer, wann, von wo, welches Ziel)
 M2 Freigabe-Prozess: Session muss zu Wartungsfenster/Ticket/Dienstleister passen
 M3 Audit + Evidence-Snapshot; Betreiber entscheidet über Netz-/Zugriffssperre
B1  Betreiber entfernt Internet-Exposition/filtert Zugriff (Netzwerk-/Firewall) — nicht GeDefense
B2  Betreiber prüft Ist-Zustand und entscheidet Rücknahme nach Betriebsprozess
GeDefense-Grenze: erkennt Exposition und Metadaten; sieht keine verschlüsselten
Inhalte, führt keine Login-/Auth-Tests durch, isoliert nichts automatisch.
Keine Kausalaussage zu CVEs (§0.2); EOL-Geräte = Restrisiko.
```

---

## 6. Erkennungsgrenzen (bewusst nicht versprochen)

| Nicht sichtbar / nicht beweisbar | Grund | Konsequenz |
|---|---|---|
| Inhalte verschlüsselter Fernwartung (VPN/TLS/RDP) | keine Entschlüsselung, kein MITM | nur Metadaten: Quelle, Ziel, Zeit, Dauer, Volumen |
| Manipulation innerhalb des Sensors/Reglers ohne Netzspur | lokale Wertänderung | nur Plausibilität/Divergenz, keine Gewissheit |
| Netzwerkverkehr außerhalb des TAP/SPAN-Segments | Segmentgrenze | explizite „blinder Fleck“-Kennzeichnung im UI |
| Aktive Schwachstellenausnutzung ohne beobachtbare Kommunikation | passives Monitoring | keine aktive Prüfung im MVP (S-03) |
| Echtheit/Kalibrierung der Messung | Metrologie | Datenqualität ≠ geeichte Messung |
| Insider mit legitimen Vollrechten | Rechte sind legitim | nur Audit/Anomalie, keine Verhinderung |
| Root auf dem Gateway | lokale Kontrolle | Erkennung nachgelagert, Restrisiko dokumentiert |
| Kältemittel-/Drucktechnik (EN 378) | nicht Cybersecurity-Scope | nicht Teil des Produkts |
| Inhalte der Management-Weboberfläche nach TLS | keine Entschlüsselung, kein MITM | nur Flow-/Header-Metadaten, soweit sichtbar; keine Login-Versuche |

---

## 7. Regulatorischer Kontext (nur mit Beleg, keine Konformitätsaussage)

> **Grundsatz:** GeDefense Retail behauptet **keine** Zertifizierung, keine NIS2-Konformität und keine HACCP-Erfüllung. Die folgenden Aussagen sind Einordnung, keine Rechtsberatung. Verbindlich ist die Prüfung durch Betreiber/Rechtsabteilung.

| Bezug | Belegte Aussage | Status / Grenze |
|---|---|---|
| NIS2-Richtlinie (EU) 2022/2555 | EU-Rahmen für Cybersicherheits-Risikomanagement und Meldepflichten; in Deutschland durch das BSIG (NIS-2-Umsetzungsgesetz) umgesetzt; Registrierung über das BSI-Portal, BSI bietet eine Betroffenheitsprüfung | Richtlinientext: [EUR-Lex 32022L2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) — Volltext in dieser Sitzung nicht abrufbar (HTTP 202), daher als Referenz prüfen. BSI-Umsetzung belegt über [BSI: NIS-2-regulierte Unternehmen](https://www.bsi.bund.de/DE/Themen/Regulierte-Wirtschaft/NIS-2-regulierte-Unternehmen/nis-2-regulierte-unternehmen_node.html) (Abruf 2026-11-03) |
| Sektor Lebensmittel | NIS2-Anhang II führt den Lebensmittelsektor (Produktion, Verarbeitung, Vertrieb) als „sonstigen kritischen Sektor“; ob ein konkreter Filialbetreiber erfasst ist, hängt von Größe/Schwellenwerten und nationaler Umsetzung ab | **Im Einzelfall zu prüfen** (BSI-Betroffenheitsprüfung/Rechtsberatung). Keine pauschale Aussage „Supermarkt = NIS2-pflichtig“. |
| NIS2-Risikomanagement-/Meldepflichten | GeDefense kann **Evidenz** für Inventar, Zugriffskontrolle, Logging, Incident-Timeline liefern | Keine Aussage, dass Pflichten damit erfüllt sind; Betreiber bleibt verantwortlich |
| HACCP / VO (EG) 852/2004 | Art. 5 verlangt von Lebensmittelunternehmern ein dauerhaftes, HACCP-basiertes Verfahren; Hygieneanforderungen in Anhang II | [EUR-Lex 32004R0852](https://eur-lex.europa.eu/eli/reg/2004/852/oj) — Volltext nicht abrufbar (HTTP 202), als Referenz prüfen. **GeDefense ist kein HACCP-System** und ersetzt keine betriebliche Kontrolle, keine amtliche Prüfung, keine Temperaturüberwachungspflicht des Betreibers |
| Grenzwerte / Produktsicherheit | Temperaturgrenzwerte sind produkt-, geräte- und prozessabhängig; Betreiber konfiguriert und verantwortet sie | Keine hart codierten universellen Grenzwerte (vgl. §5 Modul D) |
| DSGVO (EU) 2016/679 | Netzwerk-Metadaten (MAC/IP) können personenbezogen sein; Datenminimierung, Rechtsgrundlage, TOM erforderlich | [EUR-Lex 32016R0679](https://eur-lex.europa.eu/eli/reg/2016/679/oj) — im Einzelfall mit Datenschutz/Betriebsrat klären |
| IEC 62443 (Referenzrahmen) | Zonen-/Conduit-Modell und Security-Level-Konzept als Strukturierungshilfe für OT-Segmentierung | **Kein Zertifizierungsnachweis**; keine Behauptung „IEC-62443-konform“ |
| EN 378 (Kälteanlagen) | Sicherheits-/Umweltanforderungen an Kälteanlagen inkl. Kältemittel | Außerhalb Cybersecurity-Scope; keine Bewertung durch GeDefense |

**Konsequenz für Alarmtexte:** Sie dürfen regulatorische Begriffe nur als Verweis auf den Betreiberprozess nennen („Prüfung nach freigegebenem Kühlketten-/Incident-Plan“), nicht als Compliance-Aussage.

---

## 8. Explizit nicht versprochen

- kein Schutz vor physischer Zerstörung, Kältemittel-Leckage oder Anlagenausfall aus nicht-cyber Ursachen;
- keine Verhinderung von Sollwert-/Modusänderungen — nur Erkennung/Audit;
- keine Rücknahme von Änderungen an PLC/Reglern (keine Schreibpfade);
- keine automatische Isolation der OT-Prozesskommunikation oder Abschaltung von Kälteanlagen;
- keine vollständige Sichtbarkeit bei verschlüsselter Fernwartung und außerhalb des TAP-Segments;
- keine Garantie gegen Root auf dem GeDefense-Host;
- keine Gewissheit über die Wahrheit einer Messung (nur Plausibilität/Datenqualität);
- keine HACCP-Konformität, keine NIS2-Konformität, keine Zertifizierung, keine Lebensmittelsicherheitsgarantie;
- keine autonome Response, keine KI-basierte Entscheidung im MVP;
- keine Detektion ohne getestete Regeln mit Negativfällen („Regel nie ausgelöst“ ≠ „sicher“).

---

## 9. Nachweis-Mapping (Risiko → Kontrolle → Test)

| Risiko | Invariante (safety-boundaries) | Test-/Nachweisklasse |
|---|---|---|
| R-01, R-02, R-07 | S-05, S-11 | Maintenance-/Access-/Expositionstests, Audit-Feldtests |
| R-03 | S-01, S-02, S-06 | Adapter-Oberfläche ohne Schreibpfad, Simulator-PCAP mit Write-FC |
| R-04 | S-06, S-13 | Datenqualitäts-/Negativtests |
| R-05, R-07 | S-03, S-04, S-11 | Integritäts-/Update-/Segmentierungstests |
| R-06 | S-06, S-11 | RBAC-/Policy-Approval-/Audit-Tests |
| R-08 | S-06, S-08 | Negativtests (Abtau/Tür/Warenbeladung), Regel-Pflichtdatensatz |
| R-09 | S-04, S-09, S-10 | Fail-safe-, Offline-, Disk-Full-, Recovery-Tests |
| R-10 | S-10 | UTC-/Drift-/Rücksprung-Tests |

**Abnahme-Relevanz:** P0-Risiken (R-01, R-03, R-04, R-05, R-07, R-08, R-09) dürfen ohne zugehörigen bestandenen Test **kein** Pilot-Release erhalten (vgl. `MVP scope`).
