# GeDefense Retail — Protokollmatrix (Alpha 0.3.0-alpha.1)

**Produktlinie:** VisionGaiaTechnology · GeDefense Retail
**Zweck:** Verbindliche Entscheidungsgrundlage für Read-only-Adapter, passive Erkennung und Simulator-Tests
**Recherchestand / Abrufdatum:** **2026-11-03** · **Autor:** GeDefense Retail research

---

## 0. Leitregeln (nicht verhandelbar)

1. **Read-only by construction:** Kein Adapter implementiert einen Schreibpfad. Schreibfunktionen werden nicht „deaktiviert“, sondern **nicht implementiert** — plus Negativtests, die beweisen, dass kein Write-Frame erzeugt werden kann.
2. **Passiv zuerst:** Erkennung bevorzugt aus TAP/SPAN-Metadaten und PCAP. Aktive Reads nur mit expliziter Betreiberfreigabe, Rate-Limit und dokumentiertem Ziel.
3. **Kein Broadcast-Sturm:** Keine `Who-Is`-Schleifen (BACnet), keine Scan-Sweeps (Modbus), keine SNMP-Walks über fremde Bereiche.
4. **Parser-Isolation:** Jeder Adapter läuft getrennt; ein Parserfehler darf weder Core noch andere Adapter beenden (Baukonzept Schritt 4).
5. **Ports sind Hinweise, keine Wahrheit:** Kälte-Supervisoren nutzen häufig abweichende HTTP(S)-Ports. Erkennung muss signatur- und verhaltensbasiert sein.

**Beleg-Legende:** `BELEGT` = im Volltext geprüft · `STANDARD` = Protokollkonvention/Industriestandard, in dieser Recherche **nicht separat primärquelllich** verifiziert (bewusst so markiert, nicht als Zitat getarnt) · `UNBESTÄTIGT` = offen.

---

## 1. Übersichtsmatrix

| Protokoll | Transport / Standard-Port | Native Auth | Native Verschlüsselung | Read-only möglich | Passive Erkennbarkeit | DE/EU-Relevanz Filiale | MVP-Prio |
|---|---|---|---|---|---|---|---|
| **HTTP/HTTPS (Management-UI)** | TCP 80/443 (oft abweichend) | Web-Login (qualitativ sehr unterschiedlich) | nur HTTPS | nur Metadaten/Sessionbeobachtung | **hoch** (Host-/Server-Header, Titel, SNI) | **sehr hoch** — Kälte-Supervisoren (StoreView, XWEB) | **P0** |
| **Modbus TCP** | TCP 502 | **nein** | **nein** | ja (FC 3/4, lesend) | **hoch** (MBAP-Header, Function Codes) | hoch (Regler/Gateways) | **P0** |
| **BACnet/IP** | UDP 47808 | nein (teilweise Device-Level) | nein (BACnet/SC wäre sicher) | ja (ReadProperty/Multiple) | mittel–hoch (BVLC/NPDU, Objekt-IDs) | hoch (Gebäudeleittechnik) | **P1** |
| **MQTT** | TCP 1883 / TLS 8883 | Broker-Credentials | nur TLS (8883) | ja (Subscribe) | mittel (CONNECT/SUBSCRIBE; Topics nur ohne TLS) | mittel–hoch (neue IoT-/Energie-Gateways) | **P1** |
| **SNMPv3** | UDP 161 (Traps 162) | ja (USM, authPriv) | ja (v3) | ja (GET/GETBULK, RO-View) | mittel (v1/v2c-Klartext, v3 opak) | mittel (Switches, USV, BMS) | **P2** |
| **OPC UA** | TCP 4840 | ja (Zertifikate/User) | ja (SignAndEncrypt) | ja (Browse/Read) | niedrig–mittel (binär, sessionbasiert) | niedrig–mittel im Filial-OT, höher zentral | **P3** |
| **LON / proprietäre Gateways** | kein Standard-Port | gateway-abhängig | nein | nur über Gateway-Mapping | niedrig (nur über Gateway-Traffic) | mittel (Bestandsgebäude) | **P4** |

**Port-Belegstatus:** Modbus/TCP 502 `BELEGT` ([Xona](https://www.xonasystems.com/industry-advisories/global-modbus/tcp-probing-campaign-reinforces-ot-exposure-risk)). Alle übrigen Ports `STANDARD` (Protokollkonvention) — im MVP nicht als harte Erkennungsregel verwenden.

---

## 2. Protokollprofile im Detail

### 2.1 HTTP/HTTPS — Management-Oberflächen (der wichtigste „Protokoll“-Fall)

**Warum P0:** Der Frankreich-Vorfall lief **nicht** über Modbus oder BACnet, sondern über die Weboberfläche der Kälte-Supervisoren. Wer diesen Kanal nicht sichtbar macht, verpasst den belegten Angriffsweg.

| Aspekt | Befund |
|---|---|
| Belegte Geräte | Danfoss AK-SM/AK-SC mit UI „StoreView“; Copeland/Dixell XWEB `BELEGT` ([CERT-FR](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/), [Claroty](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)) |
| Erkennung passiv | HTTP `Host`, `User-Agent`, `Server`-Header, Seitentitel, typische URI-Muster (`xml.cgi`, Login-Pfade), TLS SNI |
| Sicherheitsfallen | Klartext-HTTP im OT-Netz; selbstsignierte Zertifikate; identische Admin-Konten für alle Filialen; Session-Cookies ohne `Secure`; UI erlaubt Konfigurationsänderungen (Abtauzeiten, Sollwerte) → **passive Beobachtung, keine Interaktion** |
| Was GeDefense tun darf | Flows zu/von Management-Ports zählen, Sitzungsdauer, Quell-/Zielbeziehungen, Änderung von Konfigurations-URLs **nur als Metadaten** (sofern passiv sichtbar), Alarm bei neuem Zugriff außerhalb Wartungsfenster |
| Was GeDefense nicht darf | Login-Versuche, Brute-Force, CSRF-/Auth-Tests, Session-Übernahme, UI-Crawling |
| Testbarkeit | Mock-HTTP-Server + synthetische PCAPs; kein echtes Gerät nötig |

### 2.2 Modbus TCP

| Aspekt | Befund |
|---|---|
| Eigenschaften | kompakt, verbindungsorientiert; **keine native Authentisierung oder Verschlüsselung** `BELEGT` ([Xona](https://www.xonasystems.com/industry-advisories/global-modbus/tcp-probing-campaign-reinforces-ot-exposure-risk)) |
| Read-only | Function Codes **3** (Holding Register), **4** (Input Register), ggf. 1/2 (Coils/Discrete) — nur lesend. FC 5/6/15/16 dürfen **nicht existieren** |
| Passive Erkennung | MBAP-Header (Transaction/Protocol ID, Length, Unit ID), Function Code, Register-Adressen, Wiederholraten → gute Metadaten ohne Payload-Speicherung |
| Sicherheitsfallen | Unit-ID-Mehrdeutigkeit hinter Gateways; gepollte Register können Prozesswerte sein; Samplerate kann Anlage belasten; Schreibzugriff wäre sofort prozessrelevant |
| DE/EU-Relevanz | hoch: Regler/Gateways mit Modbus-Schnittstelle sind in Kälte-/Gebäudetechnik verbreitet; in dieser Recherche **keine herstellerspezifische Modbus-Doku** für Danfoss AK-SM verifiziert (`UNBESTÄTIGT`) |
| Testbarkeit | sehr gut: Modbus-Simulator (Register-Map), synthetische PCAPs, Negativtests für Write-FCs |

### 2.3 BACnet/IP

| Aspekt | Befund |
|---|---|
| Eigenschaften | Gebäudeautomations-Standard; Geräte-/Objektmodell (Device, AnalogInput, BinaryOutput …) `STANDARD` |
| Read-only | ReadProperty, ReadPropertyMultiple; **WriteProperty nicht implementieren** |
| Passive Erkennung | UDP-Verkehr, BVLC/NPDU-Struktur, Device- und Objekt-IDs, `I-Am`-Broadcasts (passiv sichtbar, ohne selbst `Who-Is` zu senden) |
| Sicherheitsfallen | BACnet ist unauthentisiert; `Who-Is`-Broadcasts und globale Reads können ganze Netze aufwecken; **kein** aktives Objekt-Discovery im MVP; BACnet/SC wäre die sichere Variante, ist in Filialen selten |
| DE/EU-Relevanz | hoch für BMS/Gebäudeleittechnik am Filialrand; Geräteklasse belegt für Copeland E2/E3 (BACnet MSTP) `BELEGT` ([Copeland-Doku](https://www.copeland.com/en-vn/products/controls-monitoring-systems/facility-controls-electronics/facility-and-system-controls/documents/supervisory-e3)) |
| Testbarkeit | gut: BACnet-Simulator/Device-Stack, synthetische PCAPs; passive Parser zuerst |

### 2.4 MQTT

| Aspekt | Befund |
|---|---|
| Eigenschaften | Publish/Subscribe über Broker; TLS optional `STANDARD` |
| Read-only | ausschließlich **Subscribe** auf freigegebene Telemetrie-Topics; **kein Publish** |
| Passive Erkennung | CONNECT/SUBSCRIBE/PUBLISH-Pakete, Broker-Beziehungen, TLS SNI; Topic-Namen nur ohne TLS sichtbar |
| Sicherheitsfallen | Wildcard-Subscriptions (`#`) erzeugen Last und Datenflut; Broker-Credentials häufig geteilt; retained messages können veraltete Werte als „aktuell“ erscheinen lassen; QoS-/Retry-Verhalten erzeugt Duplikate |
| DE/EU-Relevanz | mittel–hoch: neue IoT-/Energie-/Zähler-Gateways; Kälte-Supervisoren nutzen eher HTTP/Portal |
| Testbarkeit | sehr gut: Mosquitto lokal, synthetische Topics, Lasttests |

### 2.5 SNMPv3

| Aspekt | Befund |
|---|---|
| Eigenschaften | UDP-basiertes Management; v3 mit USM (Authentisierung + Verschlüsselung), v1/v2c mit Community-Strings im Klartext `STANDARD` |
| Read-only | GET/GETBULK gegen eine **Read-only-View**; **kein SET** |
| Passive Erkennung | v1/v2c: Community-Strings in PCAP sichtbar (Befund, kein Angriff!); v3: opak, nur Flow-/Port-Metadaten |
| Sicherheitsfallen | v1/v2c in OT-Netzen weit verbreitet; Community-Strings gelten als „Passwörter“ und dürfen nicht geloggt werden; SNMP-Walks können Geräte mit schwacher CPU belasten |
| DE/EU-Relevanz | mittel: Switches, USV, ggf. BMS-Gateways — nützlich für Infrastruktur-Assets, nicht für Kälte-Kernwerte |
| Testbarkeit | gut: `snmpd`/Simulator, v3-Credentials, Walk-Limits |

### 2.6 OPC UA

| Aspekt | Befund |
|---|---|
| Eigenschaften | zertifikatsbasierte, sessionorientierte Kommunikation; SignAndEncrypt möglich `STANDARD` |
| Read-only | Browse + Read, ausschließlich mit `SignAndEncrypt` und geprüfter Trust List; keine Method-Calls, keine Writes |
| Passive Erkennung | schwierig: binäres Protokoll, Session-Aufbau; Nutzung von Endpoint-Zertifikaten/Ports `UNBESTÄTIGT` für Filialgeräte |
| Sicherheitsfallen | Anonymous-Endpoints, „None“-Security-Policy, schwache Zertifikatsprüfung; OPC UA ist im Filial-OT selten, im zentralen Umfeld relevanter |
| DE/EU-Relevanz | niedrig–mittel im Filialkern, höher bei zentraler Leittechnik |
| Testbarkeit | gut: open62541-Server mit Security-Policies; Negativtests für Anonymous |

### 2.7 LON / proprietäre Gateways

| Aspekt | Befund |
|---|---|
| Eigenschaften | Feldbusse ohne IP; Zugang nur über Gateway in IP-Welt `STANDARD` |
| Read-only | nur über das Mapping des Gateways (Modbus/BACnet/HTTP) |
| Passive Erkennung | nur Gateway-Traffic; keine direkte Feldbus-Sicht ohne zusätzliche Hardware |
| Sicherheitsfallen | Gateways sind oft ungehärtete Linux-Kisten mit Default-Zugängen; sie bündeln viele Feldgeräte hinter einer IP → hoher Impact bei Kompromittierung |
| DE/EU-Relevanz | mittel: Bestandsgebäude, ältere Filialen |
| Testbarkeit | eingeschränkt; nur Gateway-Seite simulierbar → **nicht MVP** |

---

## 3. MVP-Reihenfolge (Empfehlung)

| Stufe | Inhalt | Begründung |
|---|---|---|
| **P0a** | Passive Flow-/Asset-Discovery + HTTP(S)-Metadaten für Management-Oberflächen | belegter Angriffsweg der 2026er Vorfälle |
| **P0b** | Modbus-TCP-Metadaten (FC-Statistik, Beziehungen) read-only | breiteste OT-Schnittstelle, gute passive Erkennbarkeit, einfacher Simulator |
| **P1** | BACnet/IP (passiv + freigegebene Reads), MQTT-Telemetrie | BMS- und IoT-Abdeckung der Filiale |
| **P2** | SNMPv3 Read-only | Infrastruktur-Assets, geringes Risiko |
| **P3** | OPC UA (nur mit expliziter Freigabe) | selten im Filialkern, hoher Implementierungsaufwand |
| **P4** | LON/proprietär | nur über Gateways, kein MVP-Bedarf |

**Abweichung vom Baukonzept:** Das Konzept nennt „MVP: Modbus, BACnet, OPC UA, MQTT, SNMP“. Diese Matrix schlägt vor, **HTTP(S)-Metadaten vor OPC UA** zu ziehen — weil der einzige belegte Massenangriff genau diesen Kanal nutzte. Das ist eine begründete Priorisierungsänderung, keine Scope-Ausweitung.

---

## 4. Sicherheits- und Safety-Gates für alle Adapter

| Gate | Anforderung | Prüfung |
|---|---|---|
| G1 | Kein Write-Pfad im Code | statische Prüfung + Negativtest: kein FC 5/6/15/16, kein BACnet WriteProperty, kein SNMP SET, kein MQTT Publish, kein OPC-UA-Write |
| G2 | Keine aktiven Scans gegen Produktions-OT | Code-Review + Betriebsdoku; aktive Reads nur per Freigabe-Flag mit Rate-Limit |
| G3 | Keine Credentials in Logs/Configs | Secret-Handling, Redaction-Tests |
| G4 | Parser-Isolation | Fehlerinjektion pro Adapter, Core bleibt gesund |
| G5 | Rate-/Verbindungslimits | Lasttest gegen Simulator, dokumentierte Obergrenzen |
| G6 | Zeitstempel-/Zeitqualität | Events mit `observed_at`/`received_at`, unsichere Systemzeit markiert |
| G7 | Keine Payload-Speicherung | nur Metadaten; Payload-Redaction nachweisbar |

---

## 5. Simulator- und Testmatrix

| Protokoll | Simulator | Negativfälle | Synthetische PCAPs |
|---|---|---|---|
| HTTP(S) | Mock-Server mit StoreView-/XWEB-ähnlichen Headern | Login-Versuch darf nie entstehen; neuer Zugriff außerhalb Fenster | ja |
| Modbus TCP | Register-Map-Simulator | Write-FC wird nie gesendet; abnormal hohe Pollrate | ja |
| BACnet/IP | Device-/Objekt-Simulator | kein `Who-Is`-Broadcast; kein WriteProperty | ja |
| MQTT | Mosquitto mit Testtopics | kein Publish, keine `#`-Subscription in Prod | ja |
| SNMPv3 | snmpd/Simulator mit RO-View | kein SET, kein Walk außerhalb Scope | ja |
| OPC UA | open62541 mit Security-Policies | Anonymous abgelehnt, kein Method-Call | ja |

**Testregel:** Alle Tests laufen gegen Simulatoren oder dedizierte Testgeräte — niemals gegen produktive Kälteanlagen (Baukonzept Schritt 15).

---

## 6. Offene Punkte

1. **Ports nicht primärquelllich verifiziert** (außer Modbus 502): Vor Pilot mit realer Hardware bzw. Herstellerdoku verifizieren.
2. **Herstellerspezifische Modbus-Registermaps** (Danfoss, Carel, Dixell) sind nicht öffentlich geprüft — ohne Betreiber-/Herstellerfreigabe keine Register-Reads.
3. **HTTP(S)-Metadaten-Tiefe** ist rechtlich/datenschutzrechtlich zu bewerten: Header ja, Payload nein (siehe `regulatory-context.json`, DSGVO-Minimierung).
4. **BACnet/SC** als sichere Variante ist in Filialen nicht belegt — nicht als vorhanden annehmen.
5. **OPC UA im Filialkontext** ist unbelegt; Aufwand/Nutzen vor Implementierung prüfen.

---

## 7. Quellen (Abrufdatum 2026-11-03)

1. CERT-FR — CERTFR-2026-ALE-012 — https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/
2. Claroty Team82 — Danfoss AK-SM 800A (Web-Architektur, `xml.cgi`, StoreView) — https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers
3. Xona Systems — Modbus/TCP-Port 502, fehlende Auth/Verschlüsselung — https://www.xonasystems.com/industry-advisories/global-modbus/tcp-probing-campaign-reinforces-ot-exposure-risk
4. Copeland — BACnet-MSTP-/SOAP-Dokumente für E2/E3 — https://www.copeland.com/en-vn/products/controls-monitoring-systems/facility-controls-electronics/facility-and-system-controls/documents/supervisory-e3
5. The Hacker News — Vorfallmechanik/Defrost, EOL — https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html
6. Barracuda — Retail-/MSP-Einordnung, Internet-Exposition — https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su


---

## 8. Durchsetzungssemantik im Access Gate (Alpha 0.3.0-alpha.1)

### 8.1 Modbus TCP — Read-before-Write

- Unmittelbar vor einem freigegebenen Write liest das Gate den Ist-Wert (CurrentValue) erneut über
  FC3/FC1.
- Weicht der gelesene Wert vom im Plan gebundenen Ist-Wert ab, ist er leer oder nicht lesbar, wird
  der Write **verweigert** und als Deny mit Audit-Evidenz festgehalten.
- Deny-Reasons: `current_value_missing` (kein/leerer Wert), `current_value_mismatch` (abweichender
  Wert), `current_value_unreadable` (Read-Fehler/Timeout).
- Der Plan bleibt an Ziel, Funktion, Adresse und Sollwert gebunden; Read-before-Write ersetzt keine
  Freigabe.
- Gilt für Modbus TCP; echte Regler-/Firmware-Semantik ist im Alpha nicht verifiziert.

### 8.2 HTTP/HTTPS — ehrliche Grenze

- Für HTTP(S)-Supervisor-Oberflächen gibt es **keinen generischen Ist-Wert-Recheck**; Formular-/JSON-
  Werte lassen sich nicht universell verifizieren.
- Es bleibt bei URL-/Methoden-Allowlist und Wertbindung im Plan; wenn keine Verifikation möglich ist,
  zeigt die Check-Ausgabe eine Warnung.
- Das ist **keine** gleichwertige Read-before-Write-Garantie.

### 8.3 Werte, `read_coils` und TOCTOU

- `current_value`/`new_value` sind Anzeigewerte; `value_scale` (Default `1.0`) gilt Rohwert =
  round(Anzeigewert / `value_scale`). Dezimalwerte (mit `.`) erfordern `value_scale`, sonst `400`.
- Der Geräte-Reread erfolgt **unmittelbar vor dem Write**, nicht bei Plan-Erstellung. Reihenfolge:
  verify → consume/audit → forward. Fehler ⇒ Deny + Audit
  (`current_value_missing|mismatch|unreadable`), Modbus-Exception `0x04`.
- **`read_coils` (FC1)** ist ein separates Read-Window; Modbus-Targets konfigurieren
  `read_coils: {"fc":1,"start":0,"count":N}`. FC5/FC15-Coil-Writes benötigen es; fehlt es, wird der
  Write verweigert und `retailgate check` erzeugt einen **fehlschlagenden Check `RBC-<target>`**.
- **TOCTOU-Restfenster:** zwischen Reread und Write bleibt ein kurzes Fenster offen; das Gate
  **reduziert** es, schließt es aber nicht vollständig. Gegenmaßnahmen: kurze Sessions/Fenster,
  Geräte-Interlocks und Monitoring auf unerwartete Änderungen. Keine „TOCTOU-frei“-Aussage.
- HTTP(S): kein generischer Ist-Wert-Recheck; Check-Warnung und Wertbindung bleiben.

### 8.4 Vendor-Katalog

- `data/ot-catalog/vendors.json` ist Laufzeitwissen für Discovery/API/UI/Gate-Advisory; ein Treffer
  ist **kein Auto-Allow**.
- Schreibzugriffe bleiben plan- und freigabebasiert; der Katalog beeinflusst nur Klassifikation,
  Hinweise und Darstellung.

### 8.5 Setpoint-Integrität (FC3/FC6)

- Referenzen werden zyklisch per **FC3** gelesen; Abweichungen werden erst nach `confirm_reads`
  gemeldet (`gate.integrity.mismatch`). `stale_after` markiert fehlende Werte.
- Recovery schreibt den Referenzwert per **FC6**, ausschließlich für explizit freigegebene
  Referenzen (`recovery: true`), ohne aktive Freigabe/Session, mit Rate-Limit/Cooldown/Read-back.
- Recovery ist Default aus, kein Beweis über externe Schreiber und kein Ersatz für
  Read-before-Write/TOCTOU-Schutz.
