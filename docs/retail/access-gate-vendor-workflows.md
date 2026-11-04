# GeDefense Retail Access Gate — Vendor-Workflows und Änderungsklassen (G0)

**Produktlinie:** VisionGaiaTechnology · GeDefense Retail **Access Gate (0.2)**
**Dokumenttyp:** G0-Research (Punkt 5): realistische Kalibrierung der Default-Deny-Policy
**Stand / Abrufdatum:** **2026-11-03** · **Quelle:** GeDefense Retail research
**Zweck:** Belegen, **was** an Kälte-Supervisoren real geändert wird, **wer** es tut, **über welchen Weg** — damit die Policy weder zu eng (Betrieb blockiert) noch zu weit (Enforcement wertlos) wird. **Keine Schreibautomatik.**

---

## 0. Belegstatus und Methode

`BELEGT` = Quelle im Volltext geprüft · `BERICHTET` = Sekundärquelle · `STANDARD` = etablierte Praxis, hier nicht primärquelllich belegt · `OFFEN` = keine belastbare öffentliche Quelle gefunden (Betreiber-/Pilotwissen nötig) · `EINORDNUNG` = Schlussfolgerung des Autors.

Öffentliche Quellen beschreiben **Fähigkeiten** von Supervisoren und **Vorfallmechanik** meist präziser als konkrete Betreiber-Ticketprozesse. Wo der Prozess nicht öffentlich belegt ist, wird das ausdrücklich als `OFFEN` markiert — nicht als Fakt dargestellt.

---

## 1. Was an Kälte-Supervisoren real geändert wird

### 1.1 Belegte Änderungsklassen

| # | Änderungsklasse | Beleg | Belegstatus | Kritikalität |
|---|---|---|---|---|
| C-01 | **Sollwerte / Temperaturschwellen** konfigurieren | Claroty: AK-SM 800A erlaubt „Configure temperature thresholds" | `BELEGT` ([Claroty Team82](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)) | **kritisch** (direkte Produktwirkung) |
| C-02 | **Abtau-/Défroster-Zeiten und -Pläne** | CERT-FR: nach Vorfall „Vérifier l'intégralité de la configuration, notamment les **plages de dégivrage**"; Vorfallmechanik = erzwungener Dauer-Abtau | `BELEGT` ([CERT-FR](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/), [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su)) | **kritisch** (war Angriffshebel) |
| C-03 | **Betriebs-/Zeitpläne** (Schedules) | Claroty: „Adjust operating schedules" | `BELEGT` | hoch |
| C-04 | **Alarmkonfiguration / Alarm-zu-Mail / Benachrichtigungsdienste** | Claroty: „Configure notification services"; CVE-2025-41451 betrifft genau die „alarm-to-mail configuration fields" | `BELEGT` (Claroty, CISA) | hoch (Alarmunterdrückung = Blindheit) |
| C-05 | **Benutzer und Berechtigungen** | Claroty: „Manage users and permissions"; CERT-FR: Konten prüfen, Secrets ändern | `BELEGT` | **kritisch** (Persistenz) |
| C-06 | **Sicherheitsmodus / Webserver-Konfiguration** | Danfoss „Strict Session Control" (HTTPS Pflicht) ab 4.0; CVE-2025-41452 = Injektion beliebiger nginx-Direktiven über `load_nginx_headers` | `BELEGT` (CISA, Claroty), `BERICHTET` (Version/Fix) | hoch |
| C-07 | **Firmware-Update** | Danfoss `.spk`-Pakete, Upgrade-Pfad 3.x→4.x→5.3.x, kein Downgrade ab 5.3.x; Copeland E2/E3 Firmware/Application per USB (ADF) | `BERICHTET` (Danfoss), `BELEGT` (Copeland-Dokumente) | **kritisch** (eigener Prozess, nicht Gate-Scope) |
| C-08 | **Netzwerk-/Verbindungskonfiguration** (IP, Ports, Cloud-Ziel, Header) | CERT-FR: „Reconfigurer complètement l'équipement"; CVE-2025-41452 (nginx); Hersteller-Cloud-Anbindung | `BELEGT` (Existenz der Konfigurationsflächen) | hoch |
| C-09 | **Werksreset / Neustart** | CERT-FR: „Reset Factory" als Kompromittierungs-Maßnahme | `BELEGT` | hoch (Ausfallrisiko) |
| C-10 | **Sensor-Kalibrierung / Offset** | Keine gerätespezifische Primärquelle in dieser Recherche gefunden | `OFFEN` | hoch (falls vorhanden) |
| C-11 | **Uhrzeit/Zeitzone** | Nicht gerätespezifisch belegt; relevant für Abtau-/Alarmlogik | `OFFEN` | medium |

**Wichtig für die Policy:** Die **belegten** Klassen decken bereits alles ab, was im Vorfall missbraucht wurde (Abtau, Sollwert, Benutzer, Alarm). Ein Default-Deny, der diese Klassen schützt, ist fachlich begründet — ohne erfundene Register-/Objektnummern.

### 1.2 Was **nicht** als Fakt übernommen wird

- Konkrete Modbus-Registeradressen oder BACnet-Objekt-IDs je Hersteller: **nicht öffentlich belegt** (`OFFEN`). Die Policy arbeitet deshalb mit **Allowlist-Einträgen pro Asset**, die bei Inbetriebnahme belegt eingetragen werden (Register/Objekt + Wertebereich + Zweck), nicht mit geratenen Defaults.
- „Sensor-Kalibrierung" und „Zeit setzen" als Standardfunktion: plausibel, aber nicht belegt → im Katalog `low`/`unverified`.

---

## 2. Wer die Änderungen durchführt

| Akteur | Rolle | Beleg | Belegstatus |
|---|---|---|---|
| **Kältefachbetrieb / Refrigeration Contractor** | betreibt und wartet die Anlage, ändert Parameter, reagiert auf Störungen | Barracuda: Kältespezialisten bleiben für Betrieb/Wartung verantwortlich, Netzwerksicherheit liegt woanders; Coopérative U: Märkte sind Kunden der Kältehersteller/Fachbetriebe, nicht direkt von Danfoss | `BELEGT` ([Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su)) |
| **Hersteller-Support** | Fernzugriff für Diagnose/Update, teils über eigene Portale | Danfoss/Hersteller-Fernwartung ist Teil des Geschäftsmodells; Claroty: „Perform maintenance activities remotely" | `BELEGT` (Claroty), `BERICHTET` (Herstellerpraxis) |
| **Betreiber / Filialpersonal** | Alarmquittung, Sichtprüfung, ggf. kleine Anpassungen (Sollwert) | HACCP-Eigenkontrolle und Dokumentationspflichten liegen beim Lebensmittelunternehmer | `BELEGT` (Pflicht), `OFFEN` (wer genau am Supervisor schreibt) |
| **IT / MSP** | Netzwerk, VPN, Firewall, teils Monitoring | Barracuda adressiert MSPs ausdrücklich als Verantwortliche für Netz/Remote-Zugang | `BELEGT` ([Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su)) |

**Verantwortungs-Spaltung ist das Kernproblem:** Wer die Anlage bedient, ist nicht automatisch der, der das Netz absichert — und umgekehrt. Genau diese Lücke adressiert das Gate mit expliziten Rollen (`vendor_write_requester`, `approver`, `master_admin`, `auditor`).

**Deutsche Praxis (`BERICHTET`, Suchtreffer):** Der VDKF stellt ein Muster für **Wartungsverträge** in der Kälte-/Klimabranche bereit (VDKF-Wartungsvertrag, PDF) — d. h. Wartung ist vertraglich geregelt, typischerweise mit definierten Leistungen und Reaktionszeiten. Konkrete Ticket-/Freigabeprozesse für Parameteränderungen sind öffentlich **nicht** belegt (`OFFEN`).

---

## 3. Über welche Wege geändert wird

| # | Weg | Beleg | Belegstatus | Gate-Relevanz |
|---|---|---|---|---|
| W-01 | **Direkte Web-UI des Supervisors** (StoreView/XWEB) aus dem Filialnetz | Claroty: eingebetteter Webserver, Fernwartung üblich; CERT-FR: Exposition war Kernproblem | `BELEGT` | **Hauptpfad** — HTTP(S)-Proxy (Plan Punkt 10) |
| W-02 | **Direkte Web-UI aus dem Internet** (Portfreigabe/NAT) | 1.825 sichtbare StoreView-Panels in FR (Censys); CERT-FR verlangt Entfernung | `BELEGT` | **verboten** — Bypass (Netzwerk-Bypass) |
| W-03 | **Dienstleister-VPN** ins Filialnetz, danach breiter Zugriff | CERT-FR: Zugriff nur über VPN; Claroty: „unmonitored, always-on vendor VPNs" als Problem | `BELEGT` | Ziel: Terminierung am Gate, nicht am Netz |
| W-04 | **IP-Whitelisting** der Dienstleister-IPs | CERT-FR nennt es ausdrücklich als Notlösung, **nicht dauerhaft** | `BELEGT` | nur Übergang, kein Zielzustand |
| W-05 | **Hersteller-Cloud-Portal / Remote-Monitoring** (z. B. Carel RED optimise/tERA; Danfoss-Portale) | Carel: RED optimise, RED control, tERA, IoT-Gateway belegt | `BELEGT` (Existenz), `OFFEN` (Datenfluss/Rechte) | außerhalb Gate; Betreiber muss bewerten (Blueprint B-04) |
| W-06 | **Service-Laptop am lokalen Switch/OT-Port** | üblich, aber kein öffentlicher Beleg für DE-Retail | `OFFEN` | Bypass — passive Erkennung, nicht Gate |
| W-07 | **Mobilfunk-/4G-Router im Schaltschrank** | im Baukonzept als Angriffspfad genannt, hier **kein** Primärbeleg | `OFFEN` | Bypass — Blueprint B-05 |
| W-08 | **Lokales HMI-Panel** | Gerätefamilien haben lokale Bedienung (Supervisor-Konsole/Display, Copeland FSD) | `BELEGT` (Existenz Display/Konsole) | außerhalb Gate (§5 Blueprint) |
| W-09 | **USB-Update** | Copeland E2/E3: ADF-Upload per USB | `BELEGT` (Dokumenttitel) | eigener Prozess, nicht Gate |
| W-10 | **RS-485/CAN-Serviceport** | Feldbusse in Kälteanlagen (`bacnet_mstp` im Katalog) | `STANDARD` | außerhalb Gate |

**Kalibrierungsregel für die Policy:** Das Gate muss W-01 sauber proxien (Hauptpfad), W-02 hart verbieten und W-03/W-04 kontrollieren. W-05…W-10 sind **nicht** durchsetzbar und müssen über Betriebskonzept + Bypass-Erkennung adressiert werden. Alles andere wäre eine Sicherheitsbehauptung ohne Deckung.

---

## 4. Typische Ticket-/Freigabeprozesse (was belegbar ist, was nicht)

### 4.1 Belegbare Anforderungen, die einen Freigabeprozess erzwingen

| Anforderung | Quelle | Konsequenz für die Policy |
|---|---|---|
| HACCP-basierte Verfahren mit **Dokumentation und Aufzeichnungen** | VO (EG) 852/2004, Art. 5 (HACCP-Prinzipien, insb. Nr. 6–7: Verifizierung, Dokumente/Aufzeichnungen) | Jede Änderung an Temperatur-/Abtau-/Alarmlogik ist **dokumentationspflichtig** → Write-Plan + Audit ist nicht Bürokratie, sondern Anschlussfähigkeit an bestehende Pflicht |
| **Temperaturkontrolle und Registrierung** der Lagertemperatur im Betrieb | VO (EG) 852/2004, Anhang II Kap. I Nr. 2 | Sollwertänderung ist eine lebensmittelhygienisch relevante Änderung, kein „IT-Ticket" |
| Nach Vorfall: Konfiguration vollständig prüfen (insb. Abtauzeiten), Konten/Secrets prüfen, neu konfigurieren | CERT-FR | Gate muss **Vorher-Werte** im Plan führen, damit ein Vorfall rekonstruierbar ist |
| Remote-Zugang nur über kontrollierten, authentisierten, zeitgebundenen, überwachten Kanal | CERT-FR (VPN), Xona (brokered, time-bound), Claroty (Zero-Trust statt Dauer-VPN) | Fenster + TTL + Einmal-Token + Session-Audit sind marktübliche Anforderungen, keine Erfindung |
| Patch-/Update-Prozess separat behandeln | CISA ICSA-25-140-03 (Mitigationen), Copeland Security-Update-Advisories | Firmware-Update **nie** über den normalen Write-Plan automatisieren |

### 4.2 Was öffentlich **nicht** belegt ist (`OFFEN`)

- Ob deutsche Filialisten heute **Ticketnummern** für Parameteränderungen verwenden, welche ITSM-Tools, welche Genehmigungsstufen.
- Ob Freigaben telefonisch, per E-Mail oder über ein Portal erfolgen.
- Wie Dienstleister-Sessions heute protokolliert werden (oft gar nicht — genau das ist die Lücke).
- Ob Vier-Augen-Freigaben bei Sollwertänderungen üblich sind (eher nicht).

→ **Produktfolgerung:** Die Gate-Policy muss den Freigabeprozess **einfordern, aber nicht voraussetzen, dass er schon existiert.** Die UI muss einen niedrigschwelligen Plan-Antrag anbieten (Ziel, Ist→Soll, Grund, Ticket optional), damit Betreiber ohne bestehendes ITSM starten können — und das Feld `ticket_ref` optional lassen, solange der Betreiber keinen Prozess hat.

---

## 5. Ableitung der Default-Deny-Policy (Kalibrierung)

### 5.1 Änderungsklassen → Policy-Stufen

| Klasse | Beispiele | Default | Mindest-Freigabe | TTL (Vorschlag) | Vier-Augen | Allowlist-Granularität |
|---|---|---|---|---|---|---|
| **K1 — produktionskritisch** | Sollwert, Betriebsmodus, Abtauplan, Kompressor-/Ventil-Direktsteuerung | **DENY** | vendor_write_requester + approver | ≤ 30 min | bei `critical`-Assets ja | Register/Objekt **und** Wertebereich, Plan-Hash |
| **K2 — alarm-/sicherheitsrelevant** | Alarmgrenzen, Alarm-zu-Mail, Benachrichtigungsziele, Benutzerkonten, Sicherheitsmodus | **DENY** | + master_admin | ≤ 30 min | ja | URL-Pfad/Aktion + Werte |
| **K3 — betrieblich** | Zeitpläne, Anzeige-/Report-Einstellungen, unnötige Dienste | **DENY** | approver | ≤ 60 min | nur wenn kritisch | URL-Pfad/Aktion |
| **K4 — Netzwerk/Gerät** | IP/DNS/Cloud-Ziel, nginx-Header, Zertifikate | **DENY** | + master_admin | ≤ 15 min | ja | exakte Aktion; kein Wildcard |
| **K5 — Lifecycle** | Firmware, Werksreset, Werks-Backup/Restore | **NICHT über Gate** | Herstellerprozess | – | – | eigener freigegebener Prozess (Plan §8.5) |

**Regel:** `critical`-Einstufung ist eine **Betreiber-Entscheidung pro Asset**, nicht automatisch „alles Kälte = critical". Ein Kühlregal für Getränke ist nicht dasselbe wie ein Tiefkühllager für Fisch.

### 5.2 Wertebindung statt Funktionsfreigabe

Der Plan bindet **Register/Objekt + Ist-Wert + Soll-Wert**. Das Gate liest den Ist-Wert unmittelbar vor Ausführung erneut und verweigert bei Abweichung (Lost-Update-Schutz). Damit ist auch eine „genehmigte" Änderung nicht wiederverwendbar, wenn sich der Anlagenzustand geändert hat.

### 5.3 Was ausdrücklich **nicht** Teil der Policy ist

- Kein automatisches Setzen von Sollwerten (auch nicht „zur Sicherheit").
- Kein automatisches Zurücksetzen von Änderungen nach Ablauf des Fensters.
- Kein Firmware-Upload, kein Werksreset über das Gate.
- Kein Schreiben in die OT-Prozesskommunikation (Regler↔Aktorik).
- Kein „Notfall-Schreibrecht" ohne Freigabe; Notfall = Betreiber/Hersteller vor Ort.

---

## 6. Offene Punkte und Research-Gaps

1. **Keine öffentliche Quelle** für konkrete DE-Ticket-/Freigabeprozesse in der Kältetechnik → `OFFEN`; Pilot-Interviews nötig.
2. **Register-/Objektnummern** je Hersteller unbekannt → Allowlist muss bei Inbetriebnahme herstellerdokumentiert befüllt werden; keine Ratewerte.
3. **Sensor-Kalibrierung / Uhrzeit** als Änderungsklasse nicht gerätespezifisch belegt → vor Policy-Freigabe klären.
4. **Hersteller-Cloud-Rechte** (W-05) unbekannt: Wenn der Hersteller über sein Portal schreiben kann, umgeht das Gate-Policy vollständig — Betreiber muss entscheiden (deaktivieren oder separat bewerten).
5. **VDKF-Wartungsvertrag** nur als Suchtreffer verifiziert; Vertragstext nicht geprüft (`search_result_only`).
6. **4G-Router / lokale Service-Laptops** unbelegt, aber plausibel — Bypass-Inventar muss sie erfassen.

---

## 7. Quellen (Abrufdatum 2026-11-03)

1. Claroty Team82 — Danfoss AK-SM 800A: Fähigkeiten der Management-UI, CVE-Kette, exponierte Interfaces — https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers
2. CISA — ICSA-25-140-03 (CVE-2025-41450/51/52, Mitigationen, Upgrade-Pfad) — https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03
3. CERT-FR — CERTFR-2026-ALE-012 (Defrost-Konfiguration, Konten/Secrets, Reset, VPN) — https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/
4. Barracuda — Vorfall, Verantwortungsgrenzen Betreiber/Dienstleister/MSP — https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su
5. The Hacker News — Danfoss-Update-Prozess, Strict Session Control, EOL — https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html
6. Copeland — E3/Site-Supervisor-Dokumente (Password Standards, SOAP, ADF/USB, Security Advisories, Release Notes) — https://www.copeland.com/en-vn/products/controls-monitoring-systems/facility-controls-electronics/facility-and-system-controls/documents/supervisory-e3
7. Carel — Remote-Monitoring/Cloud-Portfolio (RED optimise, RED control, tERA, IoT-Gateway) — https://www.carel.com/reducing-energy-consumption-and-operational-costs-in-buildings
8. Xona Systems — brokered, time-bound, monitored access — https://www.xonasystems.com/industry-advisories/global-modbus/tcp-probing-campaign-reinforces-ot-exposure-risk
9. VO (EG) Nr. 852/2004 — HACCP/Dokumentation/Temperaturkontrolle — https://kompendium.bghw.de/bghw/docs/bghw_eg/bghw_eg-Documents/e2004-852/e2004-852_0_.html
10. VDKF-Wartungsvertrag (Muster, nur Suchtreffer) — http://mfn-gmbh.de/wp-content/uploads/2017/05/VDKF-Wartungsvertrag.pdf
11. libmodbus-Referenz — Modbus-Schreibfunktionen (FC 0x06/0x0F/0x10) — https://libmodbus.org/reference/modbus_write_register/
