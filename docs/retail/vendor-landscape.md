# GeDefense Retail — Hersteller- und Gerätelandschaft DE/EU

**Produktlinie:** VisionGaiaTechnology · GeDefense Retail
**Zweck:** Belegte Geräte-, Protokoll- und Fernwartungslandschaft für Katalog, Discovery-Klassifizierung und Advisory-Zuordnung
**Recherchestand / Abrufdatum:** **2026-11-03** · **Autor:** GeDefense Retail research

---

## 0. JSON-Schema-Dokumentation (verbindlich für den Go-Dienst)

Die beiden maschinenlesbaren Kataloge liegen unter `data/ot-catalog/`:

| Datei | Zweck |
|---|---|
| `vendors.json` | Hersteller, Gerätefamilien, Protokolle, Fernwartungsmodelle, OUI-Prefixe |
| `regulatory-context.json` | Regulatorische Rahmenwerke und ihre Rolle für die Produktgrenzen |

### 0.1 Allgemeine Konventionen

- **Format:** strikt valide UTF-8-JSON, **keine Kommentare**, keine Trailing Commas. Vor Abgabe mit `python -m json.tool <datei>` geprüft.
- **Leere optionale Felder werden weggelassen** (z. B. `ports`, `cves`, `additional_sources`): Der Go-Loader muss fehlende Felder als leere Liste/leeren String behandeln. Ausgenommen ist `oui_prefixes` — es bleibt als leeres Array vorhanden, damit die Schemaform stabil ist.
- **Zur Dateilänge:** `vendors.json` ist bewusst **eine** Datei (Vertrag für den Go-Dienst), daher länger als die 400-Zeilen-Richtlinie für Prosa-Dokumente. Die Richtlinie gilt hier für die drei Markdown-Dokumente, nicht für den datengetriebenen Katalog. Eine Aufteilung würde den im Task definierten Ladevertrag brechen.
- **Top-Level immer:** `schema_version` (String, aktuell `"1.0"`), `last_checked` (`"2026-11-03"`), `notes` (String), plus die Datenarrays.
- **Namenskonvention:** `lower_snake_case` für alle Schlüssel; stabile `id`-Felder (`lower-kebab` bzw. `snake`), damit der Go-Dienst per Map indexieren kann.
- **`confidence`:** ausschließlich `"high"`, `"medium"`, `"low"`.
  - `high` = Hersteller-/Behördenquelle im Volltext geprüft (z. B. CISA, CERT-FR, Hersteller-Doku).
  - `medium` = Fachpresse/Research-Bericht im Volltext geprüft ODER Hersteller-Doku als Suchtreffer mit eindeutigem Inhalt.
  - `low` = nur Suchtreffer/Sekundärzitat, Inhalt nicht im Volltext verifiziert.
- **`verification`:** `"fulltext_fetched"` | `"secondary_reported"` | `"search_result_only"`. Damit bleibt maschinell unterscheidbar, was tatsächlich geprüft wurde — die Ehrlichkeitsregel als Datenfeld, nicht als Fußnote.
- **`last_checked`:** pro Eintrag `"2026-11-03"`.
- **`source_url`:** genau eine primäre URL pro Eintrag; zusätzliche Belege in `additional_sources[]`.
- **Keine erfundenen Daten:** `oui_prefixes` ist leer, weil in dieser Recherche kein OUI-Prefix primärquelllich verifiziert werden konnte (siehe §6). `cves` enthält nur CVEs mit behördlicher oder herstellerseitiger Quelle.

### 0.2 `vendors.json` — Objektformen

```text
vendors[]              { id, name, legal_name?, country, role, focus,
                         source_url, additional_sources[], confidence, verification, last_checked }

device_families[]      { id, vendor_id, name, category,
                         protocols[], ports[], management_interface?,
                         firmware_update?, lifecycle?,
                         cves[], notes?,
                         source_url, confidence, verification, last_checked }

protocols[]            { id, name, transport, default_port, direction,
                         authenticated_native, encrypted_native,
                         read_only_possible, passive_detectable,
                         source_url, confidence, verification, last_checked }

remote_access_models[] { id, vendor_id?, model, description,
                         typical_components[], risks[],
                         source_url, confidence, verification, last_checked }

oui_prefixes[]         { prefix, vendor_id, source_url, confidence, last_checked }
                         # aktuell leer, siehe top-level "oui_prefixes_note"
```

**Kategorien (`category`):** `store_supervisor` (Verbund-/Store-Manager), `rack_controller`, `case_controller`, `bms_gateway`, `cloud_monitoring`, `protocol_gateway`, `compressor_electronics`.

**Go-Hinweis:** alle Felder sind optional außer den Pflichtfeldern aus 0.1; `encoding/json` ignoriert unbekannte Felder, daher ist eine additive Schemaerweiterung ohne Bruch möglich. Der Dienst sollte beim Laden validieren: `schema_version` vorhanden, `confidence` im Enum, `last_checked` gesetzt — sonst Eintrag verwerfen und als `low`-Confidence-Datensatz loggen, nicht stillschweigend übernehmen.

---

## 1. Belegstufen (auch hier)

`BELEGT` = Volltext geprüft · `BERICHTET` = Sekundärquelle, nicht hersteller-/behördenbestätigt · `UNBESTÄTIGT` = plausibel, aber nicht belegt — wird im Katalog als `low` geführt und in der UI nicht als Fakt dargestellt.

---

## 2. Die Kälte-Supervisoren: die eigentliche Angriffsfläche

Der Oktober-/November-2026-Vorfall hat die Kategorie klar definiert: **Store-Supervisoren** (Verbund-Manager mit eingebettetem Webserver) sind die Kronjuwelen. Nicht die einzelnen Kühlstellenregler, nicht die Verdichter — der Supervisor bündelt Konfiguration, Zeitpläne, Abtauprogramme und Benutzer und ist über Web erreichbar.

### 2.1 Danfoss (DK) — AK-System

| Merkmal | Befund | Belegstatus | Quelle |
|---|---|---|---|
| Produktfamilien | **AK-SM 800**, **AK-SM 800A**, **AK-SC 355** (Store-/Systemmanager) | `BELEGT` | [CERT-FR](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/), [CISA ICSA-25-140-03](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03) |
| Management-Oberfläche | eingebetteter Webserver mit UI **„StoreView“** (HTTP/HTTPS); Architektur: externes nginx → `sm_fcgi_app` → internes nginx → `sm_app`/`Task_Web` | `BELEGT` | [Claroty Team82](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers) |
| Lifecycle | AK-SM 800 EOL **Mai 2021**; AK-SC 355 **2016** ausgelaufen; AK-SM 800A aktuell | `BERICHTET` (Danfoss-Aussage, referiert) | [The Hacker News](https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html) |
| Update-Weg | signierte `.spk`-Pakete über Danfoss-Download; Upgrade 3.x → 4.x → 5.3.x; kein Downgrade von 5.3.x; „Strict Session Control“ (HTTPS Pflicht) ab 4.0 standardmäßig | `BERICHTET` + `BELEGT` (CISA-Mitigation-Link) | [CISA](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03), [HN](https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html) |
| CVEs | CVE-2025-41450 (Auth-Bypass, 8.2), CVE-2025-41451 (Command Injection, 7.6), CVE-2025-41452 (nginx-Konfig-DoS, 5.4); Fix R4.2/R4.3.1 | `BELEGT` | [CISA](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03), Danfoss [DSA-2025-03-01](https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-03-01/), [DSA-2025-08-01](https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-08-01/) |
| Fernwartung | Hersteller-/Fachbetriebszugriff über die StoreView-Weboberfläche; CERT-FR verlangt Zugriff nur über VPN/geschütztes Netz, IP-Filterung nur als Notlösung | `BELEGT` | [CERT-FR](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/) |
| Feldbus-/BMS-Protokolle | **Nicht belegt.** In den geprüften Quellen (CERT-FR, CISA, Claroty, Presse) wird kein Modbus-/BACnet-/LON-Detail für AK-SM genannt. Nicht raten. | `UNBESTÄTIGT` | – |

**Danfoss-Cloud-Monitoring (Alsense) und Reglerfamilien EKC/ECL:** In dieser Recherche **nicht primärquelllich belegt** — die Danfoss-Seiten lieferten durchgehend HTTP 403/WAF, die Quellenlage zu Alsense, EKC (Kühlstellenregler) und ECL (Heizungsregler) bleibt daher bei Sekundärnennungen. Diese Familien stehen **nicht** im Katalog, bis eine belastbare Quelle vorliegt. `UNBESTÄTIGT`

### 2.2 Copeland (US) / Emerson / Dixell (IT) — XWEB, E2, E3, Site Supervisor

| Merkmal | Befund | Belegstatus | Quelle |
|---|---|---|---|
| Betroffene Produkte im Vorfall | **Copeland XWEB**, **Dixell XWEB** (Kälte-Supervisoren) — von CERT-FR offiziell als betroffen gelistet | `BELEGT` | [CERT-FR](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/) |
| Hardening-Leitfaden | Dixell hat im Oktober 2026 „Recommandations pour une utilisation sécurisée des superviseurs XWEB v1.0“ veröffentlicht (von CERT-FR verlinkt); Inhalt hier nicht geprüft | `BELEGT` (Existenz), Inhalt `UNBESTÄTIGT` | [Dixell-PDF](https://dixell.fr/wp-content/uploads/2026/10/Recommandations-pour-une-utilisation-securisee-des-superviseurs-XWEB-v1.0.pdf) |
| Supervisory-Plattform | **E3** (Nachfolger von E2 „Site Supervisor“); zentrale Filial-Steuerung/Überwachung von Kälteanlagen | `BELEGT` | [Copeland E3](https://www.copeland.com/en-vn/products/controls-monitoring-systems/facility-controls-electronics/facility-and-system-controls/documents/supervisory-e3) |
| Protokolle (belegt) | **BACnet MSTP** für E2/E3 (eigenes Doku „BACnet MSTP Network Wiring for E2 and E3“); **SOAP/XML**-Schnittstelle („Supervisory Controller SOAP Installation Instructions“); E-Mail-/SMS-Alarme | `BELEGT` (Dokumenttitel der Hersteller-Doku) | ebenda |
| Update-Weg | Firmware-/Application-Dateien („ADF“) per **USB**-Upload; Release Notes je Version (2.2xF01–2.33F01/02); separates „Security Update Advisory for Supervisor Controllers“ | `BELEGT` (Dokumente existieren) | ebenda |
| Sicherheits-Advisories | „026-4296 Security Update Advisory for Supervisor Controllers“, „Password Standards for Login Security“, „Supervisory Controller Password Management Guide“ existieren als Herstellerdokumente | `BELEGT` (Existenz) | ebenda |
| CVEs | In dieser Recherche **keine** Copeland-/Dixell-CVE mit behördlicher Quelle im Volltext verifiziert. Der Suchtreffer „CVE-2026-24517“ (cve.armis.com) wurde nicht geprüft → nicht in den Katalog. | `UNBESTÄTIGT` | – |

**Einordnung:** Copeland/E2/E3 ist der US-geprägte Gegenpart zu Danfoss AK-SM. Für DE/EU ist die Relevanz über Filialisten mit internationalem Bestand und über Dixell (weit verbreitete Kühlstellenregler) hoch.

### 2.3 Carel (IT) — pCO, pRack/Rack-Controller, RED optimise, tERA

| Merkmal | Befund | Belegstatus | Quelle |
|---|---|---|---|
| Produktfamilien (Retail) | pCO-/pYC-Programmierbare Steuerungen, **Compressor-Rack-Controller**, Controller für Kühlmöbel/Kühlräume, „Total Store“-Lösung, IoT-Gateways | `BELEGT` (Portfolio-Navigation) | [Carel](https://www.carel.com/reducing-energy-consumption-and-operational-costs-in-buildings) |
| Remote-Monitoring/Cloud | **RED optimise** (Digitalplattform), **RED control** (App), **tERA** (Remote-Monitoring-Service), „Gateway IoT“, lokale Monitoringsysteme | `BELEGT` (Portfolio) | ebenda |
| BMS-/Feldbus-Anbindung | eigene Kategorien „BMS (Building Management System)“ und „FieldBus“; konkrete Protokolle/Ports nicht im Volltext geprüft | `UNBESTÄTIGT` | ebenda |
| Fernwartung | Remote-Expert-/Digital-Service-Angebote des Herstellers, tERA-Monitoring → Dienstleister-/Herstellerzugriff ist Teil des Geschäftsmodells | `BELEGT` (Existenz der Services) | ebenda |
| CVEs | Suchtreffer auf `cve.ics-csirt.io` für `carel` / `pcoweb_card_firmware` vorhanden, aber **nicht im Volltext geprüft** → keine CVE-IDs in den Katalog aufgenommen. | `UNBESTÄTIGT` | – |

**pRack/μRack/boss-Hinweis:** Die konkreten Modellbezeichnungen „pRack“, „μRack“ und „boss“ ließen sich in den geprüften Carel-Seiten nicht als eigenständige Produktnamen verifizieren (die Portfolio-Navigation führt „Compressor racks“, „pCO range“, „Total store“, „RED optimise“, „tERA“). Deshalb im Katalog als `low`-Confidence-Synonym, **nicht** als Fakt. `UNBESTÄTIGT`

### 2.4 Weitere DE/EU-relevante Hersteller (bewusst mit niedrigerer Belegstufe)

| Hersteller | Rolle im Filialbild | Beleglage in dieser Recherche | Katalog-Confidence |
|---|---|---|---|
| **RDM** (Resource Data Management, UK) | Kälte-/Gebäudecontrolling, Retail-Monitoring, „HVACR Control & Monitoring Solutions“ | Nur Katalog-PDF als Suchtreffer, Volltext nicht geprüft → Protokolle/Ports `UNBESTÄTIGT` | `low` |
| **Eliwell** (Schneider Electric, IT) | Kühlstellenregler, Kälte-Steuerungen; breite DE/EU-Installationsbasis | Nur Hersteller-„About“-Seite als Suchtreffer; keine geprüfte Protokoll-/Fernwartungsdoku | `low` |
| **TEKO** (DE, Kältetechnik) | Verbund-/Kälteregler, Leistungsregelung, deutscher Markt | Nur `tekopost`-PDF als Suchtreffer; keine geprüfte IT-Schnittstellendoku | `low` |
| **Bitzer** (DE) | Verdichter-/Kältemittel-Komponenten; teils eigene Elektronik | Keine geprüfte OT-Schnittstellen-/Fernwartungsquelle gefunden | `low` / `UNBESTÄTIGT` |
| **GEA** (DE) | Kälteanlagen, gewerbliche Kühlung (Anlagenbau) | Keine geprüfte OT-Schnittstellenquelle in dieser Recherche | `low` |
| **Günther** (DE) | Wärmetauscher/Kältetechnik-Komponenten | Keine geprüfte OT-Schnittstellenquelle | `low` |
| **Wurm** (DE) | Kälteanlagenbau/Systemtechnik | Keine geprüfte OT-Schnittstellenquelle | `low` |
| **Systemair** (SE) | Lüftung/Klima, z. T. Gebäudetechnik-Schnittstellen | Keine geprüfte OT-Schnittstellenquelle | `low` |

**Wichtige Einordnung:** Komponentenhersteller (Verdichter, Wärmetauscher) sind für Discovery **nachrangig** — sie haben typischerweise keinen eigenen IP-Stack. Für die Filialarchitektur entscheidend sind die **Supervisor-/Regler-Ebene** (Danfoss, Copeland/Dixell, Carel, RDM, Eliwell, TEKO) und die **BMS-Ebene** (BACnet/IP). Genau diese Reihenfolge soll der MVP abdecken.

---

## 3. Protokoll- und Portmuster der Gerätelandschaft

| Muster | Wo im Filialbild | Belegstatus |
|---|---|---|
| **Eingebetteter Webserver (HTTP/HTTPS) als Management-Interface** | Kälte-Supervisoren (StoreView, XWEB), teils BMS-Gateways | `BELEGT` ([CERT-FR](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/), [Claroty](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)) |
| **BACnet MSTP** (Feldbus, nicht IP) | Copeland E2/E3-Anbindung | `BELEGT` ([Copeland-Doku](https://www.copeland.com/en-vn/products/controls-monitoring-systems/facility-controls-electronics/facility-and-system-controls/documents/supervisory-e3)) |
| **SOAP/XML-API** | Copeland-Supervisor-Integration | `BELEGT` (Dokumenttitel) |
| **Modbus/TCP ohne native Auth/Verschlüsselung** | generisches OT-Muster, international aktiv gescannt | `BELEGT` für Protokolleigenschaft ([Xona](https://www.xonasystems.com/industry-advisories/global-modbus/tcp-probing-campaign-reinforces-ot-exposure-risk)) |
| **HTTP/HTTPS-Cloud-Gateways** (Herstellerportale) | Carel RED/tERA, Danfoss-Download-/Monitoringportale | `BELEGT` für Existenz der Portale, Ports `UNBESTÄTIGT` |
| **Vendor-VPN / Always-on-Fernwartung** | „unmonitored, always-on vendor VPNs“ als Retail-Problem benannt | `BELEGT` als Problembeschreibung ([Claroty Retail](https://claroty.com/commercial-cybersecurity/retail)) |

**Wichtig:** Die in dieser Recherche belegten **Ports** beschränken sich auf die Protokollkonventionen (siehe `protocol-support-matrix.md`). Herstellerspezifische Management-Ports (z. B. abweichende HTTPS-Ports an Kälte-Supervisoren) konnten nicht verifiziert werden — der passive Collector muss daher **port-agnostisch** auf HTTP/HTTPS-Verhalten und Protokoll-Signaturen erkennen, nicht auf feste Ports vertrauen.

---

## 4. Fernwartungsmodelle (DE/EU-Praxis)

| Modell | Beschreibung | Belegstatus | Risiko |
|---|---|---|---|
| **Direkte Web-Exposition** | Supervisor-Panel direkt aus dem Internet erreichbar (Portfreigabe/NAT) | `BELEGT` (CERT-FR, Censys) | höchstes Risiko; war Kern des Frankreich-Vorfalls |
| **IP-Whitelisting beim Kältefachbetrieb** | Firewall-Regel nur für IPs des Dienstleisters | `BELEGT` (CERT-FR nennt es als Notlösung, nicht dauerhaft) | falsche Sicherheit, IP-Wechsel, geteilte IPs |
| **VPN in das Filialnetz** | Dienstleister baut VPN auf, danach breiter Netzzugriff | `BELEGT` als empfohlene Mindestlösung (CERT-FR) | laterale Bewegung bei fehlender Segmentierung |
| **Hersteller-Cloud-Portal** | Supervisor sendet Telemetrie an Herstellerportal; Wartung über Portal | `BELEGT` für Existenz (Carel RED/tERA), Datenflussdetails `UNBESTÄTIGT` | Drittparteirisiko, Datenabfluss, Account-Kompromittierung |
| **Always-on Vendor-VPN** | permanenter Tunnel für Fernwartung | `BELEGT` als Problembeschreibung ([Claroty Retail](https://claroty.com/commercial-cybersecurity/retail)) | unmonitorierte Dauerzugänge |
| **4G-Router-Brücke** | Mobilfunkrouter im Schaltschrank als Fernwartungszugang | `UNBESTÄTIGT` — plausibel, in dieser Recherche nicht belegt | Default-Credentials, Portfreigaben |

**Produktfolgerung:** Modul C (Secure Maintenance Access) muss **Zugriffsbeziehungen und Zeitfenster** sichtbar machen, nicht Zugänge selbst bereitstellen. Die belegten Modelle liefern die Baseline-Regeln: neuer Kommunikationspartner zu einem Supervisor außerhalb eines freigegebenen Wartungsfensters = Alert.

---

## 5. Update- und Lifecycle-Wege (für Integrity/Advisory)

| Hersteller | Update-Weg | Belegstatus |
|---|---|---|
| Danfoss AK-SM 800A | signierte `.spk`-Pakete, manueller Upgrade-Prozess, kein Downgrade ab 5.3.x, „Strict Session Control“ ab 4.0 | `BERICHTET`/`BELEGT` (CISA-Mitigation-Link) |
| Danfoss AK-SM 800 / AK-SC 355 | **kein Update mehr** (EOL 2021 / 2016) | `BERICHTET` |
| Copeland E2/E3/Site Supervisor | Firmware/Application per USB (ADF-Datei), Release Notes, Security Update Advisories | `BELEGT` (Dokumente) |
| Copeland/Dixell XWEB | Hersteller-Hardening-Leitfaden 10/2026; Security-Update-Bulletin (Suchtreffer, Inhalt ungeprüft) | `BELEGT` (Existenz) / `UNBESTÄTIGT` (Inhalt) |
| Carel | Plattform-/Gateway-Updates über Hersteller- und Serviceportale | `UNBESTÄTIGT` (kein geprüfter Detailbeleg) |

**Konsequenz für Modul F/G:** Firmware-Stand ist bei Kälte-Supervisoren **nur** über freigegebene Read-only-Quellen (Web-UI-Abfrage, Hersteller-Download, Betreiberangabe) erfassbar. Ein automatischer Firmware-Abgleich gegen eine CVE-Datenbank ist nur mit Confidence-Wert zulässig — die Geräte liefern ihre Version nicht zuverlässig passiv.

---

## 6. OUI-Prefixe — bewusst leer

Für eine MAC-basierte Herstellererkennung wären IEEE-OUI-Zuordnungen nötig. In dieser Recherche wurde **kein** OUI-Prefix primärquelllich (IEEE-OUI-Datenbank, Herstellerangabe) verifiziert. Erfundene Prefixe wären ein direkter Verstoß gegen die Belegpflicht und würden die Asset-Klassifizierung systematisch falsch etikettieren.

**Entscheidung:** `oui_prefixes: []` im Katalog, mit `oui_prefixes_note` als Begründung. Discovery klassifiziert im MVP über:
1. passive Protokoll-/Port-Signaturen,
2. HTTP-Titel/Server-Header (z. B. „StoreView“, „XWEB“),
3. Betreiberzuordnung mit `confidence`,
4. optional später: verifizierte OUI-Tabelle aus IEEE-Registry (separater Task).

---

## 7. Offene Lücken

1. Keine geprüfte Protokoll-/Port-Doku für Danfoss AK-SM (Modbus/BACnet/LON) — Herstellerportale liefern 403/WAF.
2. Keine geprüfte CVE-Basis für Carel, Emerson/Dixell, Eliwell, RDM — nur Suchtreffer.
3. Carel-Produktnamen „pRack/μRack/boss“ ließen sich nicht durchgängig verifizieren; als `low` geführt.
4. Danfoss Alsense, Emerson-Cloud-Monitoring, GEA/Günther/Wurm/Bitzer-Schnittstellen: keine belegte Quelle in dieser Recherche.
5. 4G-Router-/Mobilfunkmodelle: unbelegt.
6. DE-spezifische Installationsbasis (welche Marken dominieren in DE-Filialen) ist nicht belegt — dafür wäre eine Betreiber-/Fachbetriebsbefragung nötig, keine Web-Recherche.

---

## 8. Quellen (Abrufdatum 2026-11-03)

1. CERT-FR — Alert CERTFR-2026-ALE-012 — https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/
2. CISA — ICSA-25-140-03 Danfoss AK-SM 8xxA — https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03
3. Claroty Team82 — Danfoss AK-SM 800A Research — https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers
4. The Hacker News — French supermarket controller attack — https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html
5. Copeland — E3 Supervisory Control Dokumente — https://www.copeland.com/en-vn/products/controls-monitoring-systems/facility-controls-electronics/facility-and-system-controls/documents/supervisory-e3
6. Carel — Produktportfolio/Retail — https://www.carel.com/reducing-energy-consumption-and-operational-costs-in-buildings
7. Dixell — XWEB-Hardening-Leitfaden (via CERT-FR) — https://dixell.fr/wp-content/uploads/2026/10/Recommandations-pour-une-utilisation-securisee-des-superviseurs-XWEB-v1.0.pdf
8. Danfoss — Security Advisories — https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/
9. Claroty — Retail Cybersecurity — https://claroty.com/commercial-cybersecurity/retail
10. Xona Systems — Modbus/TCP-Exposition — https://www.xonasystems.com/industry-advisories/global-modbus/tcp-probing-campaign-reinforces-ot-exposure-risk
11. RDM — HVACR-Katalog (nur Suchtreffer) — https://www.resourcedm.com/media/wytf0ftg/rdm-catalogue-full-collection-v1-en_gb.pdf
12. Eliwell — Herstellerprofil (nur Suchtreffer) — https://www.eliwell.eu/en/about-eliwell-france-s1.html
13. TEKO — Fachinformation (nur Suchtreffer) — https://teko-gmbh.com/wp-content/media/tekopost-9.pdf


---

## 9. Laufzeit-Katalog (Alpha 0.3.0-alpha.1)

- `data/ot-catalog/` ist Paketbestandteil (`vendors.json`, `write-surface.json`,
  `regulatory-context.json`).
- Discovery/API/UI nutzen den Katalog zur Klassifikation. Neue Endpunkte: `GET /api/v1/vendors`,
  `/api/v1/vendors/{id}`, `/api/v1/regulatory-context`.
- Der Katalog ist **kein Auto-Allow**: er ersetzt keine Freigabe, keine Whitelist und keine
  Read-before-Write-Prüfung. Unbekannte Geräte bleiben unbekannt.
- Katalog-Updates sind Datenupdates; sie werden auditiert dokumentiert und wirken nicht automatisch
  als Schreibfreigabe.
- **Pfad und Fallbacks:** `GEDEFENSE_OT_CATALOG` darf auf `vendors.json` oder das Katalogverzeichnis
  zeigen; `write-surface.json` und `regulatory-context.json` werden als Geschwisterdateien geladen.
  Ohne Env-Variable gelten `data/ot-catalog/vendors.json` und relative Fallbacks. Fehlende Dateien
  erzeugen Warnungen statt eines Startabbruchs.
- **Fehlerverhalten:** fehlt/ist `vendors.json` ungültig oder zu groß (>8 MiB), ist der Katalog
  deaktiviert (`enabled:false`, leere Listen, Warnungen; HTTP 200, kein 500). Teilausfälle
  (`write-surface`/`regulatory` fehlen) lassen den Katalog aktiv, betroffene Listen bleiben leer und
  werden als Warnung gemeldet. Unbekannte `family_id` bei aktivem Katalog ⇒ 404.
- **Diagnose:** `retaild check` meldet Katalog-Warnungen in `warnings[]` (deaktiviert, fehlende
  Dateien, Ladefehler), ohne `ok`/Checks zu verändern.
