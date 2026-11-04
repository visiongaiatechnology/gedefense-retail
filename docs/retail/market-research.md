# GeDefense Retail — Markt- und Angriffslage (EU/DE)

**Produktlinie:** VisionGaiaTechnology · GeDefense Retail — ColdChain & Store Infrastructure Security
**Dokumenttyp:** Research-Grundlage für Katalog, Detektionsregeln, Produktpositionierung
**Recherchestand / Abrufdatum aller Quellen:** **2026-11-03**
**Autor:** ot-researcher (Task task-1)

---

## 0. Methodik und Belegstatus

- Ausschließlich öffentlich zugängliche Quellen; jede Kernaussage mit URL und Abrufdatum.
- **Belegstufen:** `BELEGT` = Primär- oder Fachquelle im Volltext geprüft · `BERICHTET` = Medienbericht, von der zuständigen Behörde/dem Hersteller nicht bestätigt · `EINORDNUNG` = eigene Schlussfolgerung des Autors, keine Tatsachenbehauptung.
- Keine erfundenen CVEs, OUIs, Zertifizierungen oder Opferzahlen. Widersprüchliche Zahlen werden mit Quelle nebeneinandergestellt, nicht geglättet.
- Was nicht belegt ist, wird als **offen** markiert (§7).

---

## 1. Management Summary — die fünf entscheidenden Befunde

1. **Die Kältetechnik von Supermärkten ist 2026 real und massenhaft angegriffen worden.** In der Nacht 11./12.10.2026 manipulierten Angreifer Ferndiagnose-/Verbundregler in mehreren hundert französischen Filialen, schalteten Abtau-/Heizbetrieb ein und trieben Temperaturen laut Berichten bis ~50 °C. Es folgten Wellen in Belgien, Luxemburg, Schweden und Estland (Anfang November 2026). Der französische Staat sprach von rund 700 betroffenen Märkten. **Quellen:** [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su), [SecurityAffairs](https://securityaffairs.com/202260/security/another-fridge-cyberattack-hits-european-supermarkets-this-time-in-belgium-luxembourg-sweden-and-estonia.html), [ThaiCERT](https://www.thaicert.or.th/en/2026/11/03/cyberattacks-disrupt-supermarket-refrigeration-systems-across-europe-risking-product-loss-and-fires/).
2. **Der Angriffsweg war die Management-Oberfläche, nicht der Feldbus.** Betroffen waren Store-Manager/Supervisoren (Danfoss AK-SM/AK-SC, Copeland/Dixell XWEB), die über Webinterfaces aus dem Internet erreichbar waren; Zugangsdaten/Default-Passwörter und teils veraltete Firmware sind die berichteten Faktoren. **Quelle:** [CERT-FR CERTFR-2026-ALE-012](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/) (offiziell betroffene Systeme), [The Hacker News](https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html).
3. **Die Exposition ist messbar.** Censys zählte am 11.10.2026 **1.825** aus dem Internet sichtbare Danfoss-StoreView-Management-Panels in Frankreich; am 14.10. waren es noch **537**. Claroty Team82 fand zuvor rund **2.765** exponierte AK-SM-800A-Interfaces. **Quellen:** [Censys](https://censys.com/blog/frostbitten-in-france-a-danfoss-storeview-internet-exposure-report/), [Claroty Team82](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers).
4. **Es gibt eine belegte Schwachstellenkette — und sie ist nicht der behauptete Einstiegspunkt.** Die drei 2025 gepatchten AK-SM-800A-Schwachstellen (Auth-Bypass durch „code of the day“, Command Injection, nginx-Konfigurationsinjektion) sind dokumentiert und mit CVE-IDs belegt; vorläufige Einschätzungen deuten jedoch darauf hin, dass sie **nicht** der Vektor der Oktober-Angriffe waren. **Quellen:** [Claroty Team82](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers), [CISA ICSA-25-140-03](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03), [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su) (unter Berufung auf teiss).
5. **Marktlücke:** Die großen OT-Security-Plattformen (Claroty, Armis, Nozomi, Dragos) adressieren Retail inzwischen, aber mit Enterprise- und Plattformzuschnitt. Ein **vendor-neutraler, local-first, rein passiver Read-only-Ansatz für den DE/EU-Mittelstand** — Kälte- + Netzwerk- + Wartungszugriffs-Korrelation in einer Filiale, ohne Cloud-Zwang und ohne Schreibzugriff auf Anlagen — ist belegt nicht abgedeckt und passt exakt auf die GeDefense-Produktgrenzen (§6).

---

## 2. Der Primärfall: Kälteangriffe auf europäische Supermärkte 2026

### 2.1 Ablauf Frankreich (Nacht 11./12. Oktober 2026)

| Fakt | Belegstatus | Quelle |
|---|---|---|
| Angreifer manipulierten Kältesysteme in mehreren hundert französischen Supermärkten, Temperaturen stiegen auf bis zu ~50 °C | `BERICHTET` | [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su), [SecurityAffairs](https://securityaffairs.com/202260/security/another-fridge-cyberattack-hits-european-supermarkets-this-time-in-belgium-luxembourg-sweden-and-estonia.html) |
| Laut französischem Finanzminister Roland Lescure ca. **700 Läden** betroffen | `BERICHTET` | [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su) (Berufung auf KSL/AP) |
| Betroffene Ketten: Intermarché/Netto (Les Mousquetaires), Coopérative U, Carrefour, Monoprix, E.Leclerc | `BELEGT` (Unternehmensaussagen) | [The Hacker News](https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html) |
| Intermarché/Netto: ≥300 Standorte (AFP) bzw. ~150 (Reuters); Coopérative U: 80 von ~2.000; Carrefour: 80; Monoprix: ~30; E.Leclerc: mehrere | `BERICHTET` (Widersprüche offen) | [The Hacker News](https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html), [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su) |
| Schäden: verdorbene Ware, Kosten je Markt nach Schätzungen von einigen zehntausend bis zu 200.000 €; Les Mousquetaires erwartete Verluste im zweistelligen Millionen-Euro-Bereich; die Pariser Staatsanwaltschaft sprach auch von **Bränden** | `BERICHTET` | [Reuters via Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su), [SecurityAffairs](https://securityaffairs.com/202260/security/another-fridge-cyberattack-hits-european-supermarkets-this-time-in-belgium-luxembourg-sweden-and-estonia.html) |
| Physischer Mechanismus: Umschalten auf **Defrost-Modus**, Betriebsheizung statt Kühlung; bei E.Leclerc soll eine Tiefkühl-Einstellung von −22 °C auf 150 °C geändert worden sein, mit Änderungen „zwei- bis dreimal pro Sekunde“ | `BERICHTET` | [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su) (Berufung auf Le Monde), [ThaiCERT](https://www.thaicert.or.th/en/2026/11/03/cyberattacks-disrupt-supermarket-refrigeration-systems-across-europe-risking-product-loss-and-fires/) |
| Kein bestätigter Täter, keine bestätigte Attribution; ANSSI/CERT-FR beteiligt, Pariser Cybercrime-Staatsanwaltschaft ermittelt | `BELEGT` (Nicht-Bestätigung) | [CERT-FR](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/), [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su) |

**Wichtig für die Produktkommunikation:** Ein Angriff dieser Art ist *kein* Kühlketten-Zufall, sondern eine **cyber-physische Manipulation der Steuerungsebene**. Genau die Korrelation „Zugriff → Konfigurationsänderung → Temperaturverlauf“ ist das GeDefense-Retail-Kernversprechen — nicht die Behauptung, Kühlkettenausfälle verhindern zu können.

### 2.2 Offiziell betroffene Systeme (CERT-FR)

Der französische CERT-FR hat am 12.10.2026 eine Warnung veröffentlicht und am 13.10. und 16.10. erweitert. Gelistete betroffene Systeme (`BELEGT`):

- **Copeland XWEB**
- **Danfoss Serie AK-SC**
- **Danfoss Serie AK-SM**
- **Dixell XWEB**

CERT-FR weist ausdrücklich darauf hin, dass die Internet-Exposition einer Management-Oberfläche gegen gute Praxis verstößt, empfiehlt für Danfoss u. a. **Firmware-Update, Modus „Strict“ und Änderung der Default-Passwörter** und stellt fest, dass Angriffskampagnen wahrscheinlich weiterlaufen. Quelle: [CERTFR-2026-ALE-012](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/).

### 2.3 Der exponierte Bestand (Quantifizierung)

| Befund | Zahl | Belegstatus | Quelle |
|---|---|---|---|
| Aus dem Internet sichtbare Danfoss-StoreView-Panels, Frankreich, 11.10.2026 | 1.825 | `BELEGT` (Censys-Messung) | [Censys](https://censys.com/blog/frostbitten-in-france-a-danfoss-storeview-internet-exposure-report/), referiert in [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su) |
| Dieselben Panels, 14.10.2026 (nach Gegenmaßnahmen) | 537 | `BELEGT` | ebenda |
| Exponierte Danfoss AK-SM-800A-Management-Interfaces (Censys-Scan, 2025) | ~2.765 | `BELEGT` | [Claroty Team82](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers) |

Der starke Rückgang zwischen 11. und 14.10. ist laut Censys über alle Patch-Stände hinweg sichtbar — ein Indiz dafür, dass primär die **Exposition** beseitigt wurde, nicht die Firmware aktualisiert. `BERICHTET`

### 2.4 Die belegte Schwachstellenkette (AK-SM 800A, gepatcht 2025)

Claroty Team82 analysierte die Firmware des AK-SM 800A und veröffentlichte drei Schwachstellen; Danfoss hat sie mit den Releases R4.2 bzw. R4.3.1 behoben (`BELEGT`):

| CVE | Typ | CVSS v3.1 | Betroffene Versionen | Fix |
|---|---|---|---|---|
| CVE-2025-41450 | Auth-Bypass über „code of the day“ (zeitbasierte Passwortgenerierung) | 8.2 | < R4.2 | R4.2 |
| CVE-2025-41451 | Command Injection (Alarm-to-Mail-Konfiguration → OS-Shell) = post-auth RCE | 7.6 | < 4.3.1 | R4.3.1 |
| CVE-2025-41452 | Externe Kontrolle der nginx-Konfiguration → DoS | 5.4 | < 4.3.1 | R4.3.1 |

**Quellen:** [Claroty Team82](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers), [CISA ICSA-25-140-03](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03), JVN [JVNVU#96395440](http://jvn.jp/vu/JVNVU96395440/index.html) (Sekundärverweis).

**Einordnung:** Diese Kette zeigt exemplarisch, dass Supermarkt-Kälte-Supervisoren **vollwertige, oft ungehärtete Webserver mit OS-Zugriff** sind. Für GeDefense Retail ist sie ein Katalog-/Advisory-Use-Case, aber ausdrücklich **kein** behaupteter Exploit-Pfad des Oktober-Angriffs: Berichte deuten darauf hin, dass die Schwachstellen nicht der Einstieg waren (`BERICHTET`, [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su)).

### 2.5 Folgewellen (Belgien, Luxemburg, Schweden, Estland, Anfang November 2026)

| Land | Betroffene | Belegstatus | Quelle |
|---|---|---|---|
| Belgien/Luxemburg | Ahold Delhaize (Delhaize, laut Berichten ~40 belgische Filialen), Colruyt (5 Filialen); Le Soir berichtete über Dutzende Delhaize-/Carrefour-Märkte | `BERICHTET` | [SecurityAffairs](https://securityaffairs.com/202260/security/another-fridge-cyberattack-hits-european-supermarkets-this-time-in-belgium-luxembourg-sweden-and-estonia.html), [ThaiCERT](https://www.thaicert.or.th/en/2026/11/03/cyberattacks-disrupt-supermarket-refrigeration-systems-across-europe-risking-product-loss-and-fires/) |
| Schweden | ICA (u. a. Sjöbo, Baronen/Hägerstensåsen), Coop (6 Filialen); schwedisches NCSC bestätigt Arbeit an mehreren Kältevorfällen; Temperaturen teils bis 80 °C (Beraterangabe, abweichend von Polizeiangaben) | `BERICHTET` | [SecurityAffairs](https://securityaffairs.com/202260/security/another-fridge-cyberattack-hits-european-supermarkets-this-time-in-belgium-luxembourg-sweden-and-estonia.html), [ThaiCERT](https://www.thaicert.or.th/en/2026/11/03/cyberattacks-disrupt-supermarket-refrigeration-systems-across-europe-risking-product-loss-and-fires/) |
| Estland | Supermarktkette (nicht namentlich genannt), Kältedienstleister Kitman Coldtech, Systeme auf 50 °C gesetzt | `BERICHTET` | [SecurityAffairs](https://securityaffairs.com/202260/security/another-fridge-cyberattack-hits-european-supermarkets-this-time-in-belgium-luxembourg-sweden-and-estonia.html) |
| Täter/Verbindung | **Nicht bestätigt**, ob dieselben Akteure; keine Claims | `BELEGT` (Nicht-Bestätigung) | [ThaiCERT](https://www.thaicert.or.th/en/2026/11/03/cyberattacks-disrupt-supermarket-refrigeration-systems-across-europe-risking-product-loss-and-fires/) |

**Disziplin-Hinweis (wichtig für Alarmtexte):** Ähnliche Symptome ≠ gleiche Ursache. Barracuda dokumentiert, dass weder die Hannaford-/Ahold-Delhaize-Störungen noch die US-Commissary-Kühlausfälle (August 2026, ≥7 Standorte; Pentagon behandelte sie Ende Oktober als *mutmaßlichen* Cyberangriff) belastbar mit den Frankreich-Angriffen verbunden sind (`BERICHTET`: [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su), [Reuters-Meldung darin](https://www.reuters.com/technology/pentagon-treating-military-base-freezer-malfunctions-suspected-cyberattack-2026-10-29/)). GeDefense muss Beobachtung, Hypothese und empfohlene Prüfung strikt trennen.

### 2.6 EOL- und Patch-Realität der Kälte-Supervisoren

Laut Danfoss-Aussagen (referiert bei The Hacker News, `BERICHTET`):

- **AK-SM 800:** End-of-Life seit **Mai 2021**, keine Software-/Security-Updates mehr.
- **AK-SC 355:** 2016 ausgelaufen, keine Updates.
- **AK-SM 800A:** aktuelles Modell; einige betroffene Geräte liefen mit veralteter Firmware. Ab Version 4.0 ist „Strict Session Control“ standardmäßig aktiv (HTTPS verpflichtend); ab 4.3.1 sind die drei CVEs geschlossen.
- Danfoss-Newsletter 10/2025: In **2022** wurden 16 russische Supermärkte mit AK-SM 800 und 40 israelische Filialen angegriffen; alle 40 israelischen Märkte hatten laut Newsletter keinen Firewall-/VPN-Schutz.

Quelle: [The Hacker News](https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html); Danfoss-Advisories: [DSA-2025-03-01](https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-03-01/), [DSA-2025-08-01](https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-08-01/).

**Konsequenz für den Produktkatalog:** EOL-Status und Patch-Stand sind für Supermarkt-Kälte-Supervisoren **kritische Asset-Eigenschaften** — nicht optional. Ein Katalog ohne Lifecycle-Daten ist für diese Geräteklasse wertlos.

---

## 3. Weitere dokumentierte Vorfälle und Kampagnen

| Ereignis | Relevanz für Retail-OT | Belegstatus | Quelle |
|---|---|---|---|
| **Target-Breach 2013** — Ermittlungen zu den Systemen eines **HVAC-Dienstleisters** als möglichem Einstieg | Präzedenzfall: Gebäudetechnik-Dienstleister als Sprungbrett in Filial-IT | `BERICHTET` (nur Schlagzeile im Volltext geprüft) | [Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/target-breach-hvac-contractor-systems-investigated) |
| **Blue Yonder Ransomware (Nov 2024)** — Angriff auf Supply-Chain-Softwareanbieter, Auswirkungen bei Retail-/Gastronomiekunden (u. a. Starbucks) | Ransomware im Retail-Ökosystem trifft Warenwirtschaft/Replenishment, nicht Kältetechnik | `BERICHTET` (Titel/Teaser geprüft) | [heise online](https://www.heise.de/en/news/Starbucks-affected-by-cyber-attack-on-software-provider-10177831.html) |
| **Globale Modbus/TCP-Probing-Kampagne (2026)** — koordinierte Recon-/Interaktionsversuche gegen internet-exponierte Modbus-Geräte (Port 502); parallel CISA-Warnung zu iranisch-affiliierten Akteuren gegen exponierte PLCs (April 2026) | Bestätigt: OT-Protokolle bleiben auffindbar und ansprechbar; fehlende native Auth/Verschlüsselung | `BERICHTET` (Industrie-Advisory, referiert Cato Networks/CISA) | [Xona Systems](https://www.xonasystems.com/industry-advisories/global-modbus/tcp-probing-campaign-reinforces-ot-exposure-risk) |
| **Kälteangriffe 2022 (RU/IL)** — 16 russische Supermärkte (AK-SM 800), 40 israelische Filialen ohne Firewall/VPN | Belegt, dass das Muster „Fernzugriff ohne Netzschutz“ älter ist als 2026 | `BERICHTET` (Danfoss-Newsletter, referiert) | [The Hacker News](https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html) |
| **US-Militär-Commissaries (Aug 2026)** — Kühlausfälle an ≥7 Standorten, Pentagon behandelt sie Ende Oktober als mutmaßlichen Cyberangriff; **keine** bestätigte Verbindung zu Europa | Zeigt Ermittlungsunsicherheit und die Notwendigkeit forensischer Beweissicherung | `BERICHTET` | [Barracuda](https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su), [Reuters](https://www.reuters.com/technology/pentagon-treating-military-base-freezer-malfunctions-suspected-cyberattack-2026-10-29/) |

**Nicht gefunden / offen geblieben** (ehrlich benannt): ein belastbarer, offiziell bestätigter Vorfall, in dem gezielt **deutsche** Supermarkt-Kältetechnik kompromittiert wurde. Die deutsche Relevanz leitet sich aus derselben Geräte- und Dienstleisterlandschaft ab (§5), nicht aus einem belegten DE-Vorfall. Diese Lücke muss in der Außenkommunikation offen bleiben.

---

## 4. Typische Angriffspfade (mit Beleggrad)

| # | Angriffspfad | Belegt durch | Belegstatus |
|---|---|---|---|
| A1 | **Direkt exponierte Web-Management-Oberfläche** eines Kälte-Supervisors (StoreView, XWEB) | CERT-FR listet Exposition als Kernproblem; Censys-Messungen; Claroty fand tausende offene Interfaces | `BELEGT` |
| A2 | **Schwache/Default-Credentials, geteilte Technikerzugänge** — Angreifer nutzten laut Berichten erlangte Login-Daten | CERT-FR verlangt Änderung der Default-Passwörter; schwedischer Berater nennt erlangte Login-Daten | `BERICHTET` |
| A3 | **Topologie-/Segmentierungsfehler**: Kältesupervisor hängt am Filial-Internetrouter statt in einem Management-/OT-Netz | 40 israelische Filialen ohne Firewall/VPN (2022); „unmonitored, always-on vendor VPNs“ als Retail-Problem | `BERICHTET` |
| A4 | **Drittdienstleister-/Fernwartungszugang** (Kältefachbetrieb, Hersteller, MSP) | Coopérative U: Märkte sind Kunden der Kältefachbetriebe, nicht von Danfoss; E.Leclerc nennt betroffenen Kälte-Zulieferer; Groupement Mousquetaires nennt Dienstleister | `BELEGT` (Rollenaussagen) |
| A5 | **EOL-Firmware / kein Patchpfad** — AK-SM 800 (EOL 2021), AK-SC 355 (2016) | Danfoss-Aussagen; CERT-FR | `BELEGT` |
| A6 | **Fehlende Protokoll-Authentisierung** — Modbus/TCP ohne native Auth/Verschlüsselung, internet-exponiert | Xona-Advisory; Modbus-Probing-Kampagne | `BELEGT` (Protokolleigenschaft), `BERICHTET` (Kampagnendetails) |
| A7 | **Unsichere Mobilfunk-/4G-Router als Fernwartungsbrücke** (NAT, Portfreigaben, Default-Passwörter) | **In dieser Recherche NICHT belegt.** Plausibles Muster, aber kein geprüfter Vorfallbericht | `OFFEN` |
| A8 | **Manipulation von Temperaturtelemetrie** (eingefrorene Werte, Sensor-Spoofing) | Kein belegter Vorfall in dieser Recherche; als Design-Risiko im Baukonzept §5 Modul D/E gefordert | `OFFEN` |

**Produktfolgerung:** Der MVP muss zuerst A1–A4 sichtbar machen (Exposition, Zugriffsbeziehungen, Wartungsfenster, Lifecycle) — nicht mit A7/A8-Spekulationen starten.

---

## 5. Markt- und Wettbewerbslandschaft

### 5.1 OT-/CPS-Security-Plattformen

| Anbieter | Retail-/Kältebezug | Belegstatus | Quelle |
|---|---|---|---|
| **Claroty** | Eigene Retail-Vertikale; nennt als Retail-Probleme explizit „third-party vendors rely on unmonitored, always-on vendor VPNs“, „unpatchable firmware“, Reklassifizierung von Food-Logistik als CNI; bewirbt „Strict Cold Chain Governance“ (Monitoring verbundener Klima-/Kältesysteme) und Mapping auf **NIS2 / ISA-IEC-62443 / NIST CSF**; hat die Danfoss-CVEs selbst gefunden (Team82) | `BELEGT` | [Claroty Retail](https://claroty.com/commercial-cybersecurity/retail), [Team82](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers) |
| **Armis** | Retail-Solution-Brief „From the Warehouse to the Checkout“; Case Study mit italienischem Lebensmittelhändler (Multicedi) | `BERICHTET` (nur Suchtreffer, Volltext nicht geprüft) | [Armis Solution Brief](https://www.armis.com/solution-briefs/from-the-warehouse-to-the-checkout-armis-centrix-empowers-the-retail-industry/) |
| **Nozomi Networks** | Kein retail-spezifisch geprüfter Volltextbeleg in dieser Recherche; generischer OT-/IoT-Monitoring-Anbieter | `OFFEN` | – |
| **Dragos** | Kein retail-spezifisch geprüfter Volltextbeleg; Fokus Industrie-OT | `OFFEN` | – |

**Einordnung (`EINORDNUNG`):** Diese Plattformen sind funktional stark, aber auf Enterprise-Deployments, zentrale SOC-Integration und häufig auf Cloud-/Managed-Service-Modelle ausgelegt. Für eine deutsche Filiale mit 1–3 Kältesupervisoren, einem BMS und einem Kältefachbetrieb ist das typischerweise überdimensioniert und preislich nicht darstellbar.

### 5.2 Kälte-Monitoring und HACCP-Temperaturüberwachung (komplementär, nicht konkurrierend)

| Kategorie | Anbieter/Beispiele | Rolle | Belegstatus |
|---|---|---|---|
| Kälte-Supervisoren mit Monitoring | Danfoss (AK-SM/AK-SC/StoreView), Copeland/Dixell (XWEB, E2/E3/Site Supervisor), Carel (RED optimise/tERA, pCO-/Rack-/Total-Store-Lösungen) | **Das ist die zu überwachende Ebene** — nicht der Wettbewerber | `BELEGT` für Danfoss/Copeland/Carel ([CERT-FR](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/), [Copeland E3](https://www.copeland.com/en-vn/products/controls-monitoring-systems/facility-controls-electronics/facility-and-system-controls/documents/supervisory-e3), [Carel](https://www.carel.com/reducing-energy-consumption-and-operational-costs-in-buildings)) |
| HACCP-Temperaturmonitoring | u. a. Testo (Food-Retail-Lösungen), Carel tERA, herstellereigene Cloud-Portale | Dokumentation/Compliance-Nachweis; **kein Cybersecurity-Monitoring** | `OFFEN` (Testo-Seite war nicht abrufbar; nicht als geprüft zitiert) |

**Wichtige Positionierungsgrenze:** HACCP-Monitoring beantwortet „war die Temperatur im Rahmen?“. GeDefense Retail beantwortet „**wer** hat **was** an der Steuerung **wie** verändert — und passt das zum Temperaturverlauf?“. Das ist eine andere Frage und rechtfertigt ein eigenes Produkt. GeDefense ersetzt **kein** HACCP-System und darf sich nicht als konformitätsgarantierend positionieren (siehe `regulatory-context.json`).

---

## 6. Warum GeDefense Retail passt (Produktentscheidung)

1. **Der Vorfall bestätigt exakt die GeDefense-Produktgrenzen.** Passiv, read-only, local-first, keine Schreibzugriffe, keine automatische Abschaltung — genau das, was nach dem Frankreich-Vorfall gefordert ist (CERT-FR: Zugriff entfernen/filtern, nicht Anlagen abschalten). `EINORDNUNG`, gestützt auf [CERT-FR](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/).
2. **Die entscheidende Evidenz liegt im Netzwerk, nicht im Gerät.** Wer greift zu, wann, von wo, auf welchen Supervisor — das ist passive Flow-/Protokoll-Metadaten-Auswertung. Genau das kann ein TAP-basiertes Edge-Gateway leisten, ohne die Anlage zu berühren. `EINORDNUNG`
3. **Die Korrelation ist der Burggraben.** Einzelne Signale (offener Port, Temperaturanstieg) sind trivial. „Unbekanntes Wartungsgerät + Supervisor-Zugriff außerhalb Freigabe + plötzlicher Abtau-Modus + Temperaturtrend“ ist die verteidigungsfähige Kette. Baukonzept §5 Modul E liefert die Struktur. `EINORDNUNG`
4. **Der Mittelstand ist unterversorgt.** Deutsche Filialisten mit 30–300 Märkten haben weder ein eigenes OT-SOC noch das Budget für Claroty/Armis-Enterprise-Rollouts, aber dieselbe Gerätelandschaft und dieselbe NIS2-/Lebensmittelhygiene-Pflicht. `EINORDNUNG`
5. **Der Katalog ist Produktbestandteil, nicht Doku.** Die Kombination „welche Gerätefamilie + welcher Lifecycle-Status + welche Management-Oberfläche + welches Wartungsmodell“ ist der Datenvorsprung, den `data/ot-catalog/*.json` liefert. Der Frankreich-Fall zeigt: Betreiber wissen oft nicht, welche Supervisoren mit welchem Firmware-Stand im Netz hängen. `EINORDNUNG`

**Top-Priorisierung für den MVP (aus dieser Recherche):**

| Rang | Hersteller/Geräteklasse | Begründung |
|---|---|---|
| 1 | **Danfoss AK-SM 800/800A/AK-SC 355 (+ StoreView)** | Nachweislich Ziel eines Massenangriffs, dokumentierte CVEs, EOL-Problematik, DE-weit verbreitet |
| 2 | **Copeland/Dixell XWEB** | Von CERT-FR als betroffen gelistet; gleiche Angriffsfläche (Web-Supervisor) |
| 3 | **Carel pCO-/Rack-/Store-Supervisoren + RED/tERA** | Großer EU-Marktanteil im Lebensmittelhandel; Fernmonitoring-Modelle belegt |
| 4 | **Copeland E2/E3/Site Supervisor** | BACnet-/SOAP-Schnittstellen belegt; US-geprägt, in EU präsent |
| 5 | **BMS/Gebäudeleittechnik am Filialrand (BACnet/IP)** | Übergangspunkt zwischen Kälte- und Gebäudewelt |

---

## 7. Offene Unsicherheiten und Research-Gaps

1. **DE-Vorfall unbekannt:** Kein belegter Angriff auf deutsche Supermarkt-Kältetechnik in dieser Recherche. Deutsche Relevanz ist eine Analogie, keine Tatsache.
2. **Kausalität der Oktober-Angriffe offen:** Einstiegsvektor, Täter und Rolle der 2025er CVEs sind nicht bestätigt. Jede Produkt-/Marketingaussage, die den CVE als Ursache nennt, wäre falsch.
3. **Zahlen widersprüchlich:** 700 (Regierung) vs. ~500 (Summe der Einzelaussagen); 300 vs. 150 (Intermarché); 50 °C vs. 80 °C (Schweden). Nicht glätten.
4. **Keine offiziellen IOCs:** CERT-FR hatte (Stand 13.10.2026) keine Indicators of Compromise veröffentlicht. Detektion muss verhaltensbasiert sein, nicht signaturbasiert.
5. **4G-Router-Pfad unbelegt:** Als These im Baukonzept enthalten, hier ohne Primärbeleg. Nicht als Produktclaim verwenden.
6. **Protokolldetails je Hersteller dünn:** Modbus/BACnet-Unterstützung einzelner Gerätefamilien ist herstellerseitig nicht durchgängig frei dokumentiert; Download-Portale sind teils zugangsbeschränkt. Siehe `vendor-landscape.md` Belegstufen.
7. **OUI-Prefixe nicht belegt:** Für eine MAC-basierte Herstellererkennung fehlen in dieser Recherche verifizierbare OUI-Zuordnungen. `oui_prefixes` bleibt deshalb leer (siehe `data/ot-catalog/vendors.json`).
8. **Marktzahlen fehlen:** Es wurden bewusst **keine** Marktvolumina zitiert, weil keine belastbare, frei prüfbare Quelle gefunden wurde. Wer Zahlen braucht, muss sie kostenpflichtig beschaffen.

---

## 8. Quellenverzeichnis (Abrufdatum 2026-11-03)

**Vorfälle/Threat Intelligence**
1. Barracuda Networks Blog — „What managed service providers can learn from the 2026 French supermarket attacks“ (30.10.2026) — https://blog.barracuda.com/2026/10/30/what-managed-service-providers-can-learn-from-the-2026-french-su
2. SecurityAffairs — „Another fridge cyberattack hits European supermarkets…“ (02.11.2026) — https://securityaffairs.com/202260/security/another-fridge-cyberattack-hits-european-supermarkets-this-time-in-belgium-luxembourg-sweden-and-estonia.html
3. ThaiCERT — „Cyberattacks Disrupt Supermarket Refrigeration Systems Across Europe“ (03.11.2026) — https://www.thaicert.or.th/en/2026/11/03/cyberattacks-disrupt-supermarket-refrigeration-systems-across-europe-risking-product-loss-and-fires/
4. The Hacker News — „Attackers Heat French Supermarket Fridges Up to 50 °C by Hijacking Danfoss Controllers“ (13.10.2026) — https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html
5. CERT-FR / ANSSI — Alert CERTFR-2026-ALE-012 (12.–16.10.2026) — https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/
6. Censys — „Frostbitten in France: A Danfoss StoreView Internet Exposure Report“ — https://censys.com/blog/frostbitten-in-france-a-danfoss-storeview-internet-exposure-report/
7. Claroty Team82 — „Freeze the Controller, Defrost the Food“ (09.08.2026) — https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers
8. CISA — ICS Advisory ICSA-25-140-03 „Danfoss AK-SM 8xxA Series (Update A)“ (26.08.2025) — https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03
9. JVN — JVNVU#96395440 (Danfoss AK-SM 8xxA) — http://jvn.jp/vu/JVNVU96395440/index.html
10. Computer Weekly — „Cold chain cyber attacks highlight lack of OT security in retail“ — https://www.computerweekly.com/news/366653380/Cold-chain-cyber-attacks-highlight-lack-of-OT-security-in-retail
11. Xona Systems — „Global Modbus/TCP Probing Campaign Reinforces OT Exposure Risk“ (24.04.2026) — https://www.xonasystems.com/industry-advisories/global-modbus/tcp-probing-campaign-reinforces-ot-exposure-risk
12. heise online — „Starbucks affected by cyber attack on software provider“ — https://www.heise.de/en/news/Starbucks-affected-by-cyber-attack-on-software-provider-10177831.html
13. Dark Reading — „Target Breach: HVAC Contractor Systems Investigated“ — https://www.darkreading.com/cyberattacks-data-breaches/target-breach-hvac-contractor-systems-investigated

**Wettbewerb/Markt**
14. Claroty — Retail Cybersecurity — https://claroty.com/commercial-cybersecurity/retail
15. Armis — Solution Brief „From the Warehouse to the Checkout“ — https://www.armis.com/solution-briefs/from-the-warehouse-to-the-checkout-armis-centrix-empowers-the-retail-industry/

**Hersteller**
16. Copeland — E3 Supervisory Control (Dokumentenliste) — https://www.copeland.com/en-vn/products/controls-monitoring-systems/facility-controls-electronics/facility-and-system-controls/documents/supervisory-e3
17. Carel — Produkt-/Lösungsportfolio (Food Retail, RED optimise, tERA, BMS/FieldBus) — https://www.carel.com/reducing-energy-consumption-and-operational-costs-in-buildings
18. Danfoss — Security Advisories — https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/
19. Danfoss — AK-SM 800A Software / Mitigation (via CISA) — https://sm800a.danfoss.com/sw_shared/SM800A-4.2.4.spk

> Hinweis zur Belegstufe: Die URLs 9, 12, 13, 15 (Armis), 18 und 19 waren nicht im Volltext auswertbar (Paywall/Kurzfassung/JS/WAF); sie stützen nur ausdrücklich als `BERICHTET` markierte Aussagen. URL 14 (Claroty Retail) wurde im Volltext geprüft und ist `BELEGT`. Für Hersteller-Vollbelege siehe `vendor-landscape.md` §2.
