<p align="center">
  <a href="docs/assets/gedefense-logo.png">
    <img src="docs/assets/gedefense-logo.png" alt="GeDefense Retail" width="360">
  </a>
</p>

<h1 align="center">GeDefense Retail</h1>

<p align="center"><strong>ColdChain &amp; Store Infrastructure Security</strong><br>
Passives OT-Monitoring und ein Default-Deny-Gate für den Management-Pfad der Filiale.</p>

<p align="center">
  <a href="https://github.com/visiongaiatechnology/gedefense-retail/releases"><img alt="Release" src="https://img.shields.io/github/v/release/visiongaiatechnology/gedefense-retail?style=flat-square&label=release"></a>
  <img alt="Lizenz: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square">
  <img alt="Go 1.23+" src="https://img.shields.io/badge/go-1.23%2B-00ADD8?style=flat-square&logo=go&logoColor=white">
  <img alt="Plattformen: Linux und Windows" src="https://img.shields.io/badge/platforms-Linux%20%7C%20Windows-444?style=flat-square">
  <img alt="Status: Alpha" src="https://img.shields.io/badge/status-alpha-orange?style=flat-square">
</p>

[English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Italiano](README.it.md) · [Español](README.es.md) · [日本語](README.ja.md) · [中文](README.zh.md) · [Русский](README.ru.md)

---

<a id="alpha-status"></a>
## Alpha-Status

> **0.2.0-alpha.8 — experimentell, nicht produktionsreif.**
> GeDefense Retail ist eine frühe Alpha. Verifiziert wurde auf Loopback mit simulierten Reglern und
> Supervisoren, nicht gegen echte Kältetechnik in einer Filiale. Ein unabhängiger Penetrationstest
> des Access Gate liegt noch nicht vor; es gibt keine Compliance- oder Zertifizierungsaussage.
> Nicht als einzige Sicherheits-, Lebensmittel- oder Überwachungskontrolle einer Kälteanlage einsetzen.

<a id="overview"></a>
## Was das ist

GeDefense Retail schützt und dokumentiert die Infrastruktur hinter einem Supermarkt:
Kälteregler, Kühlräume, Kühlregale, Sensor-Gateways, Gebäudeautomation und den Fernwartungspfad,
den Kältetechnik-Dienstleister verwenden.

Es besteht aus zwei getrennten Diensten:

| Dienst | Binary | Rolle |
|---|---|---|
| **Monitoring** | `retaild` | Passives, read-only OT-Monitoring: Anlagen, Flows, Kühlketten-Integrität, Datenqualität, Alarme, Audit, Dashboard |
| **Access Gate** | `retailgate` | Der einzige erlaubte Pfad für Management-/Konfigurations-Schreibzugriffe: Default-Deny, plan-gebunden, menschlich freigegeben, vollständig auditiert |
| **Simulator** | `retail-sim` | Lokale Testdaten für Entwicklung und Abnahme (nur Loopback) |

**Produktversprechen:**

- **Kein OT-Prozess-Schreibpfad durch GeDefense.** `retaild` und alle passiven Adapter schreiben
  nie auf einen Regler. Das Access Gate steuert den Prozess nicht; es autorisiert und leitet genau
  eine ausdrücklich freigegebene Konfigurationsoperation weiter.
- **Schreiben ist Default-Deny.** Ein Write wird nur weitergeleitet, wenn er zu einem freigegebenen
  *Write-Plan* passt (Ziel, Protokoll, Funktion, Adresse **und** Wert) und in einem freigegebenen
  Zeitfenster liegt.
- **Menschliche Kontrolle.** Kritische Anlagen benötigen zwei verschiedene Freigaben, davon eine von
  einem `master_admin`. Es gibt kein autonomes Schreiben, kein zeitplanbasiertes Schreiben und
  keine KI-Entscheidung.
- **Fail-closed für den Management-Pfad.** Fällt das Gate aus, ist die Fernwartung zu. Die
  Kälteanlage läuft autonom weiter, weil das Gate nicht im Prozessregelkreis liegt.
- **Nachweis vor der Wirkung.** Jede Aktion und jeder abgelehnte Schreibversuch landet in einem
  hash-verketteten Audit-Log; bei gebrochener Kette startet das Gate nicht.

<a id="features"></a>
## Funktionen

### ColdChain-Monitoring (`retaild`, passiv/read-only)

- Passive Asset-Erkennung aus Flow-Metadaten, OUI-Hinweisen und Protokollevidenz — unbekannte
  Geräte bleiben unbekannt, mit Confidence-Wert.
- OT-Netzbeobachtung: neue Kommunikationspartner, unerwartete Pfade, Protokoll-Metadaten,
  Flow-Baselines.
- Kühlketten-Integrität: vom Betreiber definierte Temperaturgrenzen, Änderungsrate,
  Sollwertabweichung, Divergenz unabhängiger Sensoren.
- Datenqualitätsprüfungen: eingefrorene Werte, Telemetrielücken, Clock-Skew, unplausible Werte —
  ein schlechter Messwert wird nie als gute Temperatur angezeigt.
- Wartungszugriffe: freigegebene Fenster, Anomalien bei Dienstleisterzugriffen, Session-Metadaten.
- Erkennungsregeln und korrelierte Incidents: Fakten, Hypothese und empfohlene Prüfungen bleiben in
  jedem Alarm getrennt.
- Local-first: Erkennung und Alarmierung funktionieren ohne WAN; begrenzter lokaler Spool für
  spätere Weiterleitung.
- Hash-verkettetes Audit, rollenbasierter API-Zugriff, Glass-Dashboard, kein externes CDN und kein
  Frontend-Framework von Drittanbietern.
- Passive/read-only-Adapter für Modbus TCP, MQTT, BACnet/IP, SNMP (v1/v2c GET), PCAP und
  HTTP-Management-UI-Metadaten.

### Access Gate (`retailgate`, Default-Deny-Durchsetzung)

- Write-Pläne mit Ist-Wert, Soll-Wert, Begründung, optionaler Ticket-Referenz, Zeitfenster und
  unveränderlichem Plan-Hash.
- Freigabe-Workflow mit MFA (in dieser Alpha TOTP), idempotenten Freigaben, Verbot der
  Selbstfreigabe und Vier-Augen-Prinzip für kritische Anlagen.
- Einmal-Token und quell-IP-gebundene Write-Session; Replay, Ablauf und falsche Quelle werden
  abgelehnt und alarmiert.
- Modbus-TCP-Enforcement-Proxy und HTTP(S)-Reverse-Proxy für Supervisor-Weboberflächen.
- Register- und URL-Allowlists; Allowlisting ist notwendig, aber nicht hinreichend — ein
  freigegebener Plan muss zusätzlich exakt passen.
- Deny-Timeline, Deny-Evidenz und Audit für jeden abgelehnten Schreibversuch.
- Fail-safe-Matrix: Store-/Audit-Fehler, Clock-Sprünge und ungültige Policy sperren den Schreibpfad;
  ein totes Gate lässt die Anlage unberührt.
- HMAC-signierte Webhook-Benachrichtigungen mit Eskalation und Quittierung (`GET /escalations`,
  `POST /escalations/{id}/ack`).

### Neu in 0.2.0-alpha.2

- **Setup-Assistent** (First-Run, nur Loopback) mit geführten Schritten für Sprache, Filiale,
  Zugriffs-Whitelist, Admin-Konto, Collectors und Abschluss.
- **IP-Whitelist** für Dashboard, API, SSE, statische Assets und Setup nach Konfiguration
  (`require_whitelist` standardmäßig aktiv; fail-closed).
- **Acht UI-Sprachen:** Englisch, Deutsch, Französisch, Italienisch, Spanisch, Japanisch,
  Chinesisch, Russisch.
- **Original-GeDefense-Logo** und Maskottchen als lokale Assets (kein externes CDN).
- Linux- und Windows-Pakete mit Installer-Skripten und SHA-256-Checksums.

### Sicherheits-Härtung in 0.2.0-alpha.8

- Gehärtete Installer: dedizierte Dienstkonten; Linux-Config `root:gedefense` `0750`/`0640`,
  Windows `LocalService` mit expliziten `icacls`-DACLs und ohne geerbten `Users`-Zugriff.
- Release-Integrität: `SHA256SUMS`, `SHA256SUMS.archives`, cosign-Keyless-Signaturen und ein
  SPDX-`SBOM.spdx.json`; Windows-Binaries bleiben **NOT_SIGNED** (kein Authenticode-Zertifikat).
- Bearer-Token-Rotation, mTLS-Pflicht für die optionale Zentrale, reproduzierbare Builds mit
  `SOURCE_DATE_EPOCH`, gehärtete CI-Rechte und sauberer Shutdown-/Audit-Flush.

**Neu in 0.2.0-alpha.8:** kuratierte Vendor-/Pilot-Dokumentation unter `docs/retail/`, Modbus Read-before-Write (CurrentValue-Recheck; Mismatch/Lesefehler ⇒ Deny + Audit), Vendor-Katalog als Laufzeitwissen (kein Auto-Allow) und `data/ot-catalog` im Paket.

<a id="architecture"></a>
## Architektur (kurz)

```text
 Dienstleister / Betreiber
 (VPN / ZTNA, per Whitelist)
        │
        ▼
 ┌──────────────────────────────┐        ┌──────────────────────────────┐
 │ retaild (Monitoring)         │        │ retailgate (Enforcement)     │
 │ passiv TAP/SPAN, read-only   │        │ Identität, Freigabe, Token   │
 │ Detection, Alerts, Audit, UI │        │ Audit, Modbus-/HTTP-Proxies  │
 └──────────────┬───────────────┘        └──────────────┬───────────────┘
                │ passive Beobachtung                    │ nur Management-Pfad
                │ (schreibt nie)                         │ (plan-gebunden, Default-Deny)
                ▼                                        ▼
        OT-Monitoring-Segment                  Regler / Supervisoren
        (TAP/SPAN, read-only Polls)            (Modbus TCP, HTTP(S)-Admin-UI)
```

- Ein Gateway pro Filiale; der lokale Betrieb hängt nicht vom Internet ab.
- Das Access Gate läuft auf einer **separaten Appliance/VM mit zwei Netzwerkschnittstellen**:
  Management-/Dienstleister-Seite und OT-Management-Conduit. Es ist kein Router und liegt nicht in
  der Prozesskommunikation zwischen Regler und Aktorik.
- Optionales zentrales Management ist outbound-only (mTLS).

<a id="alpha-limitations"></a>
## Ehrliche Alpha-Grenzen

- **Keine echte OT-Hardware getestet.** Die Datenplane-Evidenz stammt aus simulierten Reglern und
  Supervisoren auf Loopback. Reale Unit-IDs, Vendor-Login-Flows, Zertifikate und Firmware-Stände
  sind Pilotthemen.
- **TOTP ist kein phishing-resistenter Faktor.** FIDO2/WebAuthn ist für ein späteres Release
  geplant; für den Alpha-Faktor wird keine Resistenz behauptet.
- **Segmentierung ist Betreiberaufgabe.** Ohne echtes „kein zweiter Pfad"-Netzdesign ist das Gate
  umgehbar. Das Monitoring macht Bypässe sichtbar; verhindern kann es sie nicht.
- **Keine automatische Bypass-Korrelation.** Gate und Monitoring sind getrennt; abgelehnte Writes
  und passive `retail.write-attempt`-Alarme werden in dieser Alpha manuell korreliert.
- **Cert-Pinning und Parameter-Allowlists** sind im Proxy implementiert, aber noch nicht im
  Konfigurationsschema exponiert.
- **`write_unknown` ohne automatischen Read-back.** Bei unklarer Reglerantwort (Timeout, Disconnect)
  wird der Write als `write_unknown` mit Critical-Alert markiert; eine Bedienperson muss den Wert
  per Read-back prüfen und darf **nicht automatisch wiederholen**.
- **API-Sessions sind in-memory.** Ein Neustart meldet Benutzer ab; das ist gewolltes
  Fail-closed-Verhalten.
- **Keine BACnet-/MQTT-Datenplane, keine Hersteller-Cloud-/HMI-/USB-Kontrolle.** Außerhalb des
  Alpha-Scopes; bleibt Betreiberthema.
- **Keine Compliance-Aussage.** GeDefense Retail behauptet keine HACCP-, NIS2-, IEC-62443- oder
  sonstige Zertifizierung.
- **Windows-Rechte unterscheiden sich von Linux.** POSIX `0600/0700` ist unter Windows kein
  Zugriffsschutz; dediziertes Dienstkonto und explizite ACLs verwenden. Das ist eine dokumentierte
  Beta-Bedingung.

<a id="download"></a>
## Download

**Aktuelles Alpha-Release: [v0.2.0-alpha.8](https://github.com/visiongaiatechnology/gedefense-retail/releases/tag/v0.2.0-alpha.8).**
Assets: vier Archive, [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS),
[SHA256SUMS.archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS.archives),
[SBOM.spdx.json](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SBOM.spdx.json)
und cosign-Signaturen (`*.sig`/`*.pem`). Windows-Binaries sind **NOT_SIGNED** mit Authenticode
(Alpha); stattdessen Hashes/Signaturen verwenden.

| Plattform | Archiv | Checksums |
|---|---|---|
| Linux amd64 | [gedefense-retail-0.2.0-alpha.8-linux-amd64.tar.gz](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/gedefense-retail-0.2.0-alpha.8-linux-amd64.tar.gz) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS) · [Archive](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS.archives) |
| Linux arm64 | [gedefense-retail-0.2.0-alpha.8-linux-arm64.tar.gz](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/gedefense-retail-0.2.0-alpha.8-linux-arm64.tar.gz) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS) · [Archive](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS.archives) |
| Windows amd64 | [gedefense-retail-0.2.0-alpha.8-windows-amd64.zip](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/gedefense-retail-0.2.0-alpha.8-windows-amd64.zip) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS) · [Archive](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS.archives) |
| Windows arm64 | [gedefense-retail-0.2.0-alpha.8-windows-arm64.zip](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/gedefense-retail-0.2.0-alpha.8-windows-arm64.zip) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS) · [Archive](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS.archives) |

**Vor Installation prüfen:** `sha256sum -c SHA256SUMS` im entpackten Bundle und
`sha256sum -c SHA256SUMS.archives` für die heruntergeladenen Archive. Archive und `SHA256SUMS` sind
mit cosign keyless signiert; eine Datei prüfen mit `cosign verify-blob --certificate <Datei>.pem
--signature <Datei>.sig --certificate-oidc-issuer https://token.actions.githubusercontent.com
--certificate-identity-regexp 'https://github.com/visiongaiatechnology/gedefense-retail/.github/workflows/release.yml@refs/tags/v.*' <Datei>` (exakte Identität in
[docs/BUILD-AND-RELEASE.md](docs/BUILD-AND-RELEASE.md)). `SBOM.spdx.json` ist das
SPDX-SBOM für Release-Archive und Binaries; alle Bundle-Dateien sind durch die Bundle-`SHA256SUMS` abgedeckt. **Fehlt eine Signaturdatei, gilt der Download als unsigniert.**

Jedes Bundle enthält `bin/` (Binaries), `config/` (Beispielkonfiguration und systemd-Units), `docs/`,
`README.md`, `LICENSE`, `VERSION`, `THIRD-PARTY-NOTICES.md`, die Installer-Skripte und eine
`SHA256SUMS`-Datei.

<a id="install-linux"></a>
## Installation — Linux

**Voraussetzungen**

- Linux x86-64 oder arm64 mit systemd.
- Administratorrechte für die Installation.
- Ein Management-Client innerhalb des geplanten Whitelist-CIDR (während des Setups Loopback).
- Für Binärpakete ist keine Go-Toolchain erforderlich.
- Whitelist und OT-/Management-Segmentierung **vor** dem Aktivieren des Fernzugriffs planen.

**1. Herunterladen und prüfen**

```bash
tar -xzf gedefense-retail-<version>-linux-amd64.tar.gz
cd gedefense-retail-<version>-linux-amd64
sha256sum -c SHA256SUMS
```

**2. Installieren**

```bash
sudo ./install.sh
```

Der Installer legt Dienstbenutzer an, installiert die systemd-Units aus `config/`
(`gedefense-retail.service`, `gedefense-retailgate.service`), richtet `/etc/gedefense-retail/`,
`/var/lib/gedefense-retail/`, `/var/lib/gedefense-gate/` und `/var/log/gedefense-retail/` ein und
hinterlässt den Monitoring-Dienst bereit für das First-Run-Setup. Er kopiert **nur** die
Beispielkonfiguration (`retail.example.json`, `gate.example.json`, `gate-policy.example.json`) und
überschreibt nie bestehende Dateien. Die Konfiguration wird `root:gedefense` installiert (`0750`
Verzeichnisse, `0640` Dateien), die Datenverzeichnisse gehören den Dienstbenutzern; der Installer
bricht bei fehlgeschlagenen Rechte-Schritten ab (fail-closed). Die produktive Konfiguration legt der
Betreiber aus den Beispielen an:

```bash
sudo cp /etc/gedefense-retail/retail.example.json /etc/gedefense-retail/retail.json
# retail.json anpassen: Filiale, Benutzer, Collectors, Security-Whitelist, Gate-Targets/Upstreams
```

**3. First-Run-Setup (nur Loopback)**

```bash
sudo systemctl enable --now gedefense-retail
```

Bei `setup.completed=false` bindet der erste Start **nur an Loopback** (für die folgende URL `listen`
auf `127.0.0.1:8080` setzen). `http://127.0.0.1:8080/setup` auf dem Gateway selbst öffnen
(SSH-Tunnel oder lokaler Browser) und den Assistenten abschließen: Sprache, Filiale/Zeitzone,
Zugriffs-Whitelist (z. B. `127.0.0.1/32`, `::1/128` plus Management-CIDR), Admin-Token (**einmalig**
angezeigt), optionale Collectors, Abschluss (`restart_required: true`). `security.setup_token_ttl_s`
hat den Default 3600 Sekunden. Die Whitelist ist fail-closed: Ohne Eintrag erhalten
Nicht-Loopback-Clients `403 ip_not_allowed`, es gibt keine Login-Seite.

```bash
sudo systemctl restart gedefense-retail
```

**4. Prüfen**

```bash
systemctl status gedefense-retail --no-pager
retaild version
curl -s http://127.0.0.1:8080/api/v1/health
```

Nur Quell-IPs aus `security.dashboard_whitelist_cidrs` erreichen Dashboard, API, SSE und statische
Assets. Anfragen außerhalb der Whitelist erhalten `403 ip_not_allowed`; es gibt keine
Fallback-Login-Seite.

**5. Optional: Access Gate aktivieren**

Das Gate erst nach abgeschlossenem Monitoring-Setup aktivieren. Es benötigt **beide** Dateien
`gate.json` und `gate-policy.json`; ohne gültige Konfiguration und Policy startet es nicht
(fail-closed).

```bash
sudo cp /etc/gedefense-retail/gate.example.json /etc/gedefense-retail/gate.json
sudo cp /etc/gedefense-retail/gate-policy.example.json /etc/gedefense-retail/gate-policy.json
# beide Dateien anpassen: Targets, Benutzer, Whitelist, kritische Assets, Allowlists
sudo retailgate hash-password --password "<mindestens 12 Zeichen>"
sudo retailgate gen-totp
# ausgegebenen Passwort-Hash und TOTP-Secret in gate.json eintragen, dann prüfen und starten:
sudo -u gedefense-gate retailgate check --config /etc/gedefense-retail/gate.json
sudo systemctl enable --now gedefense-retailgate
```

Das Gate gehört auf die separate Zwei-NIC-Appliance/VM (Management-Seite und OT-Management-Conduit),
nicht auf den Monitoring-Host. Ohne korrekte Segmentierung ist das Gate umgehbar.

<a id="install-windows"></a>
## Installation — Windows

**Voraussetzungen**

- Windows 10/11 oder Windows Server 2019+ (x64 oder arm64), PowerShell 5.1+.
- Administratorrechte.
- Ein Management-Client innerhalb des geplanten Whitelist-CIDR; das Setup läuft nur über Loopback.

**1. Herunterladen, entpacken, prüfen**

```powershell
Expand-Archive .\gedefense-retail-<version>-windows-amd64.zip -DestinationPath .
cd .\gedefense-retail-<version>-windows-amd64
Get-FileHash .\bin\retaild.exe -Algorithm SHA256
# mit den Werten in SHA256SUMS vergleichen (alle Dateien im Bundle)
```

**2. Installieren**

```powershell
# PowerShell mit Administratorrechten
.\install-windows.ps1
```

Der Installer legt das Programmverzeichnis `C:\Program Files\GeDefense\Retail\` (mit `bin\` und
`config\`) und das Datenverzeichnis `C:\ProgramData\GeDefense\Retail\` an und registriert die
Windows-Dienste über `sc.exe` (`gedefense-retail`, `gedefense-retailgate`). Er kopiert **nur** die
Beispielkonfiguration; die produktive `retail.json`/`gate.json` legt der Betreiber aus den
Beispielen in `config\` an. **Firewall-Regeln werden nicht automatisch gesetzt** — nur die
tatsächlich benötigten Whitelist-/Management-Ports ergänzen.

**3. First-Run-Setup**

```powershell
Start-Service gedefense-retail
```

`http://127.0.0.1:8080/setup` auf dem Gateway öffnen (mit `listen` = `127.0.0.1:8080`), die sechs
Setup-Schritte abschließen, dann neu starten:

```powershell
Restart-Service gedefense-retail
Get-Service gedefense-retail
.\bin\retaild.exe version
```

**Windows-Rechte (Alpha):** Der Installer betreibt beide Dienste als `NT AUTHORITY\LocalService`
und setzt explizite `icacls`-DACLs ohne Vererbung: `config\` lesend für den Dienst,
`C:\ProgramData\GeDefense\Retail\` ändernd für den Dienst, Administratoren voll, `Users` kein
Zugriff. POSIX-Modi schützen NTFS nicht; geerbte ACLs nicht wieder aktivieren. Die Deinstallation
stellt frühere ACLs nicht wieder her.

**4. Optional: Access Gate**

```powershell
# Beispiele: C:\Program Files\GeDefense\Retail\config\gate.example.json / gate-policy.example.json
# produktiv: ...\config\gate.json und ...\config\gate-policy.json (Targets/Benutzer/Allowlists anpassen)
.\bin\retailgate.exe hash-password --password "<mindestens 12 Zeichen>"
.\bin\retailgate.exe gen-totp
# ausgegebenen Passwort-Hash und TOTP-Secret in gate.json eintragen, dann prüfen und starten:
.\bin\retailgate.exe check --config "C:\Program Files\GeDefense\Retail\config\gate.json"
Start-Service gedefense-retailgate
```

Das Gate benötigt beide Konfigurationsdateien und startet ohne gültige Policy nicht (fail-closed).
Es gehört auf eine separate Zwei-NIC-Appliance/VM; der Windows-Installer richtet weder Segmentierung
noch Firewall-Regeln ein.

<a id="quickstart"></a>
## Schnellstart

1. Paket für die Zielplattform installieren.
2. Monitoring-Dienst starten und den Loopback-Setup-Assistenten abschließen.
3. Mindestens ein Management-Client-CIDR in die Whitelist eintragen — sonst wird jede
   Nicht-Loopback-Anfrage abgelehnt.
4. Am Dashboard mit dem einmalig angezeigten Admin-Token anmelden.
5. Für Simulation/Entwicklung `retail-sim` auf dem Gateway starten (nur Loopback, Simulationsflag
   erforderlich) — nie gegen produktive OT-Geräte.

Aus dem Quellcode (Entwicklung, Go 1.23+, nur Standardbibliothek, kein CGO):

```bash
go build ./...
go vet ./...
go test ./...
```

<a id="security"></a>
## Sicherheitsmodell

- **Read-only-Monitoring.** `retaild` hat keinen OT-Schreibpfad. Passive Adapter senden keine
  Schreib-Funktionscodes, führen keine aktiven Scans aus und senden keine Roh-Probes.
- **Default-Deny-Management-Pfad.** `retailgate` leitet nur Operationen weiter, die exakt zu einem
  freigegebenen Plan passen; alles andere wird abgelehnt, auditiert und alarmiert.
- **Exakte Bindung.** Ziel, Protokoll, Funktion, Adresse und Wert werden als Einheit freigegeben.
  Ein anderer Wert oder eine andere Adresse ist ein Deny, auch im freigegebenen Zeitfenster.
- **Menschliche Freigabe.** Selbstfreigabe wird abgelehnt; kritische Anlagen benötigen zwei
  verschiedene Freigebende inklusive `master_admin`. Das Einmal-Token wird einmal angezeigt und an
  Plan-Hash und Quell-IP gebunden.
- **Audit vor der Wirkung.** Abgelehnte und erlaubte Operationen landen in einem hash-verketteten
  Audit-Log; bei gebrochener Kette startet das Gate nicht.
- **Fail-closed.** Gate-, Store-, Clock- oder Policy-Probleme schließen den Management-Pfad; die
  Anlage läuft weiter.
- **Netzwerk.** Whitelist-Enforcement ist fail-closed. Dashboard und Gate nicht ins Internet
  stellen; für Fernzugriff VPN/ZTNA und dokumentierte Proxy-Einstellungen verwenden.
- **Meldeweg.** Sicherheitslücken bitte vertraulich über [SECURITY.md](SECURITY.md) melden. Nicht
  gegen produktive Kälteanlagen testen.
- **Keine Compliance-Aussage.** Siehe [SECURITY.md](SECURITY.md) und [NOTICE](NOTICE).

<a id="evidence"></a>
## Verifikationsstatus (ehrlich)

| Bereich | Status |
|---|---|
| Build, Vet, Unit-/Integrationstests, Race-Detector | grün (Loopback/CI) |
| 0.1-End-to-End-Abnahme (Monitoring) | 39/39 Prüfungen bestanden (Loopback/Simulation) |
| 0.2.0-alpha.1 Access-Gate-End-to-End | 25/25 Prüfungen bestanden (Loopback, simulierte Regler) |
| Design-QA | Mock-Daten-Screenshots erzeugt; keine Screenreader-/Touch-/Langlauf-Prüfung |
| Echte OT-Hardware | noch nicht getestet (Pilotthema) |
| Unabhängiger Gate-Penetrationstest | noch nicht vorhanden |
| Compliance/Zertifizierung | keine behauptet |

Die Zahlen beziehen sich auf die in den Release Notes beschriebenen Verifikationsläufe; sie sind
keine Aussage zur Produktionsreife.

<a id="documentation"></a>
## Dokumentation

- [README (English)](README.md) · [README (Deutsch)](README.de.md)
- [SECURITY.md](SECURITY.md) — Meldeweg, Alpha-Status, Scope
- [CONTRIBUTING.md](CONTRIBUTING.md) — Build, Tests, Safety-Invarianten, Pull Requests
- [CHANGELOG.md](CHANGELOG.md) — Release-Historie
- [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) — Abhängigkeiten und Assets
- [NOTICE](NOTICE) — Copyright- und Lizenzhinweis
- [LICENSE](LICENSE) — GNU Affero General Public License v3.0
- [Dokumentationsindex](docs/README.md)
- [Releases](https://github.com/visiongaiatechnology/gedefense-retail/releases) ·
  [Issues](https://github.com/visiongaiatechnology/gedefense-retail/issues)

<a id="license"></a>
## Lizenz

GeDefense Retail steht unter der **GNU Affero General Public License v3.0** (AGPL-3.0).
Siehe [LICENSE](LICENSE) und [NOTICE](NOTICE).

Copyright © 2026 VisionGaiaTechnology.
