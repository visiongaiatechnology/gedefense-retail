# GeDefense Retail — Build & Release (Cross-Platform)

**Produkt:** GeDefense Retail — ColdChain & Store Infrastructure Security (VisionGaiaTechnology)
**Version:** siehe `VERSION` (aktuell `0.2.0-alpha.3`)
**Status:** ALPHA — nicht produktionsfreigegeben.

Dieses Dokument beschreibt den reproduzierbaren Cross-Platform-Build, die
Paketierung, die Verifikation und die Installation von `retaild`, `retailgate`
und `retail-sim`.

---

## 1. Voraussetzungen

| Werkzeug | Version | Zweck |
|---|---|---|
| Go | ≥ 1.23 (verifiziert mit 1.26.4 Windows / 1.27.1 Linux) | Builds (nur Standardbibliothek) |
| Git | beliebig | Commit-Identität in ldflags (optional; Fallback `local`) |
| Python | 3.10+ | `tests/e2e.py`, `tests/gate_e2e.py`, `scripts/generate-sbom.py`, Packaging-Zipfallback |
| PowerShell | 5.1+ (7 empfohlen) | Windows-Build-/Install-Skripte |
| bash/tar | POSIX/WSL | Linux-Build/Paketierung |
| optional: systemd | — | Installation der Units |

Es werden **keine** Module heruntergeladen (`go.mod` ohne `require`), kein CGO
verwendet und keine Netzwerkressourcen zur Build-Zeit benötigt.

---

## 2. Build-Matrix

| Ziel | GOOS | GOARCH | Binary-Endung | Status |
|---|---|---|---|---|
| Linux x86_64 | `linux` | `amd64` | — | unterstützt |
| Linux ARM64 | `linux` | `arm64` | — | unterstützt |
| Windows x86_64 | `windows` | `amd64` | `.exe` | unterstützt |
| Windows ARM64 | `windows` | `arm64` | `.exe` | unterstützt (Cross-Build; kein ARM-Gerätetest) |
| macOS | `darwin` | — | — | **nicht** im Release (keine Verifikation) |

Ausgabe: `dist/<version>/<os>-<arch>/`
`retaild[.exe]`, `retailgate[.exe]`, `retail-sim[.exe]`, `SHA256SUMS` je Plattform;
`dist/<version>/SHA256SUMS.binaries` über alle Binaries. Das Release-Asset
`SHA256SUMS` (Archiv-Prüfsummen) entsteht beim Packaging (Abschnitt 4).

### 2.1 Reproduzierbare Flags

```text
CGO_ENABLED=0
go build -trimpath -buildvcs=false -ldflags "-s -w \
  -X <module>/internal/version.Version=<VERSION> \
  -X <module>/internal/version.Commit=<COMMIT> \
  -X <module>/internal/version.BuildDate=<RFC3339-UTC>"
```

`-trimpath` und `-buildvcs=false` entfernen lokale Pfade/VCS-Metadaten aus dem
Binary. `Version/Commit/BuildDate` erscheinen in `retaild version` und in
`GET /api/v1/meta`/`/health`. Ohne gesetzte Umgebung wird der Commit aus Git
gelesen (Fallback `local`), das Build-Datum ist die aktuelle UTC-Zeit.

**FIND-009 — Reproduzierbarkeit:** `SOURCE_DATE_EPOCH` (Unix-Sekunden) wird
respektiert; `GEDEFENSE_BUILD_DATE` bleibt als explizite Überschreibung
unterstützt (Vorrang). Für einen reproduzierbaren Vergleich:

```bash
SOURCE_DATE_EPOCH=1762290000 GEDEFENSE_COMMIT=<sha> bash scripts/build-release.sh
# BuildDate im Binary: 2025-11-04T21:00:00Z (aus dem Epoch abgeleitet)
```

Zwei Builds mit demselben `SOURCE_DATE_EPOCH`, `GEDEFENSE_COMMIT` und derselben
Go-Toolchain sind bit-identisch (Hashvergleich via `SHA256SUMS.binaries`).

```bash
GEDEFENSE_COMMIT=abc1234 GEDEFENSE_BUILD_DATE=2026-11-03T00:00:00Z \
  scripts/build-release.sh
```

---

## 3. Kommandos

### Windows (Host)

```powershell
cd <repo>
pwsh scripts/build-release.ps1            # Build-Matrix + SHA256SUMS je Plattform
pwsh scripts/build-release.ps1 -Package   # zusätzlich tar.gz/zip + Release-SHA256SUMS
```

### Linux / WSL2 Ubuntu 24.04

```bash
cd /path/to/gedefense-retail
bash scripts/build-release.sh             # Build-Matrix + SHA256SUMS je Plattform
bash scripts/build-release.sh --package   # zusätzlich tar.gz (Linux) + zip (Windows)
```

Das Skript prüft Go, liest `VERSION`, baut alle Ziele und schreibt
`SHA256SUMS` je Plattform sowie `SHA256SUMS.binaries` gesamt. Fehler brechen mit
Exitcode ≠ 0 ab. Das Packaging schreibt zusätzlich das Release-Asset
`SHA256SUMS` mit den Archiv-Prüfsummen.

---

## 4. Paketierung

`scripts/package-release.sh` / `scripts/package-release.ps1` erzeugen:

```text
dist/<version>/
├── gedefense-retail-<version>-linux-amd64.tar.gz
├── gedefense-retail-<version>-linux-arm64.tar.gz
├── gedefense-retail-<version>-windows-amd64.zip
├── gedefense-retail-<version>-windows-arm64.zip
├── SHA256SUMS              # Release-Asset: Prüfsummen aller Archive
├── SHA256SUMS.archives     # identisch zu SHA256SUMS (Release-Asset)
├── SHA256SUMS.binaries     # Prüfsummen aller Binaries (Build-Matrix)
├── SBOM.spdx.json          # SPDX-2.3-SBOM (FIND-004)
└── (Release: *.sig + *.pem je Archiv/SHA256SUMS/SHA256SUMS.archives/SBOM)
```

Inhalt eines Bundles:

| Pfad | Inhalt |
|---|---|
| `bin/` | `retaild`, `retailgate`, `retail-sim` |
| `config/` | `retail.example.json`, `gate.example.json`, `gate-policy.example.json`, `gedefense-retail.service`, `gedefense-retailgate.service` |
| `docs/` | Betriebs-/Sicherheits-/Gate-Dokumentation |
| `README.md`, `LICENSE`, `VERSION`, `THIRD-PARTY-NOTICES.md` | Produkt-/Lizenzhinweise |
| `install.sh` / `uninstall.sh` | Linux-Installation (nur Linux-Bundles) |
| `install-windows.ps1` / `uninstall-windows.ps1` | Windows-Installation (nur Windows-Bundles) |
| `SHA256SUMS` | Prüfsummen aller Bundle-Dateien |

Prüfen:

```bash
sha256sum -c SHA256SUMS          # im entpackten Linux-Bundle
Get-FileHash .\bin\retaild.exe   # Windows: gegen SHA256SUMS vergleichen
tar -tzf gedefense-retail-<version>-linux-amd64.tar.gz | head
```

---

## 5. Installation

### Linux

```bash
tar -xzf gedefense-retail-<version>-linux-amd64.tar.gz
cd gedefense-retail-<version>-linux-amd64
sudo ./install.sh                 # optional: --prefix /opt/... --no-systemd --start
# Konfiguration:
sudoedit /etc/gedefense-retail/retail.json     # aus retail.example.json ableiten
sudo /opt/gedefense-retail/bin/retaild token rotate --user admin --role admin
#   token_sha256 in users[] eintragen (Klartext-Token niemals speichern), retaild neu starten
sudo /opt/gedefense-retail/bin/retaild check --config /etc/gedefense-retail/retail.json
sudo systemctl start gedefense-retail.service
sudo systemctl start gedefense-retailgate.service
```

Der Installer legt die Systembenutzer/-gruppen `gedefense`/`gedefense-gate` an,
installiert Binaries unter `/opt/gedefense-retail`, Konfiguration unter
`/etc/gedefense-retail` (**root:gedefense 0750**, Dateien **0640 root:gedefense**),
Daten unter `/var/lib/gedefense-retail` bzw. `/var/lib/gedefense-gate`
(**gedefense:gedefense 0700**) und die systemd-Units (`User=gedefense`,
`Group=gedefense`). Der Installer ist fail-closed: er prüft Lesbarkeit der
Konfiguration durch den Dienst-User und ruft bei vorhandener `retail.json`
`retaild check` auf. Bestehende Konfiguration wird nie überschrieben.
Deinstallation: `sudo ./uninstall.sh` (Daten bleiben); `--purge` löscht
zusätzlich Konfiguration/Daten/Logs. Der Uninstaller verweigert unsichere Pfade
(root, `/`, `..`, Symlinks) und verlangt die Marker-Datei
`.gedefense-retail-install`; `--dry-run` zeigt die Aktionen nur an (FIND-006).

**Erster Start:** Der Erststart öffnet den Dashboard-Setup-Wizard. Sicherheit
ist fail-closed: `security.require_whitelist` default `true`, daher
`security.dashboard_whitelist_cidrs` setzen; `security.setup_token_ttl_s`
(Default 3600) begrenzt den Setup-Token. Details:
`docs/retail/deployment-guide.md`.

### Windows

```powershell
Expand-Archive .\gedefense-retail-<version>-windows-amd64.zip -DestinationPath .
cd .\gedefense-retail-<version>-windows-amd64
powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 -Start
# Konfiguration:
#   C:\Program Files\GeDefense\Retail\config\retail.json (aus retail.example.json)
#   & 'C:\Program Files\GeDefense\Retail\bin\retaild.exe' token rotate --user admin --role admin
#   & '...\retaild.exe' check --config '...\retail.json'
```

Der Installer kopiert Binaries/Konfiguration und legt die Dienste
`gedefense-retail` und `gedefense-retailgate` via `sc.exe` an, **laufen als
`NT AUTHORITY\LocalService`** (nicht LocalSystem). Config/Data erhalten
explizite DACLs via `icacls` (`/inheritance:r`): SYSTEM + Administratoren full,
LocalService Read (Config) bzw. Modify (Data), keine Users-Vererbung;
`icacls`-Fehler brechen die Installation ab (FIND-001). Firewall-Regeln werden
**nicht** automatisch gesetzt (bewusster Default-Deny); nur die
Management-Netze auf die konfigurierten Ports zulassen. Deinstallation:
`.\uninstall-windows.ps1 [-Purge] [-DryRun]` (validiert Pfade/Marker; setzt die
DACLs nicht zurück — dokumentierte Grenze).

> **Gate (0.2 Alpha):** `retailgate` erzwingt den Management-Pfad
> (Default-Deny-Schreiben, Vier-Augen, Einmal-Token). Es benötigt
> `gate.json` + `gate-policy.json`; Passwort-Hashes über
> `retailgate hash-password`, TOTP über `retailgate gen-totp`. Ohne gültige
> Policy/Config startet das Gate nicht (fail-closed).

---

## 6. Verifikation (Evidenz)

Alle Befehle aus `src/retail` (bzw. WSL-Pfad `<repo>/src/retail`):

```bash
go build ./...
go vet ./...
go test ./...
go test -race ./...
cd ../.. && python3 tests/e2e.py && python3 tests/gate_e2e.py
```

Zusätzlich werden die gebauten Binaries direkt geprüft:

```bash
./retaild version
./retaild check --config <test-config.json>
./retailgate version
./retail-sim version
```

Die E2E-Skripte bauen die Binaries selbst nach `bin/`, erzeugen temporäre
Tokens/Konfigurationen und laufen ausschließlich auf Loopback. Sie beweisen
Softwareverhalten mit synthetischen Beobachtungen — **nicht** das Verhalten
gegen echte OT-Hardware (siehe `docs/retail/pilot-acceptance.md`).

Referenzmatrix des Release-Laufs (2026-11-03, 0.2.0-alpha.2):

| Plattform | build | vet | test | race | e2e | gate_e2e |
|---|---|---|---|---|---|---|
| Linux (WSL2 Ubuntu 24.04, Go 1.27.1) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Windows (Go 1.26.4) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## 7. CI/CD & Release-Integrität

`.github/workflows/ci.yml` — bei Push/PR: Go build/vet/gofmt/test/race auf
ubuntu-latest **und** windows-latest, Loopback-E2E auf Linux, Skript-/SBOM-
Syntax und Uninstaller-Pfadvalidierung. Alle Checkouts mit
`persist-credentials: false`, `permissions: contents: read` je Job (FIND-005).

`.github/workflows/release.yml` — strikter Tag-Trigger
`v<major>.<minor>.<patch>[-pre]`; Build+Paketierung+SBOM auf Linux und Windows;
Publish-Job mit `environment: release`, `contents: write` + `id-token: write`
(nur dort), cosign-keyless-Signierung per OIDC. Veröffentlichte Assets:

- 4 Archive (`.tar.gz`/`.zip`)
- `SHA256SUMS` und `SHA256SUMS.archives` (identische Archiv-Prüfsummen)
- `SBOM.spdx.json` (SPDX-2.3)
- je Asset `*.sig` + `*.pem` (cosign keyless)

Verifikation (Beispiel):

```bash
cosign verify-blob --signature gedefense-retail-0.2.0-alpha.3-linux-amd64.tar.gz.sig \
  --certificate gedefense-retail-0.2.0-alpha.3-linux-amd64.tar.gz.pem \
  --certificate-identity-regexp 'https://github.com/<ORG>/<REPO>/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  gedefense-retail-0.2.0-alpha.3-linux-amd64.tar.gz
sha256sum -c SHA256SUMS
```

Aktions-Pinning: Die Workflows nutzen offizielle `actions/*` und
`sigstore/cosign-installer` per Major-Tag; SHA-Pinning ist als Follow-up
dokumentiert (kein Pinning-Tool in dieser Umgebung). Keine hartcodierten
Secrets/CDNs.

---

## 8. Token-Rotation & sauberer Stopp (FIND-007/FIND-010)

**Token-Rotation (ohne Neuaufbau):**

```bash
retaild token rotate --user admin --role admin   # neuer Token + token_sha256, schreibt nichts
retaild token hash --token '<vorhandener-token>' # SHA-256 eines bestehenden Tokens
retaild gen-token --user admin --role admin      # bestehender Befehl bleibt
```

Ablauf: `token_sha256` in `users[]` ersetzen (alte Hash-Zeile entfernen),
Konfiguration speichern und `retaild` neu starten. Es gibt bewusst **kein**
Laufzeit-Reload; der alte Token bleibt bis zum Restart gültig (dokumentierte
Grenze). Doppelte oder leere `token_sha256`-Werte lehnt `retaild check` ab.

**Sauberer Stopp:** `retaild`/`retailgate` behandeln SIGTERM und flushen den
Audit-Puffer vor dem Exit (FIND-010). `TimeoutStopSec=20s` in den Units;
`kill -TERM <pid>` bzw. `systemctl stop` verwenden, kein `kill -9`, damit die
letzten Audit-Einträge persistiert werden.

**Zentrale Anbindung (FIND-008):** `central.require_mtls` ist Default `true`;
bei `https`-URL sind `client_cert_file`, `client_key_file` und `ca_file`
Pflicht, sonst verweigert `retaild check`/`serve` den Start. Ein explizites
`require_mtls: false` ist ein dokumentierter Opt-out (nur für Loopback-Tests).

---

## 9. Bekannte Grenzen / ehrliche Hinweise

- **ALPHA:** Gate-Funktionen sind experimentierfähig, nicht produktionsfreigegeben.
- macOS/darwin wird nicht gebaut (keine Verifikation).
- Windows-arm64 ist Cross-Compiled; kein realer ARM64-Gerätetest.
- Die Builds sind reproduzierbar bezüglich Quellcode/ldflags, aber Go-Binaries
  enthalten toolchain-/versionsabhängige Bytes — byte-identische Artefakte
  erfordern dieselbe Go-Version und `SOURCE_DATE_EPOCH`/`GEDEFENSE_COMMIT`.
- **Windows-Authenticode: NOT_SIGNED.** Es liegt kein Zertifikat vor; die
  Binaries sind nicht Authenticode-signiert (SmartScreen-Warnung möglich).
  Release-Signatur erfolgt ausschließlich über cosign (keyless) auf die
  Archive/Checksums/SBOM.
- **Token-Revoke:** gültig bis Neustart; kein Hot-Reload (siehe §8).
- Die systemd-Units setzen `ProtectSystem=strict`, `NoNewPrivileges`,
  `RestrictAddressFamilies`; Pfade müssen der Installation entsprechen
  (`/opt/gedefense-retail`, `/etc/gedefense-retail`, `/var/lib/...`).
- Windows-DACLs werden beim Uninstall nicht zurückgesetzt (dokumentiert).
- Firmware-/Update-Pfade werden vom Gate hart verweigert; das Gate ersetzt
  keinen Hersteller-Updateprozess.
