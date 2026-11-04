# Pilot-Abnahme — GeDefense Retail (Alpha 0.3.0-alpha.2)

**Status:** öffentliche Abnahmegrundlage. Keine echte OT-Hardware, keine Produktionsfreigabe,
**keine Compliance- oder Zertifizierungsaussage**. Stand: 2026-11-04.
**Produkt:** GeDefense Retail — ColdChain & Store Infrastructure Security (VisionGaiaTechnology).

Dieses Dokument beschreibt, wie ein Pilot abgenommen wird und welche Nachweise dafür nötig sind. Es
enthält nur Ergebnisse, die tatsächlich ausgeführt wurden; `PASS`, `PENDING`, `NOT_RUN` und
`NOT_TESTED` werden getrennt geführt. „Code vorhanden“ ist kein Nachweis.

## 1. Statusmodell

| Status | Bedeutung |
|---|---|
| `PASS` | Lauf ausgeführt, bestanden, Befehl/Exitcode/Datum dokumentiert |
| `PENDING` | Test geplant, aber blockiert (fehlende Hardware, Freigabe oder Teilnachweis) |
| `NOT_RUN` | noch nicht ausgeführt |
| `NOT_TESTED` | Lauf erfolgt, Prüfung aber nicht bestätigt (z. B. visuelle QA) |
| `FAIL` | Lauf ausgeführt, fehlgeschlagen (Blocker) |
| `N/A` | für diesen Pilot nicht anwendbar (Begründung + Betreiberfreigabe) |

## 2. Voraussetzungen

- Getestete Plattform: Linux (amd64/arm64) und Windows (amd64/arm64), Go 1.23+ für Quellcode-Builds.
- Testumgebung: Loopback mit simulierten Reglern/Supervisoren und `retail-sim`; **keine** echten
  Kälteanlagen, keine produktiven Netze.
- Release-Artefakte mit `SHA256SUMS`, `SHA256SUMS.archives`, `SBOM.spdx.json` und cosign-Signaturen
  (Windows-Binaries: Authenticode **NOT_SIGNED**).
- Betreiberfreigaben: Netzplan/Segmentierung, read-only-Ziele, Policy-Werte, Alarm-/Eskalationsplan.

## 3. Prüfgruppen und Status

### 3.1 Build und Basistests

| Prüfung | Status | Nachweis |
|---|---|---|
| `go build ./...`, `go vet ./...`, `gofmt -l .` | PASS | lokaler/CI-Lauf, Exit 0 |
| `go test ./...`, `go test -race ./...` | PASS | lokaler/CI-Lauf, Exit 0 |
| Bezug der Release-Artefakte (`retaild version`, Hashes) | PASS | Release-Assets, Checksummenprüfung |

### 3.2 Monitoring (`retaild`)

| Kriterium | Status | Nachweis |
|---|---|---|
| Passives Asset-Inventar, Flows, Kühlketten-/Datenqualitätsregeln | PASS | Loopback-E2E mit Simulation |
| Alarm-/Incident-Workflow, Audit-Kette, Dashboard | PASS | Loopback-E2E |
| Read-only-Invariante (keine OT-Schreibpfade in passiven Adaptern) | PASS | Safety-Tests |
| Verhalten gegen echte Regler/Firmware | NOT_TESTED | keine echte Hardware im Alpha-Pilot |

### 3.3 Access Gate (`retailgate`)

| Kriterium | Status | Nachweis |
|---|---|---|
| Plan, Vier-Augen-Freigabe, Einmal-Token, quell-IP-gebundene Session | PASS | Gate-E2E Loopback |
| Default-Deny, Deny-Timeline/Audit, Fail-closed | PASS | Gate-E2E Loopback |
| **Modbus Read-before-Write:** CurrentValue wird unmittelbar vor dem Write erneut gelesen; Mismatch/Read-Fehler/leerer Wert ⇒ Deny + Audit (`current_value_missing`, `current_value_mismatch`, `current_value_unreadable`) | PASS (Loopback) / NOT_TESTED (echte Regler) | Gate-E2E mit simulierten Reglern |
| **HTTP-Grenze:** kein generischer Ist-Wert-Recheck; Check-Warnung; Wertbindung bleibt bestehen | PASS (dokumentiert) | API-/Plan-Validierung |
| Vendor-Katalog als Laufzeitwissen (Discovery/API/UI/Gate-Advisory, kein Auto-Allow) | PASS (Loopback) | API-/UI-Tests |

### 3.4 Sicherheit und Release

| Kriterium | Status | Nachweis |
|---|---|---|
| Checksummen/Signaturen/SBOM geprüft | PASS | Release-Verifikation |
| Unabhängiger Penetrationstest des Gates | PENDING | nicht beauftragt/im Alpha nicht vorhanden |
| Windows-Authenticode | NOT_TESTED / **NOT_SIGNED** | kein Zertifikat vorhanden |
| Compliance (HACCP/NIS2/IEC 62443) | N/A | keine Aussage |

### 3.5 Betrieb

| Kriterium | Status | Nachweis |
|---|---|---|
| Runbook, Backup/Restore, Update/Rollback dokumentiert | PASS | `operations-runbook.md`, `deployment-guide.md` |
| Alarm-/Eskalationsplan durch Betreiber freigegeben | PENDING | Pilot-Sign-off |
| Netzsegmentierung und Bypass-Pfade beseitigt | PENDING | Betreiberverantwortung |

## 4. Pilot-Exit-Gate

| Gate | Bedingung | Status |
|---|---|---|
| G-1 | Build/Tests/Safety-Gates grün | PASS |
| G-2 | Release-Artefakte verifiziert (Hashes/Signaturen/SBOM) | PASS |
| G-3 | Loopback-E2E für Monitoring und Gate bestanden | PASS |
| G-4 | Read-before-Write (Modbus) und HTTP-Grenze dokumentiert und getestet | PASS (Loopback) |
| G-5 | Echte OT-Hardware im Pilot getestet | PENDING |
| G-6 | Betreiberfreigaben (Netz, Policy, Alarmwege, Restrisiken) | PENDING |
| G-7 | Unabhängiger Gate-Penetrationstest | PENDING |

**Pilotfreigabe:** nur nach G-1…G-4 und dokumentierter Betreiberentscheidung zu G-5…G-7. Die
Gesamtfreigabe entscheidet der Betreiber; dieses Dokument ersetzt keine Sicherheitszertifizierung.

## 5. Offene Punkte / ehrliche Grenzen

- Keine echten Kälteanlagen/Regler; reale Firmware, Unit-IDs, Zertifikate und Vendor-Login-Flows
  sind Pilotthemen.
- Kein unabhängiger Gate-Pentest; TOTP ist nicht phishing-resistent (FIDO2 geplant).
- Segmentierung/Bypass-Pfade bleiben Betreiberaufgabe; das Gate macht sie sichtbar, verhindert sie
  nicht.
- Windows-Binaries sind nicht Authenticode-signiert; SmartScreen-Warnung möglich.
- Keine Compliance-/Zertifizierungsaussage jeglicher Art.

## 6. Nachweise und Aufbewahrung

Testergebnisse gehören in das Betreiber-Pilotprotokoll (Datum, Befehl, Exitcode, Umgebung,
Artefakt-Hash). Externe Rohberichte und interne Arbeitsnotizen werden nicht veröffentlicht; für die
öffentliche Dokumentation zählen nur reproduzierbare Befehle und Release-Assets.
