# Operations Runbook — GeDefense Retail (Alpha 0.2.0-alpha.8)

**Status:** Betriebsanleitung für Filiale/Technik · **Stand:** 2026-11-03
**Produkt:** GeDefense Retail 0.1.0 — ColdChain & Store Infrastructure Security (VisionGaiaTechnology)
**Quellen:** `engineering contract`, `API reference`, `retail-policy-reference.md`, `security assumptions`, `safety-boundaries.md`
**Gilt für:** eine Filiale je Gateway-Instanz, Linux + systemd, lokaler Betrieb (`retaild serve`).

> **Oberster Grundsatz:** GeDefense Retail ist **Detection und Dokumentation**. Es steuert **keine**
> Anlage, schreibt **keine** Sollwerte, schaltet **nichts** ab und isoliert **nichts**.
> Jede Reaktion auf einen Alarm erfolgt nach dem **freigegebenen Betreiberprozess** — nicht durch
> Eingriffe in die Kältetechnik „über das Tool“.

**Begriffe:** Alert = erkanntes Ereignis (Workflow-Objekt) · Incident = korrelierte Kette mehrerer
Alerts · Evidence = Beleg-Verweis auf gespeicherte Events · Policy = versionierte Betreiberregeln.

---

## 1. Rollen und Verantwortlichkeiten

| Rolle | Systemrolle | Darf | Typische Person |
|---|---|---|---|
| Beobachter | `viewer` | lesen (GET) | Filialleitung, Marktleitung |
| Bearbeiter | `operator` | Alerts ack/assign/close, Incident-Notiz | Technik/Store-IT |
| Administrator | `admin` | zusätzlich Wartungsfenster + Policy-Reload | Betreiber-IT / Anlagenverantwortlicher |
| Anlagenverantwortlicher | – (Betreiberprozess) | gibt Kühlketten-/Incident-Plan und Policy-Werte frei | Kältetechnik/Qualitätssicherung |
| Sicherheitskontakt | – (Betreiberprozess) | Eskalation bei Verdacht auf Angriff | Betreiber-IT/SOC |

**Trennung:** Systemrollen regeln GeDefense-Zugriffe. Sie **ersetzen nicht** die betriebliche
Verantwortung für Kühlkette, Anlage oder Lebensmittelsicherheit.

---

## 2. Täglicher Betrieb (Morgen-Check, ca. 10 Minuten)

Voraussetzung: Dienst läuft (`systemctl status gedefense-retail`), Token der Rolle `viewer`/`operator`
vorhanden (nie im Klartext in Dateien/Chats ablegen).

```bash
export GD_TOKEN='<bearer-token>'      # nur in der aktuellen Shell
BASE=http://127.0.0.1:8080/api/v1

curl -s $BASE/health | jq .
curl -s -H "Authorization: Bearer $GD_TOKEN" $BASE/overview | jq '.totals, .sites'
curl -s -H "Authorization: Bearer $GD_TOKEN" "$BASE/alerts?status=open&limit=50" | jq '.total'
curl -s -H "Authorization: Bearer $GD_TOKEN" $BASE/collectors | jq '.items'
curl -s -H "Authorization: Bearer $GD_TOKEN" $BASE/audit | jq '{chain_ok, first_verified_seq}'
```

| Prüfpunkt | Soll | Bei Abweichung |
|---|---|---|
| `health.status` | `ok` | §11 Fehlerbilder |
| `health.read_only` | `true` | **sofort** eskalieren (Safety-Verletzung) |
| `health.storage.audit_chain_ok` | `true` | §7 Audit-Verifikation |
| `collectors[].state` | `running` (oder `degraded` mit Grund) | §11; Health je Adapter lesen |
| offene kritische/high Alerts | 0 oder in Bearbeitung mit Assignee | §3 Alarmbehandlung |
| `overview.sites[].site_status` | `online` | WAN/Feed prüfen (§6) |
| Timestamps `now`/`last_event_at` | plausibel (UTC, aktuell) | Zeit/NTP prüfen |

**Wöchentlich zusätzlich:** `GET /api/v1/coldchain` je kritischer Zone sichten (Datenqualität,
`limit` gesetzt?), offene Alerts ohne Assignee, Windows-Liste (`/access`) auf abgelaufene Fenster.

---

## 3. Alarmbehandlung

### 3.1 Ablauf (Standard)

1. **Lesen, nicht raten.** `GET /api/v1/alerts/{alert_id}` öffnen: `category`, `severity`, `confidence`,
   `evidence_events`, `correlation` (Felder `observed_facts`, `hypothesis`, `recommended_checks`).
   Die drei Abschnitte sind strikt zu trennen: **Fakt ≠ Hypothese ≠ empfohlene Prüfung.**
2. **Einordnen** anhand Kategorie (§3.2) und Severity (`info`…`critical`).
3. **Bestätigen:** `POST /api/v1/alerts/{alert_id}/ack` mit `{"note":"..."}` → Status `acknowledged`
   (dokumentiert „gesehen“).
4. **Zuweisen:** `POST /api/v1/alerts/{alert_id}/assign` mit `{"assignee":"<user_id>","note":"..."}`.
   Unbekannter Assignee → `400`.
5. **Prüfen** nach `recommended_checks` und Betreiberprozess; Ergebnisse als Notiz/Incident-Notiz
   dokumentieren (`POST /api/v1/incidents/{id}/note`).
6. **Abschließen:** `POST /api/v1/alerts/{alert_id}/close` mit
   `{"status":"resolved"|"closed"|"false_positive","note":"..."}`.
   Jede Aktion erzeugt einen Audit-Eintrag (`alert.ack`, `alert.assign`, `alert.close`).
7. **Incident** bei Korrelation (`/incidents`): Status/Zuständigkeit prüfen, Export
   `GET /api/v1/incidents/{id}/export` für Nachweise (enthält Metadaten + Audit, **keine** Payloads).

### 3.2 Kategorien und typische Prüfungen

| Kategorie | Beispiele (Regel-IDs) | Belegte Fakten | Empfohlene Prüfung (Betreiberprozess) |
|---|---|---|---|
| `access` | `retail.access.off-window`, `retail.access.untrusted-vendor` | Quelle/Ziel, Zeit, Protokoll, Fensterstatus; Web-UI-Sitzungen erscheinen als `access_session` mit `method=web_ui` (`httpui`-Beobachter) | Dienstleister/Ticket verifizieren; Zugang nach Freigabeprozess sperren — **keine** Anlagenkommunikation unterbrechen |
| `network` | `retail.net.unknown-peer` | neuer Kommunikationspartner, Port, Baseline | Gerät identifizieren, Betreiber bestätigen lassen, ggf. Allowlist-Pflege |
| `thermal` | `retail.thermal.limit`, `.rate`, `.setpoint-deviation`, `.sensor-divergence` | Messwerte, Zone, Grenzwert, Zeitfenster | Temperatur mit **unabhängiger** Messung prüfen; Kältetechnik nach Plan |
| `data_quality` | `retail.dq.frozen-value`, `.gap`, `.clock-skew` | eingefrorener Wert, Lücke, Zeitversatz | Sensor/Netz/Gerätezeit prüfen; **nicht** als „Temperatur in Ordnung“ werten |
| `integrity` | `retail.integrity.change` | beobachtete Konfigurations-/Firmwareänderung, `approved` | Änderung gegen Wartungsfenster/Ticket abgleichen |
| `device_health` | Asset-/Collector-Ausfälle | letzter Kontakt, Health-Counter | Gerät/Feed/Netz prüfen |

> **Sicherheitsrelevanter Schreibversuch:** `write_attempt` wird nur **beobachtet** und gemeldet
> (`retail.write-attempt`). Er ist ein starkes Signal — die Reaktion erfolgt über Betreiberprozess,
> **nie** durch Senden von Schreib-/Gegenbefehlen.

### 3.3 Was bei einem Alarm NICHT zu tun ist

- **Keine Sollwerte, Betriebsmodi oder Parameter** an Reglern/PLCs/HMI ändern, um den Alarm zu beenden.
- **Keine Anlage abschalten**, keine Sicherung ziehen, keine Kältemaschine „quittieren“.
- **Keine Netzwerkverbindung trennen oder OT-Ports blockieren**, um einen Alert verschwinden zu lassen.
- **Keine Policy-Grenzwerte lockern**, nur damit Alerts schließen — das ist auditpflichtig und ein
  dokumentierter Missbrauchspfad (Threat Model R-06).
- **Keine Dateien** im Datenverzeichnis löschen, verschieben oder bearbeiten (Audit-Kette!).
- **Keine Tokens teilen**, in Tickets/Chats/E-Mails kopieren oder in Skripten ablegen.
- **Keine „Beweise“ erfinden:** Ein Alarm ohne Evidence ist ein Prüfauftrag, keine Tatsachenbehauptung.
- GeDefense **nicht** als HACCP-/Compliance-Nachweis verwenden.

---

## 4. Wartungsfenster und Fernzugriff

1. **Vor** dem Service: Window anlegen (`admin`):

```bash
curl -s -X POST -H "Authorization: Bearer $GD_TOKEN" -H 'Content-Type: application/json' \
  -d '{"site_id":"filiale-001","zone_ids":["zone-ot-proc-01"],"vendor":"<Dienstleister>",
       "ticket_ref":"<Ticket>","starts_at":"2026-11-04T08:00:00Z","ends_at":"2026-11-04T10:00:00Z",
       "approved_by":"<user_id>","status":"planned","notes":"Kältewartung"}' \
  $BASE/windows
```

   Server setzt fehlende ID/Zeiten/Status nach Vertrag; Validierungsfehler → `400`.
2. **Während** des Service: `/access` beobachten (`windows`, `sessions`, `anomalies`). Sitzungen
   außerhalb des Fensters oder von unerwarteter Quelle = Alert (`off-window`/`untrusted-vendor`).
3. **Nach** dem Service: Window schließen (`POST /api/v1/windows/{id}/close` mit `{"note":"..."}`),
   Ergebnis im Ticket dokumentieren.
4. **Kein** Fenster „auf Vorrat“ offen lassen; `grace_period_s` (Default 300 s) toleriert nur
   überziehende Sitzungen.

---

## 5. WAN-Ausfall und Offline-Betrieb

**Erwartetes Verhalten (by design):** Lokale Erkennung, Alarmierung und UI laufen ohne WAN weiter.
Es gibt **keine** Cloud-Abhängigkeit. Ein WAN-Ausfall beeinträchtigt den Anlagenbetrieb nicht
(Invariante 3, S-04).

| Phase | Anzeichen | Maßnahme |
|---|---|---|
| Ausfall | Zentrale nicht erreichbar; Forwarder-Log zeigt Fehler; Spool wächst | Keine Aktion an der Anlage. Lokal weiterarbeiten; Alerts wie gewohnt bearbeiten |
| Puffer füllt sich | `max_spool_mb` nähert sich; Enqueue-Fehler `ErrSpoolFull` im Log | Verlust ist **sichtbar**, nicht still; Betreiber-IT informieren; WAN priorisieren |
| Wiederkehr | Drain überträgt gepufferte Events (at-least-once, Dedup über `event_id`); Batch gemäß `central.batch_size` | Nach Drain: `/health`, `/audit` prüfen; auf Duplikate/Ordnung achten |

**Regeln:**
- Spool ist **bounded**: ist er voll, werden Events verworfen und gezählt — die Detection läuft weiter.
- Priorisierung: kritische Alerts vor Routine-Telemetrie (Betriebsprozess/SLA).
- **Offener Punkt D-4 (Deployment-Guide §9):** Der Spool-Füllstand ist in API v1 **nicht** als
  Feld exponiert. Prüfung im Betrieb über Log (`ErrSpoolFull`, Forwarder) und Dateisystem:

```bash
# Anzahl/ Größe der Spool-Dateien (Pfad gemäß data_dir)
find /var/lib/gedefense-retail/spool -type f -name '*.json' | wc -l
du -sh /var/lib/gedefense-retail/spool
```

- **Nicht** den Spool manuell löschen, um Platz zu schaffen (Datenverlust/Nachweislücke).
  Stattdessen `max_spool_mb`/Retention mit Betreiberfreigabe anpassen und WAN wiederherstellen.

---

## 6. Neustart, Recovery und Selbsttest

### 6.1 Geplanter Neustart (z. B. nach Update, Deployment-Guide §7)

```bash
sudo systemctl stop gedefense-retail
sudo -u gedefense /opt/gedefense-retail/retaild check --config /etc/gedefense-retail/retail.json
sudo systemctl start gedefense-retail
sudo systemctl status gedefense-retail --no-pager
journalctl -u gedefense-retail -n 100 --no-pager
```

`retaild check` prüft Config, Storage, Policy und Audit-Kette; **Exitcode 0 = ok, 1 = Fehler**.
Bei Exitcode 1 **nicht** starten, Fehler beheben (oder alten Stand wiederherstellen).

### 6.2 Verifikation nach jedem Neustart

| Punkt | Prüfung | Soll |
|---|---|---|
| Dienst | `systemctl status` | `active (running)` |
| Version | `retaild version` | erwartete Version/Commit |
| Health | `GET /health` | `status=ok`, `read_only=true` |
| Audit | `GET /audit` | `chain_ok=true` |
| Storage | `GET /health` → `storage` | Event-Zähler plausibel, `audit_chain_ok=true` |
| Alerts | `GET /alerts?status=open` | offene Alerts wieder da (Persistenz `alerts.json`) |
| Collectors | `GET /collectors` | `running`/`degraded`, `last_event_at` läuft |
| Zeit | `date -u` vs. `health.now` | konsistent (NTP) |

### 6.3 Ungeplanter Ausfall / Recovery

1. **Anlage läuft weiter** — GeDefense ist nicht inline; Ausfall hat keine Anlagenwirkung (S-04).
2. Ursache eingrenzen: `journalctl -u gedefense-retail --since "-2h"`, Disk voll, Rechte, Config.
3. Dienst neu starten (§6.1); wenn Start scheitert: **nicht** Daten löschen, Log sichern und eskalieren.
4. Nach Recovery: Abschnitt 6.2 vollständig prüfen; **Lücke** im Event-Stream dokumentieren
   (Zeitraum ohne Daten ist ein blinder Fleck, kein „alles OK“).
5. Backup/Restore betrifft **nur** GeDefense-Artefakte (Config + `data_dir`-Snapshot), **nie**
   PLC-/Regler-Konfiguration (S-12).

---

## 7. Audit-Verifikation (Hash-Kette)

Die Audit-Kette ist manipulations**erschwerend**, nicht manipulationssicher (Root auf dem Host kann
mehr). Jeder Eintrag: `seq`, `at`, `actor`, `role`, `action`, `object_type`, `object_id`, `prev_hash`,
`hash`; `hash = SHA256(prev_hash ‖ 0x00 ‖ kanonisches JSON)`. Erster `prev_hash` = 64 × `0`.

```bash
curl -s -H "Authorization: Bearer $GD_TOKEN" $BASE/audit | jq '{chain_ok, first_verified_seq}'
# vollständiger Selbsttest inkl. Storage/Policy:
sudo -u gedefense /opt/gedefense-retail/retaild check --config /etc/gedefense-retail/retail.json
```

**Wann prüfen:** nach jedem Neustart/Update, monatlich, bei Verdacht, vor Incident-Export.

**Bei `chain_ok=false`:**
1. **Nichts löschen/reparieren.** Host nicht neu installieren; Dateien sichern (Kopie, keine Änderung).
2. `first_verified_seq` notieren; Zeitfenster und `actor` der Bruchstelle prüfen (API `?limit=`).
3. Prüfen, ob Ursache **Betrieb** (manuelle Dateiänderung, Retention-Lücke, Clock-Sprung) oder
   **Manipulation** (R-05) ist. Beides dokumentieren.
4. Eskalieren an Sicherheitskontakt (§8); Incident-Paket exportieren.
5. Wiederherstellung nur aus geprüftem Backup mit dokumentiertem Verlust-Zeitraum.

**Wichtig:** Ein Kettenbruch ist **kein** automatischer Angriffsbeweis und **keine**
Compliance-Aussage — er ist ein Prüfauftrag.

---

## 8. Eskalationswege (Platzhalter — Betreiber füllt und gibt frei)

> **Diese Tabelle ist ein Platzhalter.** GeDefense erfindet keine betrieblichen Notfallanweisungen
> (Baukonzept Modul H). Der Betreiber hinterlegt freigegebene Kontakte, Zeiten und Vertretungen.

| Stufe | Auslöser | Kontakt (Betreiber füllt) | Zielzeit | Kanal |
|---|---|---|---|---|
| 0 – Lokal | Alert `info`/`low` | Filialleitung / Store-IT | nächster Arbeitstag | [z. B. Telefon] |
| 1 – Technik | `high`, Thermal/DataQuality | [Kältetechnik-/Store-IT-Kontakt] | [z. B. 30 min] | [Telefon] |
| 2 – Sicherheit | `critical`, `access`/`network`/`integrity`, `write_attempt` | [Betreiber-IT/SOC] | [z. B. 15 min] | [Telefon] |
| 3 – Management | bestätigter Incident, Audit-Kettenbruch | [Betreiber-verantwortlich + Datenschutz] | [z. B. 60 min] | [Telefon/E-Mail] |
| Anlage/Hersteller | Anlagenstörung (nicht Cyber) | [Kältehersteller-Service] | [SLA] | [Telefon] |

**Pflichtangaben je Kontakt (vom Betreiber zu ergänzen):** Name, Rolle, Telefon, E-Mail, Vertretung,
Erreichbarkeit, Eskalationsreihenfolge, Ticket-/Referenzformat. Policy-Feld
`alerting.escalation[]` (`after_minutes`, `role`, `channel`, `note`) spiegelt diese Stufen für das
System; die **Auslieferung** an Telefon/E-Mail ist Betreiberprozess (offener Punkt P-2 in
`retail-policy-reference.md` §13).

**Kontakt-Platzhalter (nicht produktiv):**

```text
Betreiber-IT / SOC:        [NAME, TELEFON, E-MAIL]
Anlagenverantwortlicher:   [NAME, TELEFON, E-MAIL]
Filialleitung:             [NAME, TELEFON]
Kälte-/Anlagenhersteller:  [FIRMA, SERVICE-TELEFON, VERTRAGS-NR.]
Datenschutzbeauftragte/r:  [NAME, E-MAIL]
```

---

## 9. Benutzer, Tokens, Zugriff

- Token erzeugen (auf dem Gateway, nicht auf Arbeitsplätzen):
  `retaild gen-token --user <user_id> --role <viewer|operator|admin>` → druckt Token **einmal** und
  `token_sha256` für `users[]`. Das Klartext-Token **nur** an die Person übergeben (Passwortmanager).
- Rotation: neuen Hash in `retail.json` eintragen → Dienst **neu starten** (Config wird beim Start
  gelesen) → altes Token ist ungültig. Sofort bei Personalwechsel, Verlust, Verdacht.
- Kein Token im Query-String, in Cookies, Tickets oder Skripten. `viewer` = minimaler Zugang.
- Rate-Limit: 120 req/min pro Token (Burst 40) → `429` mit `Retry-After`; keine Poll-Schleifen.

---

## 10. Logs, Retention, Rotation, Datenträger

| Thema | Zustand / Einstellung | Prüfung |
|---|---|---|
| Anwendungslog | `slog` strukturiert nach stdout → **journald** (`journalctl -u gedefense-retail`) | Rotationsgröße über journald (`SystemMaxUse`) begrenzen |
| Event-Log | append-only JSONL, Rotation nach Größe/Datum (`events-<utcdate>.jsonl`) | Dateien im `data_dir`; Größe vs. `retention.max_event_mb` |
| Retention | `retention.*` aus Policy (Defaults: 30/180/365 Tage) | Löschung soll auditpflichtig sein (`action=retention.delete`, vorgesehen gemäß `data model` §6) |
| Alerts | `alerts.json` (atomar, 0600) | Persistenz nach Neustart prüfen |
| Audit | hash-chained, append-only | §7 |
| Spool | bounded (`max_spool_mb`) | §5 |
| Datenträger | `data_dir` auf eigenem, überwachtem Volume | `df -h`; Warnung vor voller Disk |

**Disk-Full-Verhalten:** Schreibfehler werden sichtbar (Log, Health-Counter); Detection läuft weiter.
**Nicht** eigenmächtig Retention verkürzen oder Dateien löschen — Betreiberfreigabe + Audit.

---

## 11. Fehlerbilder (Kurz-Triage)

| Symptom | Wahrscheinliche Ursache | Maßnahme |
|---|---|---|
| `401 unauthorized` trotz Token | Token falsch/rotiert/Whitespace | Token neu erzeugen; Header prüfen |
| `403 forbidden` | Rolle zu schwach (`viewer` für Schreibaktion) | passende Rolle zuweisen (minimal) |
| `429 rate_limited` | Poll-Schleife | `Retry-After` abwarten; Polling reduzieren |
| `collectors[].state=failed` | Ziel nicht erreichbar, Options falsch, Config-Fehler | `last_error` lesen; Deployment-Guide §8; Startlog prüfen |
| Keine Events, Collector `running` | falsches Ziel/Topic/OID, kein Verkehr am TAP/Feed | Feed prüfen (§5 Deployment-Guide); `asset_seen`-Test |
| Thermische Alerts fehlen | keine/fehlerhafte Policy-Limits | Policy-Referenz §12; `/coldchain` auf fehlende Grenzwertangaben prüfen |
| `chain_ok=false` | Manipulation oder Betriebsfehler | §7 |
| Health `degraded` | Spool/Storage/Adapter degradiert | Health/Logs; §5/§10 |
| UI lädt, SSE bricht ab | Netz/Proxy, 30-min-Server-Limit | Client reconnectet; Verbindung prüfen |

---

## 12. Übergabe- und Routinechecklisten

**Schichtübergabe:** offene Alerts + Assignee, laufende Wartungsfenster, bekannte Störungen,
Spool-/WAN-Zustand, offene Incidents.

**Monatlich:** Audit-Kette prüfen (§7), Retention-Größen vs. Disk, Collector-Health-Trend,
Alerts-Review (Fehlalarme → Regeln/Policy nach Prozess anpassen), Token-Bestand prüfen.

**Quartalsweise:** `trusted_vendors[]`/Allowlist aktualisieren, Sichtbarkeitslücken (TAP/Feed),
Update-/Rollback-Prozess mit Betreiber-IT abstimmen, Restrisiken aus `security assumptions` §8
bestätigen.

**Immer:** Kein Eingriff in die Anlage. Kein Löschen von Audit-/Event-Daten. Keine
Compliance-Behauptung aus GeDefense-Ausgaben ableiten.


---

## 12. Read-before-Write und Vendor-Katalog (Alpha 0.2.0-alpha.8)

- **Modbus:** Vor jedem freigegebenen Write liest das Gate den CurrentValue erneut.
  `current_value_missing|mismatch|unreadable` ⇒ Deny + Audit, keine automatische Wiederholung.
  Wert/Adresse im Plan prüfen und die Freigabe erneuern.
- **HTTP:** kein generischer Ist-Wert-Recheck; Check-Warnung beachten, Wertbindung im Plan bleibt.
- **Vendor-Katalog:** `data/ot-catalog/` liefert Klassifikation/Advisory, **kein Auto-Allow**;
  unbekannte Assets bleiben unbekannt.
- Bei Katalog-/Datenupdates Paketversion dokumentieren, Audit prüfen und keine Schreibfreigabe
  daraus ableiten.
