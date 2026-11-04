# Access Gate — Vendor-Onboarding und Offboarding (Dienstleister)

**Status:** Alpha 0.3.0-alpha.1 **implementiert** (Gate-E2E 25/25; Details `alpha verification report`); **keine** echte OT-Hardware/Produktionsfreigabe
**Produkt:** GeDefense Retail Access Gate (`retailgate`) 0.2 Alpha
**Quellen:** [deployment-guide.md](deployment-guide.md), [operations-runbook.md](operations-runbook.md),
[retail-policy-reference.md](retail-policy-reference.md),
[access-gate-vendor-workflows.md](access-gate-vendor-workflows.md),
[access-gate-api-contract.md](access-gate-api-contract.md)

> **Zweck:** Ein Dienstleister (Kälte-/Anlagentechnik) erhält **keinen** direkten Gerätezugang.
> Er erhält ein lokales Gate-Konto, MFA, ein clientzertifikatgebundenes Gerät, ein Ticket und — pro
> Änderung — einen **freigegebenen Write-Plan** mit exakt definierten Werten. Schreiben ist
> Default-Deny; Lesen bleibt über die 0.1-Sichtbarkeit möglich.
> Der Dienstleister terminiert **am Gate** (Segment S3 → Gate-Appliance, NIC1), **nie** am Regler;
> das Gate leitet ausschließlich über das Conduit (NIC2/S4) weiter.
>
> **Grenzen:** Dieser Prozess ist **kein** Ersatz für Betreiber-Freigabe, HACCP oder Hersteller-
> Support. Er erzeugt **keine** Compliance-Aussage. Das Gate ist **opt-in**; die S-01-Ausnahme nur
> für `retailgate` ist durch das Gate-Design begründet (Autorisations-Proxy). Die Alpha ist implementiert
> (0.3.0-alpha.1, Gate-E2E 25/25), aber **nicht** gegen echte OT-Hardware/Produktion verifiziert —
> Schritte bleiben bis Pilot/Retest **Soll-Prozess**.

---

## 1. Rollen im Onboarding

| Beteiligter | Rolle im Gate | Aufgabe |
|---|---|---|
| Betreiber-IT / Plattform | `master_admin` | Konto anlegen/deaktivieren, Zertifikat binden, Policy/Notify |
| Anlagenverantwortlicher | Betreiberprozess (ggf. `approver`) | fachliche Freigabe der Änderung, Ticket |
| Dienstleister-Techniker | `vendor_read` + `vendor_write_requester` | Plan anlegen, Session nutzen, Änderung durchführen |
| Dienstleister-Leitung | – (Vertrag/Prozess) | benannter Ansprechpartner, Vertretung, Offboarding |
| Auditor | `auditor` | Nachweisprüfung (kein Schreibrecht) |

**Grundsätze:** Eine **Person = ein Konto**; kein geteiltes Dienstleister-Konto. Schreibrechte nur
über `vendor_write_requester` **plus** freigegebenen Plan. `master_admin` wird **nie** an einen
Dienstleister vergeben.

---

## 2. Voraussetzungen (vor Schritt 1)

- [ ] Betreiberfreigabe für den Dienstleister (Vertrag, Ansprechpartner, Vertretung, Eskalationsweg).
- [ ] Segmentierung steht: Dienstleister erreicht **nur** das Gate, nicht die Regler direkt
      (Netz-Blueprint + Bypass-Inventar, Plan Punkt 3).
- [ ] Gate läuft mit gültiger Policy, `default_deny=true`, `source_cidrs` für das Dienstleister-Netz.
- [ ] TLS/mTLS am Gate aktiv, `client_ca_file` gesetzt, `require_client_cert=true`
      (oder dokumentierte Ausnahme mit Betreiberfreigabe — nicht empfohlen).
- [ ] Ticket-/Freigabeprozess und Anlagenverantwortlicher benannt.
- [ ] Offboarding-/Widerrufsprozess (Abschnitt 8) vorab definiert.

---

## 3. Onboarding-Schritte (Soll-Prozess)

### Schritt 1 — Identität beantragen

Der Dienstleister benennt: vollständiger Name, Firma, Rolle, E-Mail, Telefon, Vertretung,
Geräte (Hostname/Seriennummer), Nutzungszeitraum. Der Betreiber prüft Vertrag/Ticket und legt
die Identität an. **Kein** Konto auf Zuruf, keine Sammelkonten.

### Schritt 2 — Gate-Konto anlegen (`gate.json users[]`)

```json
{
  "user_id": "vendor-acme-01",
  "name": "Max Beispiel (ACME Kältetechnik)",
  "kind": "vendor",
  "roles": ["vendor_read", "vendor_write_requester"],
  "password_hash": "pbkdf2-sha256$210000$<saltB64>$<hashB64>",
  "totp_secret": "<BASE32>",
  "totp_enabled": true,
  "device_fingerprints": ["<sha256-hex-der-client-cert>"],
  "status": "active"
}
```

- Passwort-Hash **nur** über `retailgate hash-password` erzeugen (PBKDF2-HMAC-SHA256, Format
  `pbkdf2-sha256$<iter>$<salt>$<hash>`); Klartext-Passwort nie in `gate.json`/Ticket/Chat.
- TOTP-Secret über `retailgate totp` erzeugen; Übergabe an die Person über sicheren Kanal
  (Passwortmanager/QR), danach Secret nur in `gate.json` (Datei 0600).
- **OFFEN (Implementierung):** exakte CLI-Flags von `retailgate hash-password/totp` sind im
  Gate-Contract nur als Subkommandos benannt — bei Implementierung verifizieren.

### Schritt 3 — MFA einrichten

TOTP in der Authenticator-App des Technikers registrieren; Test-Login durchführen
(`POST /api/v1/gate/auth/login` mit `totp`). TOTP-Replay-Schutz und ±1-Fenster gelten serverseitig.
MFA ist **Pflicht** für jede Freigabe; ein Login ohne TOTP ist für schreibende Rollen unzulässig.

### Schritt 4 — Client-Zertifikat ausstellen und Gerät binden

1. Betreiber-PKI stellt ein **Client-Zertifikat** für das Dienstleister-Gerät aus
   (eigene CA, kurze Laufzeit passend zum Einsatz, Widerrufsliste gepflegt).
2. Fingerprint berechnen (SHA-256 über die DER-Kodierung des Zertifikats) und in
   `users[].device_fingerprints` eintragen.
3. Gate-Konfiguration prüfen (`retailgate check`) und Dienst neu starten (Konfiguration wird beim
   Start gelesen).
4. Test: Login **ohne** gültiges Client-Zertifikat muss `403 device_not_bound` liefern;
   mit Zertifikat `200` + `mfa_ok=true`.

**Beispiel-Fingerprint (nur Beispiel, kein Secret):**
`openssl x509 -in vendor.crt -outform der | sha256sum` → 64 Hex; Wert in die Config übernehmen.
**Kein** privater Schlüssel verlässt das Dienstleister-Gerät; Betreiber speichert **keine** privaten
Schlüssel.

### Schritt 5 — Leserechte testen (ohne Schreibpfad)

`POST /auth/login` → Bearer `gst_…`; `GET /auth/me`, `GET /plans` (eigene), `GET /status`
(nur falls Rolle es erlaubt). **Wichtig:** Ein `vendor_read`/`vendor_write_requester` darf **keine**
direkte Modbus-/HTTP-Verbindung zum Regler haben; der einzige Weg ist das Gate.

### Schritt 6 — Ticket und Plan-Antrag (pro Änderung)

1. Betreiber eröffnet Ticket/Freigabe (Ticket-Ref, Asset, gewünschte Änderung, Begründung, Fenster).
   **Alpha-Hinweis:** `ticket_ref` ist im Plan **optional** (`access-gate-vendor-workflows.md` §4.2:
   kein belegter DE-Freigabeprozess) — `reason` bleibt Pflicht; die Freigabe erfolgt über Plan/
   Approval, nicht über das Ticketfeld. Der Betreiber kann das Feld später verpflichtend machen.
2. Dienstleister erstellt `POST /api/v1/gate/plans` mit Ziel, Protokoll, Operationen
   (`function`, `address`, `current_value`, `new_value`, Einheit), Grund, `ticket_ref`,
   `window_start`/`window_end` (≤ 24 h, nicht in der Vergangenheit).
3. Server berechnet `plan_hash` und liest/vergleicht `current_value` (Abweichung ⇒
   `400 current_value_mismatch`).

### Schritt 7 — Freigabe (Betreiber, Vier-Augen)

- `approver` prüft Plan, Hash und Fenster: `POST /plans/{plan_id}/approve` mit `X-Gate-MFA`.
- **Self-Approval verboten**; bei `critical_assets`/`four_eyes_assets`: zwei **verschiedene**
  Approver, mind. eine `master_admin`-Freigabe.
- Erst bei vollständiger Freigabe erscheint der **Einmal-Token** (`token`) **einmalig** in der
  Antwort. Ablehnung/Ablauf erzeugt Alarm.

### Schritt 8 — Session lösen und Änderung durchführen

1. `POST /api/v1/gate/sessions` mit `{plan_id, token}`; die **Source-IP** ist die Verbindungsquelle
   (kein Client-Header). Antwort: `ses_…`, `source_ip`, `max_uses`, `expires_at`.
2. Verbindung zum **Gate-Listener** des Targets auf der **Gate-Appliance** (NIC1/`eth-mgmt`, aus
   S3), z. B. Modbus `retailgate:<listen>` bzw. HTTPS an die Gate-UI — **nicht** zum Gerät direkt.
3. Genau die geplanten Operationen ausführen. Jede Abweichung (anderes Register, anderer Wert,
   anderes Fenster, fremde IP) ⇒ Deny + Critical-Alarm + Audit.
4. Lesende Kontrollwerte (Nachher-Wert) ablesen und im Ticket dokumentieren.
5. **Unklare Geräteantwort** (Timeout/Disconnect) ⇒ Zustand **`write_unknown`**: Critical-Alert,
   **Read-back prüfen, KEIN Retry**, keine neue Schreiboperation ohne neuen Plan/Freigabe; Incident
   nach Betreiberprozess.

### Schritt 9 — Abschluss

- Session beenden (`DELETE /sessions/{session_id}`) bzw. TTL ablaufen lassen; Plan → `executed`.
- Nachher-Werte + Ergebnis ins Ticket; Anlagenverantwortlicher bestätigt.
- Audit prüfen: `GET /audit` (`chain_ok=true`), `GET /denies` für den Zeitraum (Soll: keine
  ungeplanten Versuche).
- Ende des Einsatzes: Konto bleibt bestehen, Schreibrechte nur über neue Pläne; sonst Offboarding.

---

## 4. Pflicht-Checkliste je Einsatz

- [ ] Ticket/Freigabe vorhanden, Anlagenverantwortlicher benannt
- [ ] Plan mit Ist→Soll, Grund, Fenster, Ticket-Ref erstellt
- [ ] `plan_hash` unverändert; `current_value` geprüft
- [ ] Freigabe(n) vollständig (Vier-Augen bei critical), MFA verwendet
- [ ] Token **einmalig** erhalten, nicht weitergegeben, nicht gespeichert
- [ ] Session von erwarteter Source-IP, max. 1 Nutzung
- [ ] Nur geplante Operationen; keine Abweichung
- [ ] Nachher-Wert gelesen + dokumentiert
- [ ] Session beendet, Audit/Denies geprüft, Ticket geschlossen

---

## 5. Was der Dienstleister nicht darf

- Direktverbindung zum Regler/Supervisor (auch nicht „nur zum Lesen“ außerhalb der 0.1-Sichtbarkeit
  des Betreibers) oder Umgehung des Gates.
- Werte außerhalb des freigegebenen Plans ändern, „weil es gerade passt“.
- Freigaben selbst erteilen, Token weitergeben/teilen, Konto mit Kollegen teilen.
- Firmware-/Programm-Updates, PLC-Restore, Aktorik, Anlagenabschaltung.
- Secrets (Token, TOTP-Secret, Zertifikatsschlüssel) in Tickets/Chats/E-Mails kopieren.
- Behaupten, eine Änderung sei „von GeDefense freigegeben“ — freigegeben wird durch **Personen**
  im Betreiberprozess, das Gate setzt die technische Grenze.

---

## 6. Sonderfälle

| Fall | Vorgehen |
|---|---|
| Token verloren/abgelaufen | Kein Problem: Token einmalig/zeitgebunden; neuen Plan/Freigabe anfordern. Kein Klartext-Token liegt beim Betreiber. |
| Zertifikat/Gerät verloren | Betreiber deaktiviert Konto sofort (`status=disabled`), entfernt Fingerprint, widerruft Zertifikat; Neuausstellung nur mit Ticket. |
| Techniker verlässt Firma | Offboarding (Abschnitt 8) noch am selben Tag; keine „Übergangsrechte“. |
| Verdacht auf Missbrauch | Konto/Sessions widerrufen, Denies/Audit sichern, Security-Eskalation (Runbook §8), Incident öffnen. |
| Plan passt nicht (Gerät liefert anderen Ist-Wert) | Plan abbrechen, neuen Plan mit korrektem Ist-Wert; **nicht** ad hoc schreiben. |
| Fenster überschritten | Session endet/Deny; neuer Plan + Freigabe. |
| Notfall „Gate down“ | Kein Bypass durch Dienstleister; Betreiber-Notfallprozess (Runbook §6), Vor-Ort-Zugang gemäß Betriebskonzept. |

---

## 7. Nachweise und Aufbewahrung

- Konto-Datensatz (ohne Secrets), Rollen, Zeitraum, Vertretung, Gerät/Fingerprint.
- Ticket + Plan + Freigaben + Token-Ausgabezeit + Session + Nachher-Werte.
- Gate-Audit (`gate.write.allowed`, `gate.write.denied`, Plan-/Session-Events) — Retention gemäß
  Gate-Contract §6 (Audit 365 Tage, Denies 180 Tage, Pläne 365 Tage, konfigurierbar).
- **Keine** Klartext-Secrets in Nachweisen. Audit ist hash-chained und manipulationserschwerend.

---

## 8. Offboarding / Widerruf (verbindlich, sofort wirksam)

1. **Konto deaktivieren:** `users[].status = "disabled"` in `gate.json`; `retailgate check` + Neustart.
2. **Sessions widerrufen:** `DELETE /api/v1/gate/sessions/{session_id}` für alle aktiven Sessions
   der Person (approver/master_admin), Audit prüfen.
3. **Token:** laufen mit TTL ab; bei Verdacht zusätzlich Plan/Session widerrufen.
4. **Zertifikat:** Zertifikat in der Betreiber-PKI widerrufen; Fingerprint aus `gate.json` entfernen.
5. **TOTP-Secret:** Datensatz entfernen; bei Verdacht Secret neu erzeugen (neues Gerät).
6. **Nachweis:** Offboarding-Datum, Akteur, Ticket, Audit-Eintrag dokumentieren.
7. **Vertretung:** Übergabe nur über neuen, benannten Account — kein Passwort-/Token-Sharing.
8. **Widerrufstest (Pilot):** Login muss `403 user_disabled` liefern; alte Session muss sofort
   unwirksam sein (Proxy prüft `revoked`).

**SLA-Empfehlung (Betreiber):** Deaktivierung bei Personalende/Verdacht **innerhalb von 1 Stunde**;
bei Kündigung vor dem letzten Arbeitstag. Keine Ausnahmen „bis das Ticket fertig ist“.

---

## 9. Offene Annahmen (G0, vor Integration zu klären)

| ID | Offene Annahme | Klärung |
|---|---|---|
| VO-1 | exakte CLI-Flags von `retailgate hash-password/totp` | bei Implementierung verifizieren |
| VO-2 | Zertifikatsausstellung/Widerruf über Betreiber-PKI (nicht im Produkt) | Betreiberprozess + CA festlegen |
| VO-3 | TOTP-Auslieferung (QR/Secret) ist organisatorisch, nicht API | Datenschutz/Sicherheitsprozess |
| VO-4 | ob `vendor_read` GET auf `targets` erhält oder nur `me` | API-Referenz bei Implementierung präzisieren |
| VO-5 | Vertretungs-/Schichtmodell für Approver | Betreiber-Policy |
| VO-6 | Aufbewahrungsfristen je Betreiber/Rechtsrahmen | Datenschutz/Betriebsrat |
| VO-7 | Break-Glass/Notfallschreibpfad nicht definiert | Betreiber entscheidet (Scope §9) |
| VO-8 | Alpha-Grenzen: TOTP statt FIDO2, keine Event-Brücke (Bypass nur 0.1-Regel + manuelle Korrelation), `write_unknown`=Read-back/kein Retry, keine BACnet/MQTT-Datenplane, keine Cloud-/HMI-Kontrolle | bei Onboarding/Schulung ausdrücklich nennen |
