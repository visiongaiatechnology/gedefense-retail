# Access Gate — API-Contract (Alpha 0.2.0-alpha.8)

Öffentliche Kurzfassung des Gate-API-Contracts. Sie beschreibt das **Verhalten**, nicht interne
Implementierungsdetails. Ergänzende Dokumente: [DEPLOYMENT.md](../DEPLOYMENT.md),
[SECURITY-MODEL.md](../SECURITY-MODEL.md), [API.md](../API.md).

## Rollen und Authentifizierung

- Rollen: `viewer`, `operator`, `approver`, `master_admin`, `vendor_write_requester`, `auditor`.
- Login: Passwort + TOTP (`X-Gate-MFA`), optional Client-Zertifikat; Sessions kurzlebig.
- Alle Schreibzugriffe sind plan-, freigabe- und sessiongebunden; Schreiben ist Default-Deny.

## WritePlan und Werte-Modell

Ein Plan bindet Ziel, Protokoll, Funktion, Adresse und Werte:

```json
{"target_id":"aksm-1","protocol":"modbus_tcp",
 "operations":[{"operation_id":"op-1","protocol":"modbus_tcp","function":"fc6",
                "address":"40001","current_value":"4.0","new_value":"3.5",
                "value_scale":0.1,"unit":"celsius"}],
 "reason":"Sollwert nach Wartung","ticket_ref":"SVC-2026-1104",
 "window_start":"2026-11-04T06:00:00Z","window_end":"2026-11-04T08:00:00Z"}
```

- `current_value`/`new_value` sind **Anzeigewerte**. `value_scale` hat Default `1.0` und ist der
  Faktor zwischen Anzeige- und Rohwert: **Rohwert = round(Anzeigewert / value_scale)**. Beispiel:
  `current_value 4.0` / `new_value 3.5` bei `value_scale 0.1` ⇒ Rohwert `40 → 35`.
- Dezimalwerte (mit `.`) **erfordern** `value_scale`; sonst wird der Plan mit `400` abgelehnt.
  `retailgate check` warnt zusätzlich. Ohne `value_scale` sind nur ganzzahlige Rohwerte zulässig.
- Der Plan-Hash bindet Ziel, Funktion, Adresse, Anzeigewerte, `value_scale` und Zeitfenster; eine
  Änderung nach Freigabe ist ein `409 plan_hash_mismatch`.

## Read-before-Write (Modbus)

1. Bei der **Freigabe** wird der aktuelle Gerätewert noch nicht abschließend verifiziert.
2. **Unmittelbar vor dem Write** liest das Gate den Ist-Wert erneut: FC3 (Holding Register) bzw.
   FC1 (`read_coils`, für Coil-Writes). Der gelesene Rohwert wird über `value_scale` in den
   Anzeigebereich umgerechnet und mit `current_value` verglichen.
3. Ablauf ist **verify → consume/audit → forward**: Erst nach erfolgreicher Verifikation werden
   Session/Token verbraucht, das Audit geschrieben und der Write weitergeleitet.
4. Fehler ⇒ Deny + Audit, Modbus-Exception `0x04`:
   - `current_value_missing` — kein/leerer Ist-Wert,
   - `current_value_mismatch` — abweichender Wert,
   - `current_value_unreadable` — Read-Fehler/Timeout.
5. **`read_coils` (FC1) ist ein separates Read-Window.** Modbus-Targets können
   `read_coils: {"fc":1,"start":0,"count":N}` konfigurieren. FC5/FC15-Writes benötigen es; fehlt es,
   verweigert das Gate den Write und `retailgate check` erzeugt einen **fehlschlagenden Check
   `RBC-<target>`** (Warnungen zusätzlich für Modbus-/HTTP-Allowlists bei unvollständiger
   Verifikation).
6. Werte werden über `value_scale` (Default `1.0`) vom Anzeige- in den Rohbereich umgerechnet;
   Dezimalwerte ohne `value_scale` ⇒ `400`.

**TOCTOU-Restfenster:** Zwischen Read und Write bleibt ein kurzes Zeitfenster, in dem ein anderer
Akteur den Gerätewert ändern kann. Das Gate **reduziert** dieses Fenster (Reread unmittelbar vor dem
Write, kurze Sessions/Timeouts), **schließt es aber nicht vollständig**. Gegenmaßnahmen sind
Geräte-Interlocks, Monitoring/Alarme auf unerwartete Änderungen und kurze Freigabefenster. Es gibt
keine Garantie „TOCTOU-frei".

## HTTP(S)-Grenze

- Für HTTP(S)-Supervisor-Oberflächen gibt es **keinen generischen Ist-Wert-Recheck** (Formular-/JSON-
  Werte sind nicht universell lesbar).
- Es bleibt bei URL-/Methoden-Allowlist und Wertbindung im Plan; `retailgate check` warnt, wenn
  keine Wertverifikation möglich ist. Das ist **keine** gleichwertige Read-before-Write-Garantie.

## Freigabe, Token, Session

- Freigabe: Vier-Augen bei kritischen Assets, `master_admin`-Beteiligung, Self-Approval verboten.
- Einmal-Token wird einmalig angezeigt, an Plan-Hash und Quell-IP gebunden, mit TTL.
- Session-Verbrauch erst nach erfolgreicher Verifikation; abgelaufene/falsche Sessions ⇒ Deny +
  Audit.

## Fehler- und Deny-Codes (Auszug)

`400 invalid_request` · `403 target_not_allowed` / `role_required` / `mfa_required` ·
`404 not_found` · `409 plan_hash_mismatch` / `window_expired` / `self_approval` ·
`429 rate_limited`; Deny-Reasons u. a. `operation_not_approved`, `outside_window`,
`session_expired`, `current_value_missing`, `current_value_mismatch`,
`current_value_unreadable`.

## Keine Compliance-Aussage

Dieser Contract ist eine technische Verhaltensbeschreibung der Alpha. Er ist keine HACCP-, NIS2-,
IEC-62443- oder sonstige Zertifizierungs-/Konformitätsaussage.
