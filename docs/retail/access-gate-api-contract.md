# Access Gate — API-Contract (Alpha 0.3.0-alpha.1)

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

---

## Integrität, Recovery und Netzwerk-Enforcement (Alpha 0.3.0-alpha.1)

### Setpoint-Integrität

`GET /api/v1/gate/integrity` (viewer/approver/master/auditor) liefert die `integrity`-Referenzen mit
Ziel/FC/Register/Unit, erwartetem Wert/Scale, letztem Ist-Wert/Zustand, letzter Prüfung und
Recovery-Statistik (Aktionen Stunde/Tag, Cooldown, letzter
`gate.recovery.applied|failed|unknown`). SSE-Clients erhalten `gate_integrity`-Events.

```json
"integrity": {
  "enabled": true, "poll_interval_s": 60, "confirm_reads": 3, "stale_after_s": 180,
  "references": [{"target_id":"aksm-1","fc":3,"register":40002,"unit_id":1,
                  "value":"4.0","scale":0.1,"unit":"celsius",
                  "note":"Sollwert Fleischraum","recovery":true}],
  "recovery": {"enabled": false, "max_actions_per_hour": 3, "max_actions_per_day": 10,
               "cooldown_s": 600, "require_no_active_window": true}
}
```

- **Config/Validierung:** `enabled=true` braucht mindestens eine Referenz; `poll_interval_s` 10–86400,
  `confirm_reads` 1–5, `stale_after_s` > `poll_interval_s`; Referenz-Target `modbus_tcp`, `fc=3`,
  `register` im `read_registers`-Fenster, `value` numerisch/uint16-fähig, keine Duplikate
  (`target_id, unit_id, register`). `recovery.enabled` Default **false**; bei Aktivierung
  `max_actions_per_hour/day` ≥1 (Stunde ≤ Tag), `cooldown_s` ≥60,
  **`require_no_active_window=true` verpflichtend**.
- **Fail-safe:** bei Gate-`AllowWrite=false` keine Integrity-Reads/Recovery.
- **Audit-fail-closed:** ohne Audit-Intent kein Recovery-Write; Audit-Fehler nach dem Write ⇒
  `gate.recovery.unknown`, **kein Retry**.
- **Ein Versuch pro bestätigtem Mismatch** (keine Flapping-Schleife); FC3-Re-Read vor FC6 ist
  **nicht atomar** (TOCTOU-Restfenster).
- **Recovery** nur für `"recovery": true`-Referenzen, ohne Plan/Session, mit Rate-Limit/Cooldown und
  Read-back; `failed`/`unknown` erfordern Betreiberaktion. Kill-Switch:
  `recovery.enabled=false` + Reload/Restart.
- **Grenzen:** kein Beweis über externe Schreiber, nur Modbus FC3/FC6 (HTTP ohne
  Integrity/Recovery), Referenzwerte sind Betreiber-Freigabe (kein HACCP-/Compliance-Beweis).

### Netzwerk-Enforcement

`retailgate netpolicy --config gate.json --format nftables|iptables --gate-source <CIDR>
[--out FILE] [--check] [--apply] [--rollback]` akzeptiert neue Verbindungen zu Reglern nur von
Gate-Quell-CIDRs (sonst drop + Log), eigene Table/Chain. Voraussetzung: Routing/NAT/Bridge und
Segmentierung am Gate-Host; kein Router-Feature, Wirkung nur auf dem Gate-Host.
