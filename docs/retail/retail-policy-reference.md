# Retail Policy Reference — GeDefense Retail (Alpha 0.2.0-alpha.8)

**Status:** Referenz für Betreiber/Administratoren · **Stand:** 2026-11-03 · **Produkt:** GeDefense Retail 0.1.0 (ColdChain & Store Infrastructure Security)
**Quellen:** `src/retail/internal/domain/policy.go` (bindend), `engineering contract` §5.4/§5.10, `data model` §4.7, `threat-model.md`, `safety-boundaries.md`

> **Grundsatz (hart):**
> 1. GeDefense Retail enthält **keine universellen Temperaturgrenzwerte**. Grenzwerte existieren nur,
>    wenn der Betreiber sie in der Policy setzt (Invariante 4 des Engineering Contract, S-08).
> 2. Der **Betreiber verantwortet Inhalt, Freigabe und Aktualität der Policy.** GeDefense liefert
>    technische Plausibilitätsprüfung, **keine** rechtliche Produktfreigabe und **keine** HACCP-,
>    NIS2- oder Zertifizierungsaussage. Die in §10 genannten Beispielwerte sind **Beispiele**, keine
>    Vorgaben und keine Rechtsaussage.
> 3. Policy-Änderungen sind versioniert, begründungspflichtig und auditpflichtig (§7).

---

## 1. Wirkungsmodell

```text
domain.Policy (je Site, unveränderliche Versionen)
  ├─ temperature   → retail.thermal.limit / .rate / .setpoint-deviation / .sensor-divergence
  ├─ sensors       → retail.thermal.sensor-divergence (Plausibilität unabhängiger Sensoren)
  ├─ network       → retail.net.unknown-peer, Baseline/Allowlist
  ├─ maintenance   → retail.access.off-window / .untrusted-vendor
  ├─ data_quality  → retail.dq.frozen-value / .gap / .clock-skew
  ├─ retention     → lokale Speicherung (EventLog, AlertStore, AuditLog, Spool)
  └─ alerting      → Dedup/Eskalation/Notify-Schwelle (alert.Engine)
```

- Eine Policy gehört zu **genau einer Site** (`policy_id` = `policy-<site_id>` per `DefaultPolicy`).
- Jede Änderung erzeugt eine **neue, unveränderliche Version** (`policy-versions.jsonl`, append-only);
  die aktuelle Version liegt atomar in `policy.json` (Details in `internal/policy`).
- Der Policy-Hash ist der SHA-256 des kanonischen JSON **nach** Setzen aller Zeitfelder in UTC
  (Engineering Contract §5.4). Das exakte Ausgabeformat (Hex-Präfix) liefert `internal/policy`.
- Fehlt ein Grenzwert, wird **nicht** thermisch alarmiert. „Kein Alert“ bedeutet also **nicht**
  „Temperatur in Ordnung“, sondern „keine Policy-Grundlage für eine Aussage“.

---

## 2. Kopffelder (`domain.Policy`)

| Feld | Bedeutung | Default / Pflicht | Sichere Werte | Wirkung | Typische Fehlkonfiguration |
|---|---|---|---|---|---|
| `policy_id` | stabile ID der Policy einer Site | `policy-<site_id>` (DefaultPolicy) | unverändert lassen | Zuordnung API/Audit/Export | manuell geändert → Audit/Referenzen brechen |
| `site_id` | zugehörige Filiale | Pflicht, validiert | exakt `site.site_id` aus `retail.json` | Scoping aller Queries | Tippfehler → Validierungsfehler beim Start/Reload |
| `version` | Versionsnummer, monoton | Pflicht ≥ 1 | vom System erhöht | Nachvollziehbarkeit, Diff-Basis | manuell zurückgesetzt → Verwirrung im Audit |
| `updated_at` | Zeitpunkt der Version (UTC) | Pflicht, nicht Null | Systemzeit/NTP | Audit, „seit wann gilt das?“ | manuell gesetzt → falsche Zeitlinie |
| `updated_by` | Akteur (User-ID) | bei `Update` gesetzt | realer, aktiver `users[].user_id` | Rechenschaft | Fantasie-ID → Audit nicht zuordenbar |
| `reason` | Begründung der Änderung | bei `Update` Pflicht | Ticket/Produkt/Zone konkret | Audit-Nachweis | „Update“/„Fix“ → nicht prüfbar |
| `hash` | kanonischer SHA-256 der Version | von `policy.Manager` gesetzt | nicht manuell setzen | Integritäts-/Diff-Nachweis | manuell gesetzt → irreführend |

**Regel:** `policy_id`, `site_id`, `version`, `hash` werden **nicht** von Hand gepflegt. Der Betreiber
ändert fachliche Felder + `reason`; Version/Hash/Zeitstempel setzt die Software.

---

## 3. Temperatur (`temperature`)

### 3.1 `temperature.limits[]` — `domain.TemperatureLimit`

Ein Eintrag je **Zone + Metrik**. Mehrere Einträge pro Zone sind erlaubt (z. B. `air_temperature`
und `product_temperature`).

| Feld | Bedeutung | Default | Sichere Werte | Wirkung | Fehlkonfiguration |
|---|---|---|---|---|---|
| `zone_id` | betroffene Zone | Pflicht, validiert | `site.zones[].zone_id`; typisch `cooling_area` für Produktgrenzwerte | Grenzwert gilt nur dort | unbekannte Zone → Limit wirkt nie (still!) |
| `metric` | Messgröße | Pflicht | `air_temperature`, `product_temperature` | Kanalbindung | Tippfehler → keine Auswertung |
| `min_c` | unterer Grenzwert (°C) | nicht gesetzt (nur Obergrenze prüfen) | produkt-/prozessabhängig, **vom Betreiber bestätigt** | `retail.thermal.limit` `below_min` | zu eng → Alarmflut bei Abtau/Tür |
| `max_c` | oberer Grenzwert (°C) | nicht gesetzt (nur Untergrenze prüfen) | produkt-/prozessabhängig | `retail.thermal.limit` `above_max` | zu weit → echte Abweichung unentdeckt |
| `max_rate_c_per_min` | max. Änderungsrate (°C/min) | nicht gesetzt → Ratenregel ohne Schwelle | > 0; typ. 0.3–1.0 (Beispiel) | `retail.thermal.rate` | ≤ 0 → **Validierungsfehler** |
| `setpoint_tolerance_c` | Toleranz Sollwert/Ist | nicht gesetzt → Sollwertabweichung ohne Schwelle | > 0; typ. 0.5–2.0 (Beispiel) | `retail.thermal.setpoint-deviation` | zu klein → Rauschen als Abweichung |
| `valid_from` | Gültigkeit ab (UTC) | Null = immer | Datum der Freigabe | zeitliche Staffelung | in der Zukunft → Limit wirkt jetzt nicht (bewusst, aber oft vergessen) |

**Validierung (`Policy.Validate`):** `min_c < max_c` (wenn beide gesetzt), `max_rate_c_per_min > 0`,
`zone_id` gültig, `metric` nicht leer. Verstöße → Update/Reload wird abgelehnt.

> **Wichtig:** `min_c`/`max_c` sind **Zeiger** (optional). Nur gesetzte Grenzen werden geprüft.
> Es gibt keinen eingebauten „Kühlschrank-Default“.

### 3.2 `temperature.absolute_impossible_min_c` / `_max_c`

| Feld | Bedeutung | Default | Sichere Werte | Wirkung | Fehlkonfiguration |
|---|---|---|---|---|---|
| `absolute_impossible_min_c` | physikalisch unmögliche Untergrenze | nicht gesetzt | z. B. −45 (Beispiel; Kältetechnik) | Werte darunter = **Datenqualitäts**-Signal, kein „gültig aber alarmierend“ | zu nah am Betriebsbereich → echte Messwerte werden als DQ klassifiziert |
| `absolute_impossible_max_c` | physikalisch unmögliche Obergrenze | nicht gesetzt | z. B. +50 (Beispiel) | s. o. | s. o. |

Diese Grenzen sind **keine** Sicherheitsgrenzwerte, sondern Plausibilitätsgrenzen der Messkette.

---

## 4. Sensor-Plausibilität (`sensors`)

| Feld | Bedeutung | Default | Sichere Werte | Wirkung | Fehlkonfiguration |
|---|---|---|---|---|---|
| `divergence_c` | max. zulässige Differenz zweier **unabhängiger** Sensoren derselben Zone | nicht gesetzt → Divergenzprüfung inaktiv | 1.0–3.0 °C (Beispiel) | `retail.thermal.sensor-divergence` | zu klein → Fehlalarme bei Sensorrauschen; fehlt → Manipulation/Drift unentdeckt |
| `divergence_window_s` | Beobachtungsfenster für Divergenz | 0 (nicht gesetzt) | 300–900 s (Beispiel) | Glättung/Mittelung | zu klein → Einzelmessungen schlagen durch |

Voraussetzung: `Sensor.independent=true` für den Vergleichssensor (siehe `data model`).
Ohne unabhängigen zweiten Sensor ist die Prüfung wirkungslos.

---

## 5. Netzwerk (`network`)

| Feld | Bedeutung | Default | Sichere Werte | Wirkung | Fehlkonfiguration |
|---|---|---|---|---|---|
| `baseline_required` | unbekannte Kommunikationspartner alarmieren | `false` (observe-first) | erst nach Baseline-Phase `true` | `true` → `retail.net.unknown-peer` alarmiert; `false` → nur Beobachtung | zu früh `true` → Alarmflut beim Onboarding |
| `learned_baseline_window_s` | Dauer der passiven Lernphase | 0 (nicht gesetzt) | 86400–604800 s (1–7 Tage, Beispiel) | begrenzt die Lernphase | zu kurz → unvollständige Baseline |
| `allowed_pairs[]` | freigegebene Kommunikationsbeziehungen | leer | einzelne Paare, eng | Ausnahme von unknown-peer | zu breite Paare (nur Zone, kein Ziel) → Blindstelle |
| `monitored_ports[]` | ausgewertete Ziel-Ports | leer = alle | 502, 1883, 47808, 161 | Fokus/Rauschen | leer bei „nur OT beobachten“ → unnötige Flows |
| `unknown_peer_grace_s` | Schonfrist für neue Peers | `3600` (DefaultPolicy) | 3600–86400 s | unterdrückt Alerts kurz nach Start/Änderung | zu groß → Angreifer bleibt lange unauffällig |

`allowed_pairs[]` (`domain.AllowedPair`): `source_asset_id`, `source_zone_id`, `target_asset_id`,
`target_zone_id`, `protocol`, `port` (0–65535), `note`. Leere Felder = „beliebig“ auf dieser Achse.
**Je mehr Achsen leer bleiben, desto breiter die Ausnahme** — bewusst setzen und dokumentieren.

---

## 6. Wartung / Fernzugriff (`maintenance`)

| Feld | Bedeutung | Default | Sichere Werte | Wirkung | Fehlkonfiguration |
|---|---|---|---|---|---|
| `require_window` | externer Zugriff außerhalb eines Wartungsfensters mind. High | `true` | `true` beibehalten | `retail.access.off-window` | `false` → Kernschutz aus, nur Beobachtung |
| `grace_period_s` | Kulanz nach Fensterende | `300` | 0–600 s | verhindert Alarme bei überziehender Sitzung | zu groß → späte Zugriffe unauffällig |
| `trusted_vendors[]` | vom Betreiber freigegebene Dienstleister | leer | exakte, gepflegte Herstellernamen | `retail.access.untrusted-vendor` | veraltete/ungenaue Namen → Fehlalarme; zu breite Liste → Blindstelle |

Wartungsfenster selbst sind **keine** Policy-Felder, sondern `domain.MaintenanceWindow`
(`maintenance_window_id`, `site_id`, `zone_ids[]`, `vendor`, `ticket_ref`, `approved_by`,
`starts_at`, `ends_at`, `target_asset_ids[]`, `allowed_source_cidrs[]`, `status`,
`notes`) und werden über `POST /api/v1/windows` (Rolle `admin`) bzw.
`POST /api/v1/windows/{id}/close` gepflegt (§8).

---

## 7. Datenqualität (`data_quality`)

| Feld | Bedeutung | Default | Sichere Werte | Wirkung | Fehlkonfiguration |
|---|---|---|---|---|---|
| `frozen_value_window_s` | identischer Wert länger als X = verdächtig | `1800` | 1800–3600 s | `retail.dq.frozen-value` | zu klein → stabile Kühlung als Fehler; fehlt → „eingefrorene“ Anzeige unentdeckt |
| `telemetry_gap_s` | ausbleibende Telemetrie = Lücke | `900` | 600–1800 s | `retail.dq.gap` | zu klein → Netzwerk-Jitter als Lücke |
| `max_clock_skew_s` | Toleranz `observed_at` vs. Gateway-Uhr | `300` | 60–300 s (NTP nötig) | `retail.dq.clock-skew`, `quality=clock_uncertain` | ohne NTP → massenhafte Clock-Skew-Alarme |

---

## 8. Aufbewahrung (`retention`)

| Feld | Bedeutung | Default | Sichere Werte | Wirkung | Fehlkonfiguration |
|---|---|---|---|---|---|
| `event_days` | Aufbewahrung normaler Events | `30` | ≥ 1; nach Betreiber-/Datenschutzvorgabe | Rotation/Retention des EventLog | zu klein → Baseline/Incident-Nachweis fehlt |
| `alert_days` | Aufbewahrung von Alerts | `180` | ≥ 1 | Alert-Historie | zu klein → Nachvollziehbarkeit leidet |
| `audit_days` | Aufbewahrung Audit-Log | `365` | ≥ 1 | Hash-Kette/Rechenschaft | kleiner als Prüf-/Aufbewahrungspflicht → Audit-Lücke |
| `max_event_mb` | Größenobergrenze EventStore | `2048` | ≥ 1; passend zur Disk | Disk-Full-Schutz | zu groß für Disk → Disk-Full-Risiko |
| `max_spool_mb` | Größenobergrenze Offline-Puffer | `512` | ≥ 1; WAN-Ausfalldauer × Aufkommen | Spool-Full = sichtbarer Verlust | zu klein → Pufferüberlauf bei längerem WAN-Ausfall |

Löschung durch Retention soll **auditpflichtig** sein (`action=retention.delete`, vorgesehen gemäß
`data model` §6; Implementierung in `internal/store` bei Integration verifizieren).

---

## 9. Alarmierung (`alerting`)

| Feld | Bedeutung | Default | Sichere Werte | Wirkung | Fehlkonfiguration |
|---|---|---|---|---|---|
| `min_notify_severity` | Mindest-Severity für Benachrichtigung | `high` | `high`/`critical` | `alert.Engine` notifyt nur ≥ Schwelle & Status `open` | `info`/`low` → Benachrichtigungsflut |
| `escalation[].after_minutes` | Wartezeit bis Eskalationsstufe | 0 (nicht gesetzt) | 0–60 min, gestaffelt | Eskalationskette | 0/0/0 → alles gleichzeitig |
| `escalation[].role` | Rolle/Empfänger | Pflicht (nicht leer) | reale Betreiberrolle (z. B. `filialleitung`) | Zuordnung | Rolle existiert im Betreiberprozess nicht → Eskalation ins Leere |
| `escalation[].channel` | Kanal | optional | `local`, `phone`, `email` (Prozess) | Hinweis für Betreiberprozess | Kanal ohne hinterlegten Kontakt (§ Runbook) |
| `escalation[].note` | Hinweis | optional | kurz, konkret | Betriebsanweisung | – |

**MVP-Grenze:** Die Policy definiert die Eskalationsstufen; die **Auslieferung** an Telefon/E-Mail
erfolgt über den freigegebenen Betreiberprozess (Runbook §8). Ein externer Webhook ist nicht Teil
des `config.Config`-Vertrags v1 (offener Punkt P-2).

---

## 10. Beispiel-Policies je Kältezone (nur Beispiel, Betreiber bestätigt)

> **Keine Rechtsaussage, keine Empfehlung.** Die Werte illustrieren die Mechanik. Der Betreiber
> muss sie mit Produkt, Anlage, Herstellerdaten, HACCP-/Kühlkettenplan und Rechtsabteilung
> abgleichen und freigeben. `product_temperature` misst die Ware, `air_temperature` die Luft.
> Die referenzierten Zonen sind **logische Kühlbereiche** (`kind: cooling_area`, ADR D-08), nicht
> Netzwerksegmente.

### 10.1 Fleisch / Wurst (Kühlraum, Zone `zone-fleisch-01`)

```json
{
  "zone_id": "zone-fleisch-01",
  "metric": "air_temperature",
  "min_c": 0.0,
  "max_c": 4.5,
  "max_rate_c_per_min": 0.5,
  "setpoint_tolerance_c": 1.5
}
```

Sinn: enge Obergrenze, Rate begrenzt plötzliche Erwärmung. Fehlkonfiguration: `min_c` = 2.0 →
Alarm bei jeder Abtauung.

### 10.2 Molkerei (Kühlregal, Zone `zone-molkerei-01`)

```json
{
  "zone_id": "zone-molkerei-01",
  "metric": "air_temperature",
  "min_c": 2.0,
  "max_c": 8.0,
  "max_rate_c_per_min": 0.6,
  "setpoint_tolerance_c": 2.0
}
```

Sinn: größerer Betriebskorridor als Fleisch. Fehlkonfiguration: `max_c` = 8.0 ohne untere Grenze →
Unterkühlung wird nicht erkannt.

### 10.3 Tiefkühl (TK, Zone `zone-tk-01`)

```json
{
  "zone_id": "zone-tk-01",
  "metric": "air_temperature",
  "min_c": -24.0,
  "max_c": -18.0,
  "max_rate_c_per_min": 0.3,
  "setpoint_tolerance_c": 2.0
}
```

Sinn: enge Rate (TK reagiert träge), Grenzen im negativen Bereich. Fehlkonfiguration: `min_c`/`max_c`
vertauscht (positiv) → **Validierungsfehler** bei Update/Reload.

### 10.4 Zonenübergreifend (Beispiel für `absolute_impossible_*`)

```text
"temperature": {
  "limits": [ … Einträge aus 10.1–10.3 … ],
  "absolute_impossible_min_c": -40.0,
  "absolute_impossible_max_c": 40.0
}
```

---

## 11. Änderungs-, Versionierungs- und Audit-Prozess

1. **Antrag:** Änderung fachlich begründen (Produkt, Zone, Anlass, Ticket) → `reason` ist Pflicht.
2. **Vier-Augen-Prinzip (Betreiberprozess):** Anlagenverantwortlicher + Betreiber-IT bestätigen.
   GeDefense erzwingt dies **nicht**; es ist eine Betreiberanweisung.
3. **Änderung anwenden:** Die aktuelle Policy-Datei des `policy.Manager` fachlich anpassen
   (Ablageort gemäß `internal/policy`, i. d. R. im `data_dir`) und anschließend
   `POST /api/v1/policies/reload` (Rolle `admin`) ausführen.
   > **MVP-Grenze (P-1):** `policy.Manager.Update` existiert im Go-API, hat aber **keinen**
   > HTTP-Endpunkt in API v1. Der reguläre Weg im MVP ist Datei + `reload`. Ein UI-Editor für
   > Policy ist nicht Teil von Alpha 0.2.0-alpha.8.
4. **Reload:** `Reload` liest die Datei, validiert (`Policy.Validate`), erzeugt eine neue Version
   (`policy-versions.jsonl`) und einen Audit-Eintrag (`action=policy.reload`, `object_type=policy`).
   Bei Validierungsfehler bleibt die alte Version aktiv.
5. **Verifikation:** `GET /api/v1/policies?site_id=…` → neue `version`, `updated_by`, `reason`,
   `hash`; `GET /api/v1/audit` → Eintrag vorhanden, `chain_ok=true`. Optional `retaild check`.
6. **Dokumentation:** Version, Grund, Freigebende und Datum im Betreiber-Change-Log festhalten.
7. **Kein stilles Ändern:** Temperaturgrenzwerte dürfen nicht unbemerkt oder ohne
   Betreiberfreigabe geändert werden (Baukonzept §6 Schritt 10). Die Audit-Kette macht eine
   Änderung nachvollziehbar, ersetzt aber **keine** Freigabe.

**Rollen:** Policy-Reload erfordert `admin` (`API reference` §8). Keine Rolle darf
Temperaturgrenzwerte „im Alarmfall schnell mal“ ändern, um Alarme zu beenden — das ist ein
dokumentierter Missbrauchspfad (vgl. Threat Model R-06).

---

## 12. Typische Fehlkonfigurationen (Symptom → Ursache → Prüfung)

| Symptom | Wahrscheinliche Ursache | Prüfung |
|---|---|---|
| Keine thermischen Alerts trotz sichtbarer Abweichung | `limits[]` leer / falsche `zone_id` / `valid_from` in der Zukunft | `GET /api/v1/coldchain` → fehlende Grenzwertangaben; Policy prüfen |
| Alarmflut bei Abtau/Türöffnung | `min_c`/`max_c` zu eng, `max_rate_c_per_min` zu klein | Negativfälle im Runbook, Werte gegen Anlagenverhalten prüfen |
| „Eingefrorene“ Temperatur wird als gut angezeigt | `frozen_value_window_s` = 0/zu groß | Datenqualität in `/coldchain` prüfen (`quality`) |
| Massenhaft Unknown-Peer-Alerts beim Start | `baseline_required=true` ohne Lernphase | `learned_baseline_window_s`/`unknown_peer_grace_s` |
| Kein Off-Window-Alert bei Nachtzugriff | `require_window=false` oder Wartungsfenster zu breit (`ends_at`) | `/api/v1/access`, Windows prüfen |
| Spool-Verlust bei WAN-Ausfall | `max_spool_mb` zu klein, `batch_size` falsch | `/health`-Collector/Forwarder-Zustand, Runbook §6 |
| Audit-Kette bricht | manuelle Dateiänderung, Clock-Sprünge, Retention-Lücke | `GET /api/v1/audit` → `chain_ok`, `first_verified_seq`; `retaild check` |
| Policy-Reload abgelehnt | `min_c >= max_c`, negative Fenster, `after_minutes < 0`, leere Rolle | Fehlerantwort `invalid_request`, Log `retaild` |

---

## 13. Konsistenz und offene Punkte

- **Bindend:** Feldnamen/Typen aus `domain.Policy`; Defaults aus `DefaultPolicy`; Validierung aus
  `Policy.Validate`. Abweichungen in Beispielen sind Fehler.
- **Offen P-1:** kein HTTP-Endpunkt für Policy-Update (nur `reload`); Dateiablage/Genaues
  Dateiformat im `data_dir` gemäß `internal/policy` — bei Integration gegen den Code verifizieren.
- **Offen P-2:** kein externer Notifier/Webhook in `config.Config` v1; Eskalationsauslieferung
  ist Betreiberprozess.
- **Offen P-3:** `TemperatureLimit.valid_from` wird von `Policy.Validate` **nicht** geprüft
  (kein Fehler bei unmöglichen/überlappenden Zeiträumen); die Auswertung zukünftiger Gültigkeit
  ist in `detect/rules` zu bestätigen.
- **Offen P-4:** `Policy.SensorPolicy` hat kein Feld „nur kritische Sensoren“; Auswahl erfolgt
  über `Sensor.independent` (siehe `data model`).
- Beispiel-IDs (`zone-fleisch-01`, …) sind **Platzhalter**; gültige IDs gemäß `domain.ids`
  (`[A-Za-z0-9._:-/_]`, max. 96 Bytes).

---

## 14. Werte, `value_scale` und Read-before-Write (Alpha 0.2.0-alpha.8)

### 14.1 Werte-Modell

- `current_value` und `new_value` in WritePlans sind **Anzeigewerte**.
- `value_scale` (Default `1.0`) ist der Faktor zwischen Anzeige- und Rohwert: **Rohwert =
  round(Anzeigewert / value_scale)**. Beispiel: `current_value 4.0` / `new_value 3.5` bei
  `value_scale=0.1` ⇒ Rohwert `40 → 35`.
- Dezimalwerte (mit `.`) **erfordern** `value_scale`; sonst wird der Plan mit `400` abgelehnt.
  `retailgate check` warnt zusätzlich; ohne `value_scale` sind nur ganzzahlige Rohwerte zulässig.
- Der Plan-Hash bindet Ziel, Funktion, Adresse, `current_value`, `new_value` und `value_scale`; eine
  nachträgliche Änderung ist `409 plan_hash_mismatch`.

### 14.2 Read-before-Write und Reihenfolge

- Der Geräte-Reread passiert **unmittelbar vor dem Write** (nicht bei Plan-Erstellung).
- Reihenfolge: **verify → consume/audit → forward**. Erst nach erfolgreicher Verifikation werden
  Session/Token verbraucht und der Audit-Eintrag geschrieben; vorher wird nichts weitergeleitet.
- Fehlerfälle: `current_value_missing` (leer), `current_value_mismatch` (abweichend),
  `current_value_unreadable` (Read-Fehler/Timeout) ⇒ Deny + Audit, Modbus-Exception `0x04`.

### 14.3 Coil-Writes und `read_coils`

- Modbus-Targets konfigurieren optional `read_coils: {"fc":1,"start":0,"count":N}`.
- FC5/FC15-Writes benötigen dieses separate **`read_coils`-Fenster (FC1)** zur Verifikation.
- Fehlt das Fenster, verweigert das Gate den Write; `retailgate check` erzeugt einen
  **fehlschlagenden Check `RBC-<target>`** (Warnungen zusätzlich für Modbus-/HTTP-Allowlists bei
  unvollständiger Verifikation).

### 14.4 TOCTOU-Restrisiko

- Zwischen Reread und Write bleibt ein kurzes Zeitfenster (TOCTOU), in dem sich der Gerätewert
  ändern kann. Das Gate verkleinert es, **schließt es aber nicht vollständig**.
- Gegenmaßnahmen: kurze Freigabe-/Session-Fenster, Geräte-Interlocks und Monitoring/Alarme auf
  unerwartete Wertänderungen. Keine „TOCTOU-frei“-Behauptung.

### 14.5 HTTP-Grenze

- HTTP(S)-Supervisor-Writes haben **keinen generischen Ist-Wert-Recheck**; URL-/Methoden-Allowlist
  und Wertbindung bleiben, `retailgate check` warnt bei fehlender Verifikation.
