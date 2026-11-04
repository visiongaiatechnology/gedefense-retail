# Deployment Guide — GeDefense Retail (Alpha 0.3.0-alpha.2)

**Status:** Installations- und Betriebsvorbereitung für den Pilot · **Stand:** 2026-11-03
**Produkt:** GeDefense Retail 0.1.0 — ColdChain & Store Infrastructure Security (VisionGaiaTechnology)
**Zielgruppe:** Filial-IT / Systemtechnik / Integrator · **Plattform:** Linux (systemd), Go-Binary `retaild`
**Verwandte Dokumente:** `operations-runbook.md`, `retail-policy-reference.md`, `security assumptions`, `pilot-acceptance.md`, `engineering contract`, `API reference`

> **Vor dem Beginn lesen:** GeDefense Retail ist **passiv/read-only**. Es steuert keine Anlage, schreibt
> keine Sollwerte, schaltet nichts ab und isoliert nichts (`safety-boundaries.md`).
> Das Gateway ist **kein Router/NAT** zwischen Netzwerkzonen. Ein Deployment, das diese Annahmen
> verletzt, ist kein gültiger Pilotaufbau (siehe `security assumptions` A-01/A-03).

---

## 1. Komponentenübersicht

| Komponente | Zweck | Ablage (Vorschlag) |
|---|---|---|
| `retaild` | Gateway-Binary (`serve`, `check`, `version`, `gen-token`); optional `retail-sim` für Tests | `/opt/gedefense-retail/retaild` |
| Konfiguration | `retail.json` (ohne Secrets im Klartext-Token) | `/etc/gedefense-retail/retail.json` |
| Daten | EventLog, Alerts, Audit, Policy, Spool | `/var/lib/gedefense-retail/` |
| Logs | strukturiertes `slog` → stdout | journald (`journalctl -u gedefense-retail`) |
| UI/API | HTTP auf `listen` (Default `127.0.0.1:8080`) | Management-Zone |
| systemd-Unit | Dienststart, Hardening, Restart | `/etc/systemd/system/gedefense-retail.service` |

---

## 2. Edge-Gateway-Hardware (Mindestanforderungen)

| Ressource | Minimum | Empfohlen (Pilot) | Begründung |
|---|---|---|---|
| CPU | 2 vCPU x86_64 oder arm64 | 4 vCPU | Parser + Detection + JSONL-I/O; keine GPU |
| RAM | 2 GB | 4–8 GB | In-Memory-Registry, Samples-Ringpuffer, Event-Window |
| Disk | 32 GB SSD | 128 GB SSD, eigenes Volume für `data_dir` | Events × `event_days`, Spool, Audit; Disk-Full-Schutz |
| Netzwerk | 3 Schnittstellen (siehe §4) | 3 × 1 GbE, getrennt | Management / OT-Monitoring(TAP/Feed) / optional Zentrale |
| Uhrzeit | NTP-fähig, dauerhaft | NTP + RTC | Clock-Skew-Erkennung (R-10) |
| Strom | USV empfohlen | USV + sauberes Shutdown | Dateisystem-/Spool-Integrität |
| Aufstellung | abgeschlossen, zugriffsbeschränkt | Serverschrank/abgeschlossenes Gehäuse | Physischer Zugriff = Restrisiko (R-05) |

**Nicht erforderlich:** GPU, Container-Runtime, Cloud, DB-Server. **Nicht zulässig:** Gateway als
Router/Bridge zwischen Zonen, frei erreichbarer Internet-Listener, Arbeitsplatz-PC mit Fremddiensten.
**Dimensionierung `data_dir`:** Events ∝ Aufkommen × `retention.event_days`, begrenzt durch
`retention.max_event_mb`/`max_spool_mb`; bei unbekanntem Aufkommen mit Simulator messen, ≥ 30 % Reserve.

---

## 3. Betriebssystem-Härtung

**Grundlage:** aktuelle Linux-LTS-Distribution mit systemd, dedizierter Host (keine Fremddienste).
Keine CGO-Abhängigkeit → statisches Binary, keine Runtime-Pakete nötig.

### 3.1 Systembenutzer und Verzeichnisse

```bash
# dedizierter Systembenutzer ohne Login-Shell
sudo useradd --system --no-create-home --shell /usr/sbin/nologin gedefense

sudo install -d -o gedefense -g gedefense -m 0700 /opt/gedefense-retail
sudo install -d -o gedefense -g gedefense -m 0700 /etc/gedefense-retail
sudo install -d -o gedefense -g gedefense -m 0700 /var/lib/gedefense-retail
```

| Pfad | Rechte | Owner | Inhalt |
|---|---|---|---|
| `/opt/gedefense-retail/` | `0700` | `gedefense` | Binaries |
| `/etc/gedefense-retail/` | `0700` | `gedefense` | `retail.json` (Datei `0600`) |
| `/var/lib/gedefense-retail/` | `0700` | `gedefense` | Datenverzeichnis (`data_dir`) |
| alle Datendateien | `0600` | `gedefense` | EventLog/Alerts/Audit/Policy/Spool |

**Regel aus dem Engineering Contract (§5.2):** Dateien `0600`, Verzeichnisse `0700`, symlink-sicher.
Der Dienst läuft **ausschließlich** als `gedefense`, nie als `root`.

### 3.2 Härtungscheckliste

- [ ] Nur notwendige Pakete; **kein** Compiler, keine Desktop-Umgebung, kein Webserver.
- [ ] SSH nur aus der Management-Zone, Key-only, `PermitRootLogin no`, `PasswordAuthentication no`.
- [ ] Host-Firewall default-deny (§4); `net.ipv4.ip_forward = 0` (**kein Routing**).
- [ ] NTP aktiv (`timedatectl`, `chronyc tracking`); Speicherung ist UTC, Zeitzone nur Anzeige.
- [ ] OS-Sicherheitsupdates nach Betreiberprozess; `data_dir` auf eigenem Volume (`df -h`, Warnung 80 %).
- [ ] journald-Limits (`SystemMaxUse`); optional LUKS für `data_dir`; physischer Zugriff beschränkt.
- [ ] Kein `docker`/`podman`, keine zusätzlichen Netzwerkdienste auf dem Host.

---

## 4. Netzwerkzonen und Ports

### 4.1 Zonen (Modell aus `domain.ZoneKind`)

| `site.zones[].kind` | Bedeutung | Gateway-Rolle |
|---|---|---|
| `ot_process` | PLCs, Kälteregler, Anlagensteuerung | **nur beobachten**, kein Poll ohne Freigabe |
| `ot_monitoring` | TAP/SPAN-Eingänge, passive Sensorik | **bevorzugte** Einbindung |
| `retail_it` | Kassen, Office, Warenwirtschaft | kein Transit, keine Beobachtung ohne Freigabe |
| `management` | Gateway, Admin-Zugänge, Update-Verteilung | Host/API/UI stehen hier |
| `external_maintenance` | Dienstleister-/Fernwartungszugänge | nur Metadaten + Wartungsfenster |
| `cooling_area` | **logischer** Kühlbereich (Regal/Kühlraum/Display) — keine Netzgrenze | Ziel für produkt-/bereichsspezifische Policy-Limits |
| `unknown` | nicht zugeordnet | ehrlich als unbekannt führen |

### 4.2 Verbindungsmatrix

| Richtung | Von | Nach | Port/Protokoll | Zweck | Pflicht |
|---|---|---|---|---|---|
| **inbound** | Admin-Workstation (Mgmt-Zone) | Gateway `listen` | TCP 8080 (konfigurierbar) | UI/API, nur Management | ja (kann auf Loopback bleiben) |
| **inbound** | Feed-Relay | `modbus` tap | TCP `listen` (**Pflicht**), z. B. `127.0.0.1:15020` | passiver MBAP-Stream | optional |
| **inbound** | Feed-Relay | `bacnet` | UDP `listen` (**Pflicht**), z. B. `127.0.0.1:47808` | passiver BACnet/IP-Decoder (kein Outbound) | optional |
| **inbound** | Feed-Relay | `httpui` | TCP `listen` (**Pflicht**) + `device_ip`/`device_port` | HTTP-/TLS-Metadaten + SNI (keine Requests) | optional |
| **inbound** | Feed-Relay | generisch | TCP/UDP, **vom Betreiber definiert** | weitere passive Feeds | optional |
| **outbound** | Gateway | Modbus-Ziel | TCP **502** | read-only Poll (FC3/FC4) | nur mit Freigabe |
| **outbound** | Gateway | MQTT-Broker | TCP **1883** | Subscribe (read-only) | nur mit Freigabe |
| **outbound** | Gateway | SNMP-Ziel | UDP **161** | GET (v1/v2c, read-only) | nur mit Freigabe |
| **outbound** | Gateway | zentrale Konsole | TCP **443** | mTLS, outbound-only, Store-and-forward | optional (nicht MVP) |
| **outbound** | Gateway | NTP | UDP 123 | Zeit | ja |

**Nicht vorgesehen:** eingehende Verbindungen aus OT/Internet, Port-Forwarding auf das Gateway,
BACnet-Who-Is/WriteProperty, Modbus-Write, SNMP-SET, MQTT-Publish, aktives Scannen,
HTTP-Requests des `httpui`-Adapters (rein passiv, keine Entschlüsselung).

> **Feed-Architektur (MVP):** Die passiven Adapter **lauschen nur** (kein Dial); `listen` ist bei
> ihnen **Pflicht**. Ein vom Betreiber betriebener Feed-Relay/SPAN-Shim verbindet sich auf den
> konfigurierten `listen`-Port und liefert die Kopie des TAP-/SPAN-Verkehrs; alternativ liest der
> `pcap`-Adapter Dateien. Bei Loopback-Adresse (üblich) muss der Relay **auf demselben Host** laufen;
> für einen externen Relay `listen` an eine Adresse der Management-/Monitoring-Zone binden und per
> Firewall auf den Relay-Host begrenzen. **Live-Capture (AF_PACKET) ist nicht Teil des MVP**
> (offen D-2); Feed-Ports sind frei konfigurierbar und keine Produktkonstante.

### 4.3 Host-Firewall (Beispiel, an Betreiberplan anpassen)

```bash
sudo nft add table inet gdretail
sudo nft add chain inet gdretail input '{ type filter hook input priority 0; policy drop; }'
sudo nft add rule inet gdretail input iif lo accept
sudo nft add rule inet gdretail input ct state established,related accept
sudo nft add rule inet gdretail input tcp dport 8080 ip saddr <mgmt-netz> accept
# outbound: 502/1883/161/443 nur zu den freigegebenen OT-/Zentral-Zielen; ip_forward=0, FORWARD DROP
```

**Regel:** Das Gateway darf **keinen** Verkehr zwischen Zonen weiterleiten. `ip_forward=0` und
`FORWARD DROP` sind Teil der Abnahme (A-01).

---

## 5. Installation

### 5.1 Binary

```bash
# geprüftes Release-Artefakt (SHA-256) auf den Host bringen, dann:
sudo install -o gedefense -g gedefense -m 0700 retaild /opt/gedefense-retail/retaild
/opt/gedefense-retail/retaild version
```

`version` muss Produkt, Version, Commit und Build-Datum zeigen (`version.Product`, `version.Version`,
`version.Commit`, `version.BuildDate`; per `-ldflags -X` gesetzt). Stimmt die Version nicht mit dem
freigegebenen Artefakt überein: **nicht** installieren.

### 5.2 systemd-Unit

```ini
# /etc/systemd/system/gedefense-retail.service
[Unit]
Description=GeDefense Retail Edge Gateway (read-only OT monitoring)
After=network-online.target time-sync.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=gedefense
Group=gedefense
WorkingDirectory=/opt/gedefense-retail
ExecStart=/opt/gedefense-retail/retaild serve --config /etc/gedefense-retail/retail.json
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
UMask=0077
LimitNOFILE=65536

# Hardening
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
ReadWritePaths=/var/lib/gedefense-retail

[Install]
WantedBy=multi-user.target
```

> `ReadWritePaths` muss exakt das `data_dir` enthalten (bei abweichendem `data_dir` anpassen).
> `ProtectSystem=strict` macht `/etc`/`/opt` read-only — Konfigurationsänderungen daher als
> `gedefense` oder per `sudo install` vornehmen, nicht aus dem laufenden Prozess.
> Im Repo liegt zusätzlich `config/gedefense-retail.service` als Referenz. Sie nutzt `--config`
> und den Pfad `/opt/gedefense-retail/bin/retaild`; Pfad- und Verzeichniskonventionen vor dem
> Einsatz an §5.1/§3.1 anpassen.

### 5.3 Erstkonfiguration: `retail.json` ohne Secrets

```json
{
  "listen": "127.0.0.1:8080",
  "data_dir": "/var/lib/gedefense-retail",
  "log_level": "info",
  "site": {
    "site_id": "filiale-001",
    "name": "Markt Nord",
    "status": "unknown",
    "zones": [
      { "zone_id": "zone-ot-proc-01", "site_id": "filiale-001", "name": "Kälteanlagen",
        "kind": "ot_process", "purpose": "Verbund-/Kühlstellenregler", "critical": true },
      { "zone_id": "zone-ot-mon-01", "site_id": "filiale-001", "name": "OT Monitoring",
        "kind": "ot_monitoring", "purpose": "TAP/SPAN-Feed", "critical": true },
      { "zone_id": "zone-kuehl-01", "site_id": "filiale-001", "name": "Kühlraum links",
        "kind": "cooling_area", "purpose": "Fleisch 0…4 °C – Policy-Limits", "critical": true }
    ]
  },
  "users": [
    { "user_id": "admin-01", "name": "Administrator", "role": "admin",
      "token_sha256": "<64-hex-sha256-des-tokens>" },
    { "user_id": "technik-01", "name": "Store-IT", "role": "operator",
      "token_sha256": "<64-hex>" }
  ],
  "collectors": [
    { "adapter_id": "modbus.pool1", "enabled": true, "zone_id": "zone-ot-proc-01",
      "options": { "mode": "poll",
                   "target": "<regler-ip>:502", "unit": "1",
                   "interval": "30s", "timeout": "2s",
                   "registers": "3:100:sensor-air-01:air_temperature:celsius:0.1" } }
  ],
  "central": {
    "url": "https://<zentrale-host>:443", "timeout_s": 10, "batch_size": 100, "spool_max_mb": 512,
    "client_cert_file": "/etc/gedefense-retail/client.crt",
    "client_key_file": "/etc/gedefense-retail/client.key",
    "ca_file": "/etc/gedefense-retail/ca.crt"
  }
}
```

| Feld | Pflicht | Default | Bedeutung / Regel |
|---|---|---|---|
| `listen` | nein | `127.0.0.1:8080` | Host:Port; Host **muss** explizit sein; nur Management-Zone |
| `data_dir` | nein | `./var/lib/gedefense-retail` | dediziertes Verzeichnis, nicht `.` oder `/` |
| `log_level` | nein | `info` | `debug`/`info`/`warn`/`error` |
| `site.site_id`, `site.name`, `site.status`, `site.zones[]` | ja | `status` → `unknown` | Zonen mit gültigem `kind`; keine doppelten `zone_id` |
| `users[]` | ja (≥1) | – | `user_id`, `role` (`viewer`/`operator`/`admin`), `token_sha256`; **≥1 admin**; keine doppelten IDs/Hashes; Platzhalter-Hashes werden abgelehnt |
| `collectors[]` | nein | leer | `adapter_id` eindeutig ≤96 Zeichen; `zone_id` muss in `site.zones` deklariert sein; `options` max. 64 Einträge |
| `central` | nein | – | `url` Pflicht (https; http nur Loopback), Zertifikat+Key nur gemeinsam, `timeout_s` 1–300, `batch_size` 1–1000, `spool_max_mb` ≥1 |
| `simulation` | nein | aus | **nur** mit Loopback-`listen`; nie im Produktivbetrieb |
| `policy` | nein | `DefaultPolicy` | siehe `retail-policy-reference.md` |
| `web_dir` | nein | embedded | nur Entwicklungs-Override, kein Pfad `.` |

> Die Platzhalter `<64-hex-sha256-des-tokens>` und `<64-hex>` sind **keine gültigen Hashes**; der
> Validator lehnt sie ab. Zuerst `gen-token` ausführen (§5.4) und den echten Hash eintragen.
> Ein Dev-Build meldet `0.1.0-dev`/`dev`; ein freigegebenes Release-Build `0.1.0` + Commit/Datum
> (per `-ldflags -X` gesetzt) — Abweichung = falsches Artefakt.
>
> **Referenzdatei im Repo:** `config/retail.example.json` ist eine **Demo-/E2E-Vorlage** (vom
> E2E-Harness verwendet): `simulation.enabled=true` und Platzhalter-Hashes (`000…`). Für Produktion
> Werte ersetzen; die Adapter-Options-Keys entsprechen dem FINAL-Stand (§6).

Konfiguration laden/validieren (strikt, unbekannte Felder = Fehler):

```bash
sudo -u gedefense /opt/gedefense-retail/retaild check --config /etc/gedefense-retail/retail.json
```

### 5.4 Token-Erzeugung (`gen-token`-Flow)

```bash
# 1) Token + Hash erzeugen (Ausgabe: Token EINMALIG anzeigen)
sudo -u gedefense /opt/gedefense-retail/retaild gen-token --user admin-01 --role admin

# 2) Nur den SHA-256-Hash in retail.json users[].token_sha256 eintragen
# 3) Klartext-Token sicher an die Person übergeben (Passwortmanager), NIE in Dateien/Tickets
```

**Regeln:** Kein Klartext-Token in `retail.json`, Logs, Tickets oder Skripten. `token_sha256` ist
64 Zeichen Hex (lowercase). Der Config-Validator lehnt Platzhalter-Hashes (z. B. Hash von "admin",
"changeme", "test") ab. Rotation: neuen Hash eintragen → Dienst neu starten → altes Token ungültig.

### 5.5 Dienst starten und verifizieren

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now gedefense-retail
sudo systemctl status gedefense-retail --no-pager
journalctl -u gedefense-retail -n 50 --no-pager

curl -s http://127.0.0.1:8080/api/v1/health | jq '{status,version,read_only,storage}'
```

| Prüfung | Soll |
|---|---|
| Dienststatus | `active (running)`, kein Restart-Loop |
| `health.status` | `ok`, `health.read_only=true` |
| `health.storage.audit_chain_ok` | `true` |
| `health.collectors[]` | konfigurierte Adapter sichtbar, `state=running`/`degraded` |
| Log | keine Fehler/`panic`, keine Secrets |

**Betriebswarnung:** `read_only=false` oder ein Adapter mit Schreibpfad ist eine **Safety-Verletzung**
→ Dienst stoppen, Lead/Security informieren.

---

## 6. Collector-Konfiguration (read-only)

Gemeinsames Schema: `collectors[]` mit `adapter_id`, `enabled`, `zone_id` (muss in `site.zones`
deklariert sein), `options` (**alle Werte sind Strings**, `map[string]string`). Adapter laufen
isoliert; ein Parserfehler beendet weder den Prozess noch andere Adapter (`collect.Registry`,
Fehlerzähler in `health`). Fehlende/ungültige Pflicht-Optionen und ein Schreib-Function-Code führen
zum **Startfehler** des Adapters — nie zu stillem Default.

**Gemeinsame Options (alle Adapter):** `site_id` wird **von `app.Run` injiziert**
(`collect.AdapterConfig.SiteID = cfg.Site.SiteID`) — **nicht** in `options` setzen. Optional
`interval` (z. B. `"5s"`), `timeout` (z. B. `"2s"`), `flow_interval` (z. B. `"60s"`). Dauerwerte
sind Go-Dauerstrings und brauchen **immer eine Einheit** (`30` ist ungültig ⇒ Startfehler). Bei den
passiven Adaptern (`modbus` tap, `bacnet`, `httpui`) ist **`listen` Pflicht**.

### 6.1 Modbus TCP (`modbus`) — Port 502

| Option | Werte | Default | Bedeutung |
|---|---|---|---|
| `mode` | `tap` \| `poll` | `tap` | `tap` = passiver MBAP-Parser (empfohlen); `poll` = read-only FC3/FC4 |
| `listen` (tap) | `host:port` | **Pflicht** | Adapter **lauscht nur** (TCP-Feed/SPAN-Shim), kein Dial; z. B. `127.0.0.1:15020` |
| `device_ip`, `max_connections` (tap) | IP / Int | – | optionale `asset_seen`-Zuordnung / Verbindungslimit |
| `registers` | Semikolon-Liste | tap: optional · poll: **Pflicht** | `fc:addr:sensor_id:metric:unit[:scale[:offset]]`; **fc nur 3/4**; 5/6/15/16/… ⇒ Startfehler `guard.ErrWriteDenied` |
| `target` (poll) | `host:502` | **Pflicht** | Ziel; nur mit Betreiberfreigabe |
| `unit` (poll) | 0–255 | – | Modbus-Unit-ID (typ. 1) |
| `interval` (poll) | Dauer | `5s` | Mindestfloor 1 s (Loopback 50 ms nur für Tests) |
| `timeout` (poll) | Dauer | `2s` | Lese-/Verbindungs-Timeout |
| `flow_interval` | Dauer | – | Aggregationsfenster für Flow-Events |

Negative Temperaturen werden als int16 interpretiert; typische Skalierung `0.1` (`scale`). Beispiel:

```json
{ "adapter_id": "modbus.pool1", "enabled": true, "zone_id": "zone-ot-proc-01",
  "options": { "mode": "tap", "listen": "127.0.0.1:15020",
               "device_ip": "<regler-ip>",
               "registers": "3:100:sensor-air-01:air_temperature:celsius:0.1;3:102:sensor-air-02:air_temperature:celsius:0.1" } }
```

Schreibversuche werden **nur beobachtet** (`EventWriteAttempt`, `retail.write-attempt`) — nie beantwortet.
Bei `mode=poll` entsteht Anlagenverkehr: nur mit dokumentierter Freigabe und konservativem Intervall.

### 6.2 MQTT (`mqtt`) — Port 1883

| Option | Werte | Default | Bedeutung |
|---|---|---|---|
| `broker` | `host:1883` | **Pflicht** | Broker; TLS-Client ist **nicht** im MVP |
| `topics` | kommagetrennt | – | Topic-Filter (QoS0); leer ⇒ aus `sensors` abgeleitet; `+`/`#` nur mit `allow_wildcard=1` |
| `sensors` | Semikolon-Liste | **Pflicht, wenn `topics` leer** | `topic\|sensor_id\|metric\|unit` (Topic darf auf `#`/`+` enden) |
| `client_id` | String | `gedefense-retail` | eindeutige Client-ID |
| `username`, `password` | String | – | optional, nur falls Broker Auth verlangt; **Klartext in `retail.json`** (§6.7) |
| `keepalive` | Dauer | `30s` | MQTT-Keepalive; Reconnect mit Backoff+Jitter intern |
| `timeout` | Dauer | `5s` | CONNECT-/SUBSCRIBE-Timeout |

Nur CONNECT/SUBSCRIBE/PINGREQ; **kein** PUBLISH an Geräte, keine Steuer-Topics.

### 6.3 BACnet/IP (`bacnet`) — Port 47808 (nur passiv)

| Option | Werte | Default | Bedeutung |
|---|---|---|---|
| `listen` | `host:port` (UDP) | **Pflicht** | Adapter lauscht auf passivem UDP-Feed (z. B. `127.0.0.1:47808`) |
| `objects` | Semikolon-Liste | – | `objecttype:instance\|sensor_id\|metric\|unit` (AI/AV/BI/BV) |
| `flow_interval` | Dauer | – | Aggregationsfenster für Flow-Events |

**Ausschließlich passiv:** kein Poll, kein Who-Is, keine ReadProperty-Anfrage, keine WriteProperty.
PCAP-Analyse erfolgt über den `pcap`-Adapter (kein zweiter Optionsweg).

### 6.4 SNMP (`snmp`) — Port 161

| Option | Werte | Default | Bedeutung |
|---|---|---|---|
| `targets` | kommagetrennt `ip[:161]` | **Pflicht** | Ziele (Port default 161); nur GET |
| `community` | String | **Pflicht** | read-only-Community; wird **nie** geloggt/ausgegeben |
| `version` | `2c` \| `1` | `2c` | **`3`/`v3` ⇒ Startfehler** („SNMPv3 is not implemented in the MVP“) |
| `oids` | Semikolon-Liste | **Pflicht** | `oid\|sensor_id\|metric\|unit` (nur numerische OIDs) |
| `interval` | Dauer | `30s` | Poll-Intervall (Loopback 50 ms nur für Tests) |
| `timeout` | Dauer | `3s` | GET-Timeout |

Nur GET; **kein** GETBULK/Walk, **kein** SET. Health zeigt `state=degraded` mit Warnung, dass
v1/v2c die Community im Klartext überträgt und SNMPv3 nicht implementiert ist (Restrisiko RR-09).

### 6.5 PCAP (`pcap`) — offline

| Option | Werte | Default | Bedeutung |
|---|---|---|---|
| `files` **oder** `dir` | kommagetrennte Pfade / Verzeichnis | **Pflicht (eines von beiden)** | PCAP-Dateien (LE/BE, Ethernet/IPv4/TCP+UDP) bzw. alle `*.pcap` sortiert |
| `registers`/`sensors`/`objects` | Semikolon-Liste | – | optionale Decoder-Mappings wie bei den Live-Adaptern |
| `http_ports` | kommagetrennt | `80,8000,8080,443,8443` | als Management-UI gewertete Ports (HTTP-Metadaten) |

`collection_method = operator_export`: Datei-Import, danach Idle bis Shutdown — **kein** Replay/Nachsendeverhalten.

### 6.6 HTTP-Management-UI (`httpui`) — passiv, Nachtrag 2026-11-03

| Option | Werte | Default | Bedeutung |
|---|---|---|---|
| `listen` | `host:port` (TCP) | **Pflicht** | Adapter **lauscht nur** auf lokalem Feed |
| `device_ip` | IP | **Pflicht** | Zuordnung zu beobachtetem Management-UI-Gerät (`asset_seen`) |
| `device_port` | 1–65535 | `443` | Port der beobachteten Management-UI |
| `max_header_bytes`, `max_connections` | Int | – | Parser-/Verbindungslimits |

Rein passiv: Plaintext-HTTP-Metadaten (Methode/Pfad **ohne Query**/Host/User-Agent/Server/Status) und
TLS-ClientHello-**SNI** (keine Entschlüsselung). Emittiert `flow` + `asset_seen`
(Protocol `http`/`https`, Host-/Server-Hinweis) und `access_session` (Methode `web_ui`).
**POST/PUT/PATCH/DELETE werden als `write_attempt` beobachtet** — nur Beobachtung, keine Antwort.
**Niemals** Payloads, Cookies oder `Authorization`. **Keine** aktiven Requests. SNI ist nur Metadatum,
keine Allowlist (kein aktives Blocken).

### 6.7 Secrets in `options` — MVP-Grenze

MQTT-Passwort und SNMP-Community werden **direkt** aus `options` gelesen — **keine** env-/Datei-
Indirektion, kein Secret-Store, keine Rotation im MVP (Rotation = Werte ändern + Neustart).
Verbindlich: `retail.json` `0600`, Verzeichnis `0700`, nie ins Repo/Backup ohne Schutz, dediziertes
read-only-Konto; Health/Logs/Fehler geben die Werte **nie** aus (Redaction-Test).

---

## 7. Updates und Rollback

**MVP-Realität:** Es gibt **keinen** automatischen Updater und **keine** signierte Selbst-Update-Funktion
in `retaild`; ein allgemeiner Update-/Recovery-Mechanismus ist **nicht** Teil dieser Alpha; das 0.3-Recovery betrifft ausschließlich konfigurierte Setpoint-Referenzen.
Update = kontrollierter Betreiberprozess mit geprüftem Artefakt.

### 7.1 Update (in freigegebenem Wartungsfenster)

1. Artefakt beziehen; **SHA-256 (und Signatur, falls Betreiberprozess) gegen freigegebene
   Release-Referenz prüfen** — Abweichung ⇒ **abbrechen**.
2. Backup: `retail.json` + Snapshot des `data_dir` (Dienst gestoppt oder Dateisystem-Snapshot).
3. Dienst stoppen: `sudo systemctl stop gedefense-retail`.
4. Binary ersetzen (Rechte `0700`, Owner `gedefense`), `retaild version` prüfen,
   `retaild check --config …` → Exitcode **0** erforderlich.
5. Starten, Runbook §6.2 prüfen (Health, Audit, Collectors, Alerts), Ergebnis + Version/Commit
   im Betreiber-Change-Log festhalten.

### 7.2 Rollback

1. Dienst stoppen, vorheriges Binary zurückkopieren (`retaild version` prüfen).
2. Daten: **nicht** blind ein älteres `data_dir` über neuere Daten legen (Formatänderungen können
   Audit-/Event-Daten beschädigen). Im Zweifel aktuelles `data_dir` beiseitelegen, Snapshot vom
   Update-Zeitpunkt einspielen, Verlustzeitraum dokumentieren.
3. `retaild check` → 0, starten, Runbook §6.2; Abweichung im Change-Log dokumentieren.

> **Grenze:** Recovery betrifft **nur** GeDefense-Artefakte. PLC-/Regler-Konfiguration wird **nie**
> durch GeDefense gesichert oder zurückgeschrieben (S-12).

---

## 8. Troubleshooting

| Symptom | Ursache (typisch) | Maßnahme |
|---|---|---|
| Start scheitert, `invalid configuration` | unbekanntes Feld, fehlender Admin, ungültige Rolle/Zone, Platzhalter-Hash | `retaild check`-Meldung lesen; Config gegen §5.3 |
| `token_sha256 is a well-known placeholder` | Demo-/Standard-Hash eingetragen | `gen-token` verwenden |
| `listen must name an explicit host` | `":8080"` oder leerer Host | `127.0.0.1:8080` oder Management-IP |
| `simulation is only allowed with a loopback listen address` | `simulation.enabled` mit Nicht-Loopback | Simulation aus; nie im Produktivbetrieb |
| `central.url must use https` | http zu Nicht-Loopback | mTLS/https konfigurieren |
| Dienst startet, sofort Restart | Rechte auf `data_dir`, Port belegt, fehlende Schreibrechte | `journalctl`, `ss -ltnp`, `ls -ld data_dir` |
| UI/API nicht erreichbar / `401`/`403` | `listen` nur Loopback; Token fehlt/falsch, Rolle zu schwach | lokal testen oder Management-Bind + Firewall; Token/`role` prüfen |
| Collector `failed` | Ziel/Port/Options falsch, Feed fehlt, Startfehler Register-Spec | `last_error`, Startlog; §6 |
| Keine Events, Collector läuft | falsches Ziel/Topic/OID, kein TAP-Feed | Feed/TAP prüfen; Simulator-Test |
| Audit `chain_ok=false` | Manipulation, Retention-Lücke, Clock-/Dateifehler | Runbook §7; nicht löschen |
| Disk voll / hohe CPU | Retention/`max_event_mb`/journald; zu kurzes Poll-Intervall | Runbook §10; Intervalle ≥ 5 s; Health/Log |

---

## 9. Offene Punkte (Stand vor Integration)

| ID | Offener Punkt | Auswirkung |
|---|---|---|
| D-1 | Options-Keys **FINAL** mit engineer-collectors abgestimmt (2026-11-03); `SiteID` wird von `app.Run` injiziert (nicht in `options`); Contract §5.8 enthält `httpui` als Nachtrag | Bei Code-Abweichung Doc angleichen (Lead/Collectors) |
| D-2 | Live-Capture nicht im Produkt: Adapter **lauschen** auf Feed-Ports; Feed-Relay/SPAN-Shim ist Betreiber-/Integratorleistung | Ohne Feed nur `poll`, `pcap` und Testdaten nutzbar |
| D-3 | Signaturprüfung von Update-Artefakten ist Betreiberprozess, kein Produktfeature; Update-/Rollback-Pfad beschrieben, aber nicht automatisiert | Update-Schritt 1 organisatorisch erzwingen; AC-O-03 nur als Prozessnachweis |
| D-4 | Spool-Füllstand nicht über API exponiert | Monitoring über Log/Dateisystem (Runbook §5) |
| D-5 | Secrets (MQTT-Passwort, SNMP-Community) als Klartext in `retail.json`, keine Rotation im MVP; keine MFA | Datei `0600`, Verzeichnis `0700`, kein Repo/Backup ohne Schutz; API nur Management-Netz |


---

## 12. Vendor-Katalog im Paket (Alpha 0.3.0-alpha.2)

- Das Release-Bundle enthält `data/ot-catalog/` (`vendors.json`, `write-surface.json`,
  `regulatory-context.json`).
- Pfad nach Installation: `/opt/gedefense-retail/data/ot-catalog` bzw.
  `C:\Program Files\GeDefense\Retail\data\ot-catalog` (Installer prüfen).
- Der Katalog ist Laufzeitwissen (Discovery/API/UI/Gate-Advisory) und **kein Auto-Allow**; unbekannte
  Geräte bleiben unbekannt.
- Neue API-Endpunkte: `/api/v1/vendors*`, `/api/v1/regulatory-context` (siehe `../API.md`).
- Keine Secrets im Katalog; regulatorischer Kontext ist ein Hinweis, keine Compliance-Aussage.

---

## 13. Netzwerk-Enforcement, Setpoint-Integrität und Bypass (Alpha 0.3.0-alpha.2)

### 13.1 `retailgate netpolicy`

`retailgate netpolicy --config gate.json --format nftables|iptables --gate-source <CIDR>
[--out FILE] [--check] [--apply] [--rollback]`

- Akzeptiert neue Verbindungen zu Reglern nur von den `--gate-source`-CIDR(s); andere neue
  Verbindungen werden verworfen und geloggt. Eigene Table/Chain; `--check` prüft ohne Apply,
  `--out` schreibt das Regelset, `--apply`/`--rollback` verwalten es.
- **Voraussetzung:** Routing/NAT/Bridge und Segmentierung müssen am Gate-Host bereits funktionieren;
  das Tool ist **kein Router** und wirkt nur auf dem Gate-Host. Bypass-Pfade außerhalb bleiben
  Betreiberaufgabe. Regeln vor `--apply` prüfen und einen Out-of-band-Rollback vorhalten.

### 13.2 Setpoint-Integrität + Automatic Recovery

```json
"integrity": {
  "enabled": true, "poll_interval_s": 60, "confirm_reads": 3, "stale_after_s": 180,
  "references": [{"target_id":"aksm-1","fc":3,"register":40002,"unit_id":1,
                  "value":"4.0","scale":0.1,"unit":"celsius",
                  "note":"Sollwert Fleischraum","recovery":true}],
  "recovery": {"enabled": false, "max_actions_per_hour": 3, "max_actions_per_day": 10,
               "cooldown_s": 300, "require_no_active_window": true}
}
```

- Worker pollt Referenzen zyklisch per FC3, bestätigt Abweichungen (`confirm_reads`) und meldet
  `gate.integrity.mismatch`; `stale_after` markiert fehlende/veraltete Werte.
- **Recovery ist opt-in, Default aus.** Nur Referenzen mit `"recovery": true` werden per FC6
  geschrieben (ohne Plan/Session), begrenzt durch Stunden-/Tageslimit, Cooldown und
  `require_no_active_window`; Read-back prüft das Ergebnis, Audit `gate.recovery.applied|failed|unknown`.
- API `GET /api/v1/gate/integrity`, SSE `gate_integrity`.
- **Grenzen:** Recovery beweist nicht, wer außerhalb des Gates geschrieben hat, und beseitigt das
  Read→Write-TOCTOU-Fenster nicht; HTTP-Writes haben keinen generischen Ist-Wert-Recheck.

### 13.3 Bypass-Erkennung in `retaild`

```json
"bypass": {"enabled": true, "gate_source_cidrs": ["10.10.40.0/24", "10.10.50.10/32"]}
```

- `bypass.gate_source_cidrs`: CIDR/Einzel-IP (nur IPv4/IPv6, max. 64, keine normalisierten Duplikate,
  keine IPv6-Zonen); Validierung auch bei `enabled=false`, unbekannte Felder ⇒ Konfigurationsfehler.
  `enabled=true` ohne gültige Liste ⇒ Start verweigert (`retaild check` Exit ≠ 0), kein stilles
  Abschalten.
- Passive Schreibversuche (`write_attempt`) von Quellen außerhalb `gate_source_cidrs` erzeugen
  `retail.bypass-suspected` (critical, Kategorie `access`, Rule-Version 1); Gate-Quellen/Reads nicht.
  Alert mit Evidence/Fakten/Hypothese/Prüfempfehlungen, Dedup
  `retail.bypass-suspected|<site>|<source>|<target>|<register>`, normale Alert-Engine/Incident-Kette.
- **Grenze:** belegt sind nur Schreibversuch und Quelle außerhalb der Gate-CIDRs — nicht Urheber,
  Freigabe oder bewiesene Segmentierungslücke; mit Geräte-Logs/Betreiber-Evidenz verifizieren. Die
  Regel ist eine Adapter-/Gate-Signal-Regel, nicht Teil des passiven Rule-Packs (15 Regeln).

### 13.4 Betreiber-Checkliste Setpoint-Integrität & Automatic Recovery

- **Config-Felder:** `integrity.enabled`, `poll_interval_s` (10–86400), `confirm_reads` (1–5),
  `stale_after_s` (> poll_interval_s), `references[]` (`target_id`, `fc=3`, `register` im
  Read-Window `40001…465536`, `value`, `scale`, `unit`, `note`, `recovery`),
  `recovery.enabled` (Default **false**), `max_actions_per_hour/day`, `cooldown_s` (≥60),
  `require_no_active_window` (bei Recovery **true verpflichtend**).
- **Validierung:** Referenz-Target muss `modbus_tcp` sein, `fc=3`, Register im
  `read_registers`-Fenster, `value` numerisch und über `scale` in uint16 passend, keine doppelten
  `(target_id, unit_id, register)`; `enabled=true` braucht mindestens eine Referenz.
- **Fail-safe:** bei `AllowWrite=false` keine Integrity-Reads/Recovery.
- **Audit-fail-closed:** ohne Audit-Intent kein Recovery-Write; Audit-Fehler nach dem Write ⇒
  `gate.recovery.unknown`, **kein Retry**.
- **Ein Versuch pro bestätigtem Mismatch**, keine Flapping-Schleife; FC3-Re-Read kurz vor FC6, aber
  **nicht atomar** (TOCTOU-Restfenster).
- **Kill-Switch:** `integrity.recovery.enabled=false` + Reload/Restart; Rate-Limit/Cooldown und
  `require_no_active_window` nicht umgehen; `gate.recovery.failed|unknown` eskalieren.
- **Grenze:** Referenzwerte sind Betreiber-Freigabe, kein HACCP-/Compliance-Beweis; nur Modbus
  FC3/FC6, HTTP ohne Integrity/Recovery.
