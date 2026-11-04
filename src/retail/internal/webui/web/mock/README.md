# Design-QA im Mock-Modus (ohne Backend)

Diese Vorschau rendert **exakt dieselben ES-Module und CSS-Dateien** wie die
produktive Konsole. Ausgetauscht wird ausschließlich die Datenquelle: ein
`fetch`-Interceptor in [`mock-api.js`](mock-api.js) bedient `/api/v1/*` aus den
JSON-Fixtures unter [`fixtures/`](fixtures/). Es gibt keinen Netzaufruf, keinen
Token-Zwang und keinen externen Request.

> **Kennzeichnung:** Die Vorschau zeigt dauerhaft „Design-QA · Mock-Daten — keine
> echte Sicherheitslage" und setzt `data-mock="true"`. Die produktive
> [`index.html`](../index.html) referenziert keine Mock-Datei; es gibt bewusst
> **keinen** `?mock=1`-Schalter im Produktions-Shell, weil ein Fake-Datenpfad in
> einer Sicherheitskonsole irreführend wäre. Der QA-Modus läuft ausschließlich
> unter `/mock/`.

## Starten

```bash
# from the repository root
cd src/retail/internal/webui/web
python3 -m http.server 8123 --bind 127.0.0.1
```

Dann `http://127.0.0.1:8123/mock/` öffnen (oder direkt eine Ansicht):

```text
/mock/?state=normal#/overview
/mock/?state=normal#/site
/mock/?state=normal#/assets
/mock/?state=normal#/coldchain
/mock/?state=normal#/access
/mock/?state=normal#/threat
/mock/?state=normal#/integrity
/mock/?state=normal#/incidents
```

## Query-Parameter

| Parameter | Werte | Wirkung |
|---|---|---|
| `state` | `normal` (Default), `empty`, `error`, `offline`, `partial` | Szenario der Fixture-API |
| `delay` | `0` … `5000` (ms), Default `120` | simulierte Latenz; `delay=2000` zeigt Skeletons |

Beispiele:

- `?state=empty#/assets` — leeres Inventar
- `?state=error#/coldchain` — konkreter 503-Fehlerzustand
- `?state=offline#/overview` — Transportfehler, Offline-Banner
- `?state=partial#/threat` — Teildaten (Verlauf lädt, Alarmdetails fehlen)

Deep-Links funktionieren auch im Mock: `#/assets?asset=asset-verbund-01`,
`#/incidents?id=inc-2026-11-03-01`, `#/threat?alert=alrt-2026-11-03-01`.

## Screenshots (Headless Chrome)

```powershell
chrome --headless=new --disable-gpu --hide-scrollbars `
  --window-size=1440,900 --virtual-time-budget=9000 `
  --screenshot=out.png "http://127.0.0.1:8123/mock/?state=normal#/overview"
```

**Wichtig für Mobile-QA:** Chrome/Windows erzwingt für `--window-size` eine
Mindest-Fensterbreite von ca. 500 CSS-Pixeln. Ein `--window-size=390,844`
liefert deshalb einen **390 px breiten Ausschnitt eines 500-px-Viewports** — der
Eindruck von horizontalem Overflow ist ein Artefakt des Screenshot-Werkzeugs,
kein Layoutfehler. Echte 390-px-Prüfung per DevTools-Protokoll
(`Emulation.setDeviceMetricsOverride`) ergibt:

```text
innerWidth=390  innerHeight=844  scrollWidth=390  (kein horizontaler Overflow)
```

Für QA-Skripte entweder `--window-size=500,844` (Mobile-Breakpoint greift weiter)
oder CDP-Emulation verwenden. Die echte 390-px-Komposition ist zusätzlich in
`var/visual-qa/` dokumentiert.

## Fixtures

`fixtures/` enthält realistische, aber **synthetische** Daten (Filialen, Zonen,
Anlagen, Alarme, Cold-Chain-Serien, Wartungsfenster, Vorfälle, Policy). IDs und
Zeitstempel sind erfunden; Firmware-/Confidence-Werte sind Beispieldaten und
keine Aussage über reale Geräte. `fixtures/empty/` enthält die leeren Varianten.

## Access Gate (0.2)

Die Gate-Ansicht nutzt denselben Mock-Harness. `mock-gate-api.js` bedient
`/api/v1/gate/*` aus `fixtures/gate/*.json`; `?state=empty` verwendet
`fixtures/empty/gate-*.json`.

- **Gate-Views:** `#/gate` (Approval-Inbox), `#/gate?plan=pln-2026-11-04-01`
  (Plan-Detail), `#/gate?tab=sessions`, `#/gate?tab=denies`, `#/gate?tab=status`.
- **Gate-Login ansehen:** `?gateLogin=1#/gate` — der Mock setzt sonst
  automatisch eine Dummy-Gate-Session, damit Screenshots ohne Interaktion
  funktionieren.
- **Dummy-Tokens:** Approval-Antworten liefern `dummy-one-time-token-…`,
  Login `gst_dummy_…`. Diese Werte sind **keine** echten Gate-Tokens und haben
  keine Gültigkeit.
- **Interaktion:** Freigabe-Dialog verlangt einen 6-stelligen MFA-Code (Mock
  akzeptiert z. B. `123456`); ein kritischer Plan benötigt zwei Freigaben, erst
  die zweite zeigt den Einmal-Token-Dialog. Ablehnen verlangt einen Grund;
  Sessions lassen sich mit Bestätigung widerrufen.
- **Fixture-Hinweis:** Pläne/Sessions/Denies sind synthetisch. Es werden keine
  echten Passwörter, TOTP-Seeds oder Session-Tokens verwendet.

## Herstellerkatalog (optional)

`mock-vendor-api.js` bedient `GET /api/v1/vendors`, `/vendors/{family_id}` und
`/regulatory-context` aus `fixtures/vendors.json`, `regulatory-context.json` und
`write-surfaces.json` (Quelle: `data/ot-catalog/`). `?state=empty` oder
`?vendors=disabled` simuliert einen fehlenden/deaktivierten Katalog (`enabled:false`).
Demo-Asset: `#/assets?asset=asset-danfoss-aksm800` öffnet den Inspector mit
Herstellerwissen-Panel.
