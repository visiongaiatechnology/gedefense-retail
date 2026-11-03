<p align="center">
  <a href="docs/assets/gedefense-logo.png">
    <img src="docs/assets/gedefense-logo.png" alt="GeDefense Retail" width="360">
  </a>
</p>

<h1 align="center">GeDefense Retail</h1>

<p align="center"><strong>ColdChain &amp; Store Infrastructure Security</strong><br>
Monitoraggio OT passivo e gate con applicazione Default-Deny per il percorso di gestione del punto vendita.</p>

<p align="center">
  <a href="https://github.com/visiongaiatechnology/gedefense-retail/releases"><img alt="Release" src="https://img.shields.io/github/v/release/visiongaiatechnology/gedefense-retail?style=flat-square&label=release"></a>
  <img alt="Licenza: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square">
  <img alt="Go 1.23+" src="https://img.shields.io/badge/go-1.23%2B-00ADD8?style=flat-square&logo=go&logoColor=white">
  <img alt="Piattaforme: Linux e Windows" src="https://img.shields.io/badge/platforms-Linux%20%7C%20Windows-444?style=flat-square">
  <img alt="Stato: Alpha" src="https://img.shields.io/badge/status-alpha-orange?style=flat-square">
</p>

[English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Italiano](README.it.md) · [Español](README.es.md) · [日本語](README.ja.md) · [中文](README.zh.md) · [Русский](README.ru.md)

---

<a id="alpha-status"></a>
## Stato alpha

> **0.2.0-alpha.7 — sperimentale, non pronto per la produzione.**
> GeDefense Retail è una alpha preliminare. È stato verificato su loopback con regolatori e
> supervisori simulati, non contro hardware frigorifero reale in un punto vendita. Non esiste ancora
> un penetration test indipendente dell'Access Gate e non viene formulata alcuna dichiarazione di
> conformità o certificazione. Non lo utilizzi come unico controllo di sicurezza, di sicurezza
> alimentare o di monitoraggio di un impianto frigorifero.

<a id="overview"></a>
## Che cos'è

GeDefense Retail protegge e documenta l'infrastruttura che sta dietro un supermercato: regolatori
frigoriferi, celle frigorifere, banchi refrigerati, gateway dei sensori, automazione dell'edificio e
il percorso di manutenzione remota utilizzato dalle aziende di refrigerazione.

Viene distribuito come due servizi separati:

| Servizio | Binario | Ruolo |
|---|---|---|
| **Monitoraggio** | `retaild` | Osservabilità OT passiva e in sola lettura: asset, flussi, integrità della catena del freddo, qualità dei dati, allerte, audit, dashboard |
| **Access Gate** | `retailgate` | L'unico percorso consentito per le scritture di gestione/configurazione verso i regolatori: Default-Deny, vincolato a un piano, approvato da una persona, completamente auditato |
| **Simulatore** | `retail-sim` | Dati di test locali per sviluppo e campagne di accettazione (solo loopback) |

**Promessa del prodotto:**

- **Nessun percorso di scrittura verso il processo OT da GeDefense.** `retaild` e tutti gli adattatori
  passivi non scrivono mai su un regolatore. L'Access Gate non controlla il processo; autorizza e
  inoltra una singola operazione di configurazione esplicitamente approvata.
- **Le scritture sono in Default-Deny.** Una scrittura viene inoltrata solo se corrisponde a un
  *piano di scrittura* approvato (destinazione, protocollo, funzione, indirizzo **e** valore)
  all'interno di una finestra temporale approvata.
- **Controllo umano.** Gli asset critici richiedono due approvazioni distinte, una delle quali da un
  `master_admin`. Non esistono scritture autonome, scritture pianificate o decisioni basate su IA.
- **Fail-closed per il percorso di gestione.** Se il gate si arresta, la gestione remota è chiusa.
  L'impianto frigorifero continua a funzionare in modo autonomo, perché il gate non fa parte del ciclo
  di processo.
- **La prova prima dell'effetto.** Ogni azione e ogni scrittura rifiutata viene registrata in un log di
  audit concatenato tramite hash; il gate si rifiuta di avviarsi se la catena è interrotta.

<a id="features"></a>
## Funzionalità

### Monitoraggio ColdChain (`retaild`, passivo/sola lettura)

- Scoperta passiva degli asset dai metadati dei flussi, dagli indizi OUI e dalle evidenze di
  protocollo — i dispositivi sconosciuti restano sconosciuti, con valori di confidenza.
- Osservazione della rete OT: nuovi interlocutori, percorsi inattesi, metadati di protocollo, baseline
  di flusso.
- Integrità della catena del freddo: soglie di temperatura definite dall'operatore, velocità di
  variazione, scostamento dal setpoint, divergenza tra sensori indipendenti.
- Controlli di qualità dei dati: valori congelati, lacune di telemetria, clock skew, valori non
  plausibili — una lettura scadente non viene mai mostrata come una buona temperatura.
- Accessi di manutenzione: finestre approvate, anomalie negli accessi dei fornitori, metadati delle
  sessioni.
- Regole di rilevamento e incidenti correlati: fatti, ipotesi e verifiche consigliate restano separati
  in ogni allerta.
- Funzionamento local-first: rilevamento e allerta continuano a funzionare senza WAN; spool locale
  limitato per l'inoltro successivo.
- Audit concatenato tramite hash, accesso API basato sui ruoli, dashboard in stile vetro, nessuna CDN
  esterna e nessun framework frontend di terze parti.
- Adattatori passivi/in sola lettura per Modbus TCP, MQTT, BACnet/IP, SNMP (GET v1/v2c), PCAP e
  metadati delle interfacce di gestione HTTP.

### Access Gate (`retailgate`, applicazione del Default-Deny)

- Piani di scrittura con valore attuale, nuovo valore, motivazione, riferimento al ticket (facoltativo),
  finestra e hash del piano immutabile.
- Workflow di approvazione con MFA (TOTP in questa alpha), approvazioni idempotenti, divieto di
  auto-approvazione e principio delle quattro orecchie per gli asset critici.
- Token monouso e sessione di scrittura vincolata all'IP di origine; i tentativi di replay, scadenza e
  origine errata vengono rifiutati e generano un'allerta.
- Proxy di applicazione Modbus TCP e reverse proxy HTTP(S) per le interfacce web dei supervisori.
- Allowlist di registri e URL; l'allowlisting è necessario ma non sufficiente — anche un piano
  approvato deve corrispondere esattamente.
- Deny timeline, evidenze dei rifiuti e audit per ogni scrittura rifiutata.
- Matrice fail-safe: errori di archivio/audit, salti di orologio e policy non valide chiudono il
  percorso di scrittura; un gate non funzionante lascia l'impianto intatto.
- Notifiche webhook firmate HMAC con escalation e presa in carico (`GET /escalations`,
  `POST /escalations/{id}/ack`).

### Novità di 0.2.0-alpha.2

- **Procedura guidata di configurazione** (primo avvio, solo loopback) con passaggi guidati per
  lingua, sito, whitelist di accesso, account amministratore, collector e completamento.
- **Whitelist IP** applicata a dashboard, API, SSE, risorse statiche e setup una volta configurata
  (`require_whitelist` attivo per impostazione predefinita; fail-closed).
- **Otto lingue dell'interfaccia**: inglese, tedesco, francese, italiano, spagnolo, giapponese,
  cinese, russo.
- **Logo GeDefense originale** e mascotte integrati come asset locali (nessuna CDN esterna).
- Pacchetti Linux e Windows con script di installazione e checksum SHA-256.

<a id="architecture"></a>
## Architettura (in breve)

```text
 Azienda di manutenzione / operatore
 (VPN / ZTNA, in whitelist)
        │
        ▼
 ┌──────────────────────────────┐        ┌──────────────────────────────┐
 │ retaild (monitoraggio)       │        │ retailgate (applicazione)    │
 │ TAP/SPAN passivo, sola lettura│      │ identità, approvazione, token│
 │ rilevamento, allerte, audit, UI│     │ audit, proxy Modbus/HTTP     │
 └──────────────┬───────────────┘        └──────────────┬───────────────┘
                │ osservazione passiva                   │ solo percorso di gestione
                │ (non scrive mai)                       │ (vincolato al piano, Default-Deny)
                ▼                                        ▼
        Segmento di monitoraggio OT               Regolatori / supervisori
        (TAP/SPAN, polling in sola lettura)       (Modbus TCP, UI admin HTTP(S))
```

- Un gateway per punto vendita; il funzionamento locale non dipende da Internet.
- L'Access Gate viene distribuito come **appliance/VM separata con due interfacce di rete**: un lato
  gestione/fornitore e un condotto di gestione OT. Non è un router e non si trova nella comunicazione
  di processo tra regolatore e attuatori.
- La gestione centralizzata opzionale è solo in uscita (mTLS).

<a id="alpha-limitations"></a>
## Limiti dichiarati dell'alpha

- **Nessun hardware OT reale testato.** Le evidenze del data plane provengono da regolatori e
  supervisori simulati su loopback. Gli unit ID reali, i flussi di login dei produttori, i certificati
  e gli stati del firmware sono temi del pilota.
- **TOTP non è un fattore resistente al phishing.** FIDO2/WebAuthn è previsto per una versione
  successiva; non viene rivendicata alcuna resistenza per il fattore dell'alpha.
- **La segmentazione è responsabilità dell'operatore.** Senza un progetto di rete reale "nessun secondo
  percorso", il gate può essere aggirato. Il servizio di monitoraggio rende visibili i bypass; non può
  impedirli.
- **Nessuna correlazione automatica dei bypass.** Gate e servizio di monitoraggio sono separati; le
  scritture rifiutate e le allerte passive `retail.write-attempt` vengono correlate manualmente in
  questa alpha.
- **Il certificate pinning e le allowlist dei parametri** sono implementati nel proxy ma non ancora
  esposti nello schema di configurazione.
- **`write_unknown` senza rilettura automatica.** Se la risposta del regolatore è incerta (timeout,
  disconnessione), la scrittura viene contrassegnata come `write_unknown` con un'allerta critica; un
  operatore deve verificare il valore con una rilettura e **non deve riprovare automaticamente**.
- **Le sessioni API sono in memoria.** Un riavvio disconnette gli utenti; è un comportamento
  fail-closed intenzionale.
- **Nessun data plane BACnet/MQTT, nessun controllo del cloud del produttore/dell'HMI locale/USB.**
  Fuori dal perimetro di questa alpha; resta un tema dell'operatore.
- **Nessuna dichiarazione di conformità.** GeDefense Retail non rivendica HACCP, NIS2, IEC 62443 né
  alcun'altra certificazione.
- **I permessi Windows sono diversi da Linux.** Il POSIX `0600/0700` non è un meccanismo di controllo
  degli accessi su Windows; utilizzi un account di servizio dedicato e ACL esplicite. Si tratta di una
  condizione beta documentata.

<a id="download"></a>
## Download

**Ultima release alpha: [v0.2.0-alpha.7](https://github.com/visiongaiatechnology/gedefense-retail/releases/tag/v0.2.0-alpha.7).**
Asset: quattro archivi, [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/SHA256SUMS),
[SHA256SUMS.archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/SHA256SUMS.archives),
[SBOM.spdx.json](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/SBOM.spdx.json)
e firme cosign (`*.sig`/`*.pem`). I binari Windows sono **NOT_SIGNED** (Authenticode, alpha); usi
hash/firme.

| Piattaforma | Archivio | Checksum |
|---|---|---|
| Linux amd64 | [gedefense-retail-0.2.0-alpha.7-linux-amd64.tar.gz](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/gedefense-retail-0.2.0-alpha.7-linux-amd64.tar.gz) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/SHA256SUMS) · [archivi](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/SHA256SUMS.archives) |
| Linux arm64 | [gedefense-retail-0.2.0-alpha.7-linux-arm64.tar.gz](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/gedefense-retail-0.2.0-alpha.7-linux-arm64.tar.gz) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/SHA256SUMS) · [archivi](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/SHA256SUMS.archives) |
| Windows amd64 | [gedefense-retail-0.2.0-alpha.7-windows-amd64.zip](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/gedefense-retail-0.2.0-alpha.7-windows-amd64.zip) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/SHA256SUMS) · [archivi](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/SHA256SUMS.archives) |
| Windows arm64 | [gedefense-retail-0.2.0-alpha.7-windows-arm64.zip](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/gedefense-retail-0.2.0-alpha.7-windows-arm64.zip) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/SHA256SUMS) · [archivi](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.7/SHA256SUMS.archives) |

**Verifichi prima dell'installazione:** `sha256sum -c SHA256SUMS` nell'archivio estratto e
`sha256sum -c SHA256SUMS.archives` per gli archivi scaricati. Archivi e `SHA256SUMS` sono firmati con
cosign keyless; verifichi un file con `cosign verify-blob --certificate <file>.pem --signature
<file>.sig --certificate-oidc-issuer https://token.actions.githubusercontent.com
--certificate-identity-regexp 'https://github.com/visiongaiatechnology/gedefense-retail/.github/workflows/release.yml@refs/tags/v.*' <file>` (identità esatta in
[docs/BUILD-AND-RELEASE.md](docs/BUILD-AND-RELEASE.md)). `SBOM.spdx.json` è l'inventario SPDX.
**Se manca un file di firma, consideri il download non firmato.**

Ogni archivio contiene `bin/` (binari), `config/` (configurazione di esempio e unit systemd), `docs/`,
`README.md`, `LICENSE`, `VERSION`, `THIRD-PARTY-NOTICES.md`, gli script di installazione e un file
`SHA256SUMS`.

<a id="install-linux"></a>
## Installazione — Linux

**Prerequisiti**

- Linux x86-64 o arm64 con systemd.
- Diritti di amministratore per l'installazione.
- Un client di gestione all'interno del CIDR della whitelist prevista (loopback durante il setup).
- Nessuna toolchain Go necessaria per i pacchetti binari.
- Pianifichi la whitelist e la segmentazione OT/gestione **prima** di attivare l'accesso remoto.

**1. Scaricare e verificare**

```bash
tar -xzf gedefense-retail-<version>-linux-amd64.tar.gz
cd gedefense-retail-<version>-linux-amd64
sha256sum -c SHA256SUMS
```

**2. Installare**

```bash
sudo ./install.sh
```

L'installer crea gli account di servizio, installa le unit systemd da `config/`
(`gedefense-retail.service`, `gedefense-retailgate.service`), prepara `/etc/gedefense-retail/`,
`/var/lib/gedefense-retail/`, `/var/lib/gedefense-gate/` e `/var/log/gedefense-retail/`, e lascia il
servizio di monitoraggio pronto per il setup al primo avvio. Copia **solo la configurazione di esempio**
(`retail.example.json`, `gate.example.json`, `gate-policy.example.json`) e non sovrascrive mai i file
esistenti. La configurazione viene installata `root:gedefense` (directory `0750`, file `0640`), le
directory dati appartengono agli account di servizio e l'installer si interrompe se questi passaggi
di permessi falliscono (fail-closed). L'operatore crea la configurazione produttiva a partire dagli
esempi:

```bash
sudo cp /etc/gedefense-retail/retail.example.json /etc/gedefense-retail/retail.json
# modificare retail.json: sede, utenti, collector, whitelist di sicurezza, target/upstream del gate
```

**3. Setup al primo avvio (solo loopback)**

```bash
sudo systemctl enable --now gedefense-retail
```

Con `setup.completed=false` il primo avvio si associa **solo al loopback** (configurare `listen` su
`127.0.0.1:8080` per l'URL seguente). Apra `http://127.0.0.1:8080/setup` sul gateway stesso (tunnel SSH
o browser locale) e completi la procedura guidata: lingua, sede/fuso orario, whitelist di accesso (ad
esempio `127.0.0.1/32`, `::1/128` più il CIDR di gestione), token admin (mostrato **una sola volta**),
collector facoltativi, completamento (`restart_required: true`). `security.setup_token_ttl_s` vale 3600
secondi per impostazione predefinita. La whitelist è fail-closed: senza voce, i client non loopback
ricevono `403 ip_not_allowed` e non viene esposta alcuna pagina di login.

```bash
sudo systemctl restart gedefense-retail
```

**4. Verificare**

```bash
systemctl status gedefense-retail --no-pager
retaild version
curl -s http://127.0.0.1:8080/api/v1/health
```

Solo gli IP di origine all'interno di `security.dashboard_whitelist_cidrs` possono raggiungere
dashboard, API, SSE e risorse statiche. Una richiesta proveniente dall'esterno della whitelist riceve
`403 ip_not_allowed`; non esiste una pagina di login di fallback.

**5. Facoltativo: attivare l'Access Gate**

Attivi il gate solo dopo aver completato la configurazione del monitoraggio. Richiede **sia**
`gate.json` sia `gate-policy.json`; senza configurazione e policy valide si rifiuta di avviarsi
(fail-closed).

```bash
sudo cp /etc/gedefense-retail/gate.example.json /etc/gedefense-retail/gate.json
sudo cp /etc/gedefense-retail/gate-policy.example.json /etc/gedefense-retail/gate-policy.json
# modificare entrambi i file: destinazioni, utenti, whitelist, asset critici, allowlist
sudo retailgate hash-password --password "<at least 12 characters>"
sudo retailgate gen-totp
# inserire l'hash della password e il segreto TOTP stampati in gate.json, poi validare e avviare:
sudo -u gedefense-gate retailgate check --config /etc/gedefense-retail/gate.json
sudo systemctl enable --now gedefense-retailgate
```

Il gate deve essere eseguito sull'appliance/VM separata a due NIC (lato gestione e condotto di gestione
OT), non sull'host di monitoraggio. Senza una segmentazione corretta il gate è aggirabile.

<a id="install-windows"></a>
## Installazione — Windows

**Prerequisiti**

- Windows 10/11 o Windows Server 2019+ (x64 o arm64), PowerShell 5.1+.
- Diritti di amministratore.
- Un client di gestione all'interno del CIDR della whitelist prevista; il setup viene eseguito solo via
  loopback.

**1. Scaricare, estrarre, verificare**

```powershell
Expand-Archive .\gedefense-retail-<version>-windows-amd64.zip -DestinationPath .
cd .\gedefense-retail-<version>-windows-amd64
Get-FileHash .\bin\retaild.exe -Algorithm SHA256
# confrontare con i valori nel file SHA256SUMS (tutti i file dell'archivio)
```

**2. Installare**

```powershell
# PowerShell con diritti di amministratore
.\install-windows.ps1
```

L'installer crea la directory del programma `C:\Program Files\GeDefense\Retail\` (con `bin\` e
`config\`), la directory dati `C:\ProgramData\GeDefense\Retail\` e registra i servizi Windows tramite
`sc.exe` (`gedefense-retail`, `gedefense-retailgate`). Copia **solo la configurazione di esempio**;
l'operatore crea i file produttivi `retail.json` / `gate.json` dagli esempi in `config\`. **Le regole del
firewall non vengono create automaticamente** — aggiunga solo le porte di whitelist e gestione
effettivamente necessarie.

**3. Setup al primo avvio**

```powershell
Start-Service gedefense-retail
```

Apra `http://127.0.0.1:8080/setup` sul gateway (con `listen` impostato su `127.0.0.1:8080`), completi i
sei passaggi del setup, quindi riavvii:

```powershell
Restart-Service gedefense-retail
Get-Service gedefense-retail
.\bin\retaild.exe version
```

**Permessi Windows (alpha):** l'installer esegue entrambi i servizi come `NT AUTHORITY\LocalService`
e applica ACL `icacls` esplicite senza ereditarietà: `config\` in lettura,
`C:\ProgramData\GeDefense\Retail\` in modifica per il servizio, Amministratori controllo completo,
`Users` nessun accesso. I modi POSIX non proteggono NTFS; non riattivi le ACL ereditate. La
disinstallazione non ripristina le ACL precedenti.

**4. Facoltativo: Access Gate**

```powershell
# esempi di configurazione: C:\Program Files\GeDefense\Retail\config\gate.example.json / gate-policy.example.json
# file produttivi: ...\config\gate.json e ...\config\gate-policy.json (modificare destinazioni/utenti/allowlist)
.\bin\retailgate.exe hash-password --password "<at least 12 characters>"
.\bin\retailgate.exe gen-totp
# inserire l'hash della password e il segreto TOTP stampati in gate.json, poi validare e avviare:
.\bin\retailgate.exe check --config "C:\Program Files\GeDefense\Retail\config\gate.json"
Start-Service gedefense-retailgate
```

Il gate richiede entrambi i file di configurazione e si rifiuta di avviarsi senza policy valida
(fail-closed). Lo esegua su un'appliance/VM separata a due NIC; l'installer Windows non configura né la
segmentazione né le regole del firewall.

<a id="quickstart"></a>
## Avvio rapido

1. Installi il pacchetto per la piattaforma in uso.
2. Avvii il servizio di monitoraggio e completi la procedura guidata di setup in loopback.
3. Aggiunga almeno un CIDR di client di gestione alla whitelist — altrimenti ogni richiesta non
   loopback viene rifiutata.
4. Acceda alla dashboard con il token admin mostrato una sola volta dalla procedura guidata.
5. Per simulazione o sviluppo esegua `retail-sim` sul gateway (solo loopback, flag di simulazione
   richiesto) — mai contro dispositivi OT di produzione.

Dai sorgenti (sviluppatori, Go 1.23+, solo libreria standard, nessun CGO):

```bash
go build ./...
go vet ./...
go test ./...
```

<a id="security"></a>
## Modello di sicurezza

- **Monitoraggio in sola lettura.** `retaild` non ha alcun percorso di scrittura OT. Gli adattatori
  passivi non inviano mai codici di funzione di scrittura, non eseguono scansioni attive e non inviano
  sonde grezze.
- **Percorso di gestione in Default-Deny.** `retailgate` inoltra solo le operazioni che corrispondono
  esattamente a un piano approvato; tutto il resto viene rifiutato, auditato e segnalato.
- **Vincolo esatto.** Destinazione, protocollo, funzione, indirizzo e valore vengono approvati come
  unità. Un valore o un indirizzo diverso costituisce un rifiuto, anche all'interno della finestra
  temporale approvata.
- **Approvazione umana.** L'auto-approvazione viene rifiutata; gli asset critici richiedono due
  approvatori distinti, incluso un `master_admin`. Il token monouso viene mostrato una sola volta ed è
  vincolato all'hash del piano e all'IP di origine.
- **Audit prima dell'effetto.** Le operazioni rifiutate e consentite vengono registrate in un log di
  audit concatenato tramite hash; il gate si rifiuta di avviarsi se la catena è interrotta.
- **Fail-closed.** Problemi di gate, archivio, orologio o policy chiudono il percorso di gestione;
  l'impianto continua a funzionare.
- **Rete.** L'applicazione della whitelist è fail-closed. Non esponga dashboard o gate a Internet;
  utilizzi un percorso VPN/ZTNA e impostazioni proxy documentate se necessita di accesso remoto.
- **Segnalazione.** Segnali le vulnerabilità in modo riservato come descritto in
  [SECURITY.md](SECURITY.md). Non esegua test contro impianti frigoriferi di produzione.
- **Nessuna dichiarazione di conformità.** Vedere [SECURITY.md](SECURITY.md) e [NOTICE](NOTICE).

<a id="evidence"></a>
## Stato di verifica (dichiarato)

| Area | Stato |
|---|---|
| Build, vet, test unitari/di integrazione, race detector | verde (loopback/CI) |
| Accettazione end-to-end 0.1 (monitoraggio) | 39/39 controlli superati (loopback/simulazione) |
| End-to-end Access Gate 0.2.0-alpha.1 | 25/25 controlli superati (loopback, regolatori simulati) |
| Design QA | screenshot con dati simulati generati; nessuna validazione screen reader/touch/lunga durata |
| Hardware OT reale | non ancora testato (tema del pilota) |
| Penetration test indipendente del gate | non ancora disponibile |
| Conformità/certificazione | nessuna rivendicata |

I numeri si riferiscono alle campagne di verifica descritte nelle release notes; non costituiscono una
dichiarazione di maturità per la produzione.

<a id="documentation"></a>
## Documentazione

- [README (English)](README.md) · [README (Deutsch)](README.de.md)
- [SECURITY.md](SECURITY.md) — segnalazione, stato alpha, perimetro
- [CONTRIBUTING.md](CONTRIBUTING.md) — build, test, invarianti di sicurezza, pull request
- [CHANGELOG.md](CHANGELOG.md) — cronologia delle release
- [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) — dipendenze e asset
- [NOTICE](NOTICE) — nota su copyright e licenza
- [LICENSE](LICENSE) — GNU Affero General Public License v3.0
- [Indice della documentazione](docs/README.md)
- [Releases](https://github.com/visiongaiatechnology/gedefense-retail/releases) ·
  [Issues](https://github.com/visiongaiatechnology/gedefense-retail/issues)

<a id="license"></a>
## Licenza

GeDefense Retail è distribuito con **GNU Affero General Public License v3.0** (AGPL-3.0).
Vedere [LICENSE](LICENSE) e [NOTICE](NOTICE).

Copyright © 2026 VisionGaiaTechnology.
