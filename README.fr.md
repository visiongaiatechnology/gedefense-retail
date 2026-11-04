<p align="center">
  <a href="docs/assets/gedefense-logo.png">
    <img src="docs/assets/gedefense-logo.png" alt="GeDefense Retail" width="360">
  </a>
</p>

<h1 align="center">GeDefense Retail</h1>

<p align="center"><strong>ColdChain &amp; Store Infrastructure Security</strong><br>
Surveillance OT passive et mise en œuvre du Default-Deny pour le chemin de gestion du magasin.</p>

<p align="center">
  <a href="https://github.com/visiongaiatechnology/gedefense-retail/releases"><img alt="Version" src="https://img.shields.io/github/v/release/visiongaiatechnology/gedefense-retail?style=flat-square&label=release"></a>
  <img alt="Licence : AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square">
  <img alt="Go 1.23+" src="https://img.shields.io/badge/go-1.23%2B-00ADD8?style=flat-square&logo=go&logoColor=white">
  <img alt="Plateformes : Linux et Windows" src="https://img.shields.io/badge/platforms-Linux%20%7C%20Windows-444?style=flat-square">
  <img alt="Statut : Alpha" src="https://img.shields.io/badge/status-alpha-orange?style=flat-square">
</p>

[English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Italiano](README.it.md) · [Español](README.es.md) · [日本語](README.ja.md) · [中文](README.zh.md) · [Русский](README.ru.md)

---

<a id="alpha-status"></a>
## Statut alpha

> **0.2.0-alpha.8 — expérimental, pas prêt pour la production.**
> GeDefense Retail est une alpha précoce. Il a été vérifié sur loopback avec des régulateurs et des
> superviseurs simulés, et non contre du matériel frigorifique réel dans un magasin. Il n'existe pas
> encore de test d'intrusion indépendant de l'Access Gate, et aucune allégation de conformité ou de
> certification n'est formulée. Ne l'utilisez pas comme unique contrôle de sécurité, de sécurité
> alimentaire ou de surveillance d'une installation frigorifique.

<a id="overview"></a>
## Ce que c'est

GeDefense Retail protège et documente l'infrastructure qui se trouve derrière un supermarché :
régulateurs de froid, chambres froides, meubles réfrigérés, passerelles de capteurs, automatisation du
bâtiment et le chemin de maintenance à distance utilisé par les entreprises de froid.

Il est livré sous forme de deux services distincts :

| Service | Binaire | Rôle |
|---|---|---|
| **Surveillance** | `retaild` | Observabilité OT passive et en lecture seule : équipements, flux, intégrité de la chaîne du froid, qualité des données, alertes, audit, tableau de bord |
| **Access Gate** | `retailgate` | Le seul chemin autorisé pour les écritures de gestion/configuration vers les régulateurs : Default-Deny, lié à un plan, approuvé par un humain, entièrement audité |
| **Simulateur** | `retail-sim` | Données de test locales pour le développement et les campagnes d'acceptation (loopback uniquement) |

**Promesse du produit :**

- **Aucun chemin d'écriture vers le processus OT depuis GeDefense.** `retaild` et tous les adaptateurs
  passifs n'écrivent jamais dans un régulateur. L'Access Gate ne contrôle pas le processus ; il
  autorise et transmet une seule opération de configuration explicitement approuvée.
- **Les écritures sont en Default-Deny.** Une écriture n'est transmise que si elle correspond à un
  *plan d'écriture* approuvé (cible, protocole, fonction, adresse **et** valeur) à l'intérieur d'une
  fenêtre temporelle approuvée.
- **Contrôle humain.** Les équipements critiques exigent deux approbations distinctes, dont celle d'un
  `master_admin`. Il n'y a ni écriture autonome, ni écriture planifiée, ni décision par IA.
- **Fail-closed pour le chemin de gestion.** Si le gate s'arrête, la gestion à distance est fermée.
  L'installation frigorifique continue de fonctionner de manière autonome, car le gate ne fait pas
  partie de la boucle de processus.
- **La preuve avant l'effet.** Chaque action et chaque écriture refusée est consignée dans un journal
  d'audit chaîné par hachage ; le gate refuse de démarrer si la chaîne est rompue.

<a id="features"></a>
## Fonctionnalités

### Surveillance ColdChain (`retaild`, passive/lecture seule)

- Découverte passive des équipements à partir des métadonnées de flux, des indices OUI et des preuves
  protocolaires — les appareils inconnus restent inconnus, avec des valeurs de confiance.
- Observation du réseau OT : nouveaux interlocuteurs, chemins inattendus, métadonnées de protocole,
  références de flux (baselines).
- Intégrité de la chaîne du froid : seuils de température définis par l'exploitant, vitesse de
  variation, écart de consigne, divergence entre capteurs indépendants.
- Contrôles de qualité des données : valeurs figées, lacunes de télémétrie, dérive d'horloge, valeurs
  invraisemblables — une mauvaise mesure n'est jamais affichée comme une bonne température.
- Accès de maintenance : fenêtres approuvées, anomalies d'accès des prestataires, métadonnées de
  session.
- Règles de détection et incidents corrélés : faits, hypothèse et vérifications recommandées restent
  séparés dans chaque alerte.
- Fonctionnement local d'abord : la détection et l'alerte continuent de fonctionner sans WAN ; file
  d'attente locale bornée pour une transmission ultérieure.
- Audit chaîné par hachage, accès API basé sur les rôles, tableau de bord de style verre, aucun CDN
  externe et aucun framework frontend tiers.
- Adaptateurs passifs/lecture seule pour Modbus TCP, MQTT, BACnet/IP, SNMP (GET v1/v2c), PCAP et les
  métadonnées d'interface de gestion HTTP.

### Access Gate (`retailgate`, application du Default-Deny)

- Plans d'écriture avec valeur actuelle, nouvelle valeur, motif, référence de ticket (facultative),
  fenêtre et hachage de plan immuable.
- Workflow d'approbation avec MFA (TOTP dans cette alpha), approbations idempotentes, refus de
  l'auto-approbation et principe des quatre yeux pour les équipements critiques.
- Jeton à usage unique et session d'écriture liée à l'IP source ; les tentatives de rejeu,
  d'expiration et de mauvaise source sont refusées et déclenchent une alerte.
- Proxy d'application Modbus TCP et reverse proxy HTTP(S) pour les interfaces web des superviseurs.
- Listes d'autorisation de registres et d'URL ; l'allowlisting est nécessaire mais pas suffisant — un
  plan approuvé doit également correspondre exactement.
- Deny timeline, preuves de refus et audit pour chaque écriture refusée.
- Matrice fail-safe : les erreurs de stockage/d'audit, les sauts d'horloge et une politique invalide
  ferment le chemin d'écriture ; un gate mort laisse l'installation intacte.
- Notifications webhook signées HMAC avec escalade et accusé de réception (`GET /escalations`,
  `POST /escalations/{id}/ack`).

### Nouveautés de 0.2.0-alpha.2

- **Assistant de configuration** (premier lancement, loopback uniquement) avec des étapes guidées pour
  la langue, le site, la liste blanche d'accès, le compte administrateur, les collecteurs et la
  finalisation.
- **Liste blanche IP** appliquée au tableau de bord, à l'API, au SSE, aux ressources statiques et au
  setup une fois configurée (`require_whitelist` activé par défaut ; fail-closed).
- **Huit langues d'interface** : anglais, allemand, français, italien, espagnol, japonais, chinois,
  russe.
- **Logo GeDefense original** et mascotte intégrés comme ressources locales (aucun CDN externe).
- Paquets Linux et Windows avec scripts d'installation et sommes de contrôle SHA-256.

**Nouveau dans 0.2.0-alpha.8 :** documentation fournisseur/pilote dans `docs/retail/`, relecture CurrentValue avant écriture Modbus (écart/échec ⇒ refus + audit), catalogue fournisseur d'exécution (pas d'auto-allow) et `data/ot-catalog` dans le paquet.

<a id="architecture"></a>
## Architecture (en bref)

```text
 Entreprise de maintenance / exploitant
 (VPN / ZTNA, sur liste blanche)
        │
        ▼
 ┌──────────────────────────────┐        ┌──────────────────────────────┐
 │ retaild (surveillance)       │        │ retailgate (application)     │
 │ TAP/SPAN passif, lecture seule│       │ identité, approbation, jeton │
 │ détection, alertes, audit, UI │       │ audit, proxys Modbus/HTTP    │
 └──────────────┬───────────────┘        └──────────────┬───────────────┘
                │ observation passive                    │ chemin de gestion uniquement
                │ (n'écrit jamais)                       │ (lié au plan, Default-Deny)
                ▼                                        ▼
        Segment de surveillance OT                Régulateurs / superviseurs
        (TAP/SPAN, polling en lecture seule)      (Modbus TCP, UI d'admin HTTP(S))
```

- Une passerelle par magasin ; le fonctionnement local ne dépend pas d'Internet.
- L'Access Gate est déployé comme **appliance/VM distincte avec deux interfaces réseau** : un côté
  gestion/prestataire et un conduit de gestion OT. Ce n'est pas un routeur et il ne se trouve pas dans
  la communication de processus entre régulateur et actionneurs.
- La gestion centralisée optionnelle est sortante uniquement (mTLS).

<a id="alpha-limitations"></a>
## Limites honnêtes de l'alpha

- **Aucun matériel OT réel testé.** Les preuves de la data plane proviennent de régulateurs et de
  superviseurs simulés sur loopback. Les unit IDs réels, les flux de connexion des fabricants, les
  certificats et les états de firmware sont des sujets de pilote.
- **TOTP n'est pas un facteur résistant au phishing.** FIDO2/WebAuthn est prévu pour une version
  ultérieure ; aucune résistance n'est revendiquée pour le facteur de l'alpha.
- **La segmentation est la responsabilité de l'exploitant.** Sans une véritable conception réseau
  « aucun second chemin », le gate peut être contourné. Le service de surveillance rend les
  contournements visibles ; il ne peut pas les empêcher.
- **Pas de corrélation automatique des contournements.** Le gate et le service de surveillance sont
  séparés ; les écritures refusées et les alertes passives `retail.write-attempt` sont corrélées
  manuellement dans cette alpha.
- **Le certificate pinning et les listes d'autorisation de paramètres** sont implémentés dans le proxy
  mais pas encore exposés dans le schéma de configuration.
- **`write_unknown` sans relecture automatique.** Si la réponse du régulateur est incertaine (timeout,
  déconnexion), l'écriture est marquée `write_unknown` avec une alerte critique ; un opérateur doit
  vérifier la valeur par une relecture et **ne doit pas réessayer automatiquement**.
- **Les sessions API sont en mémoire.** Un redémarrage déconnecte les utilisateurs ; il s'agit d'un
  comportement fail-closed intentionnel.
- **Pas de data plane BACnet/MQTT, pas de contrôle du cloud fabricant/de l'IHM locale/USB.** Hors
  périmètre de cette alpha ; cela reste du ressort de l'exploitant.
- **Aucune déclaration de conformité.** GeDefense Retail ne revendique ni HACCP, ni NIS2, ni
  IEC 62443, ni aucune autre certification.
- **Les permissions Windows diffèrent de Linux.** Le POSIX `0600/0700` n'est pas un mécanisme de
  contrôle d'accès sous Windows ; utilisez un compte de service dédié et des ACL explicites. Il s'agit
  d'une condition bêta documentée.

<a id="download"></a>
## Téléchargement

**Dernière release alpha : [v0.2.0-alpha.8](https://github.com/visiongaiatechnology/gedefense-retail/releases/tag/v0.2.0-alpha.8).**
Ressources : quatre archives, [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS),
[SHA256SUMS.archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS.archives),
[SBOM.spdx.json](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SBOM.spdx.json)
et signatures cosign (`*.sig`/`*.pem`). Les binaires Windows sont **NOT_SIGNED** (Authenticode, alpha) ;
utilisez les hachages/signatures.

| Plateforme | Archive | Sommes de contrôle |
|---|---|---|
| Linux amd64 | [gedefense-retail-0.2.0-alpha.8-linux-amd64.tar.gz](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/gedefense-retail-0.2.0-alpha.8-linux-amd64.tar.gz) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS) · [archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS.archives) |
| Linux arm64 | [gedefense-retail-0.2.0-alpha.8-linux-arm64.tar.gz](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/gedefense-retail-0.2.0-alpha.8-linux-arm64.tar.gz) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS) · [archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS.archives) |
| Windows amd64 | [gedefense-retail-0.2.0-alpha.8-windows-amd64.zip](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/gedefense-retail-0.2.0-alpha.8-windows-amd64.zip) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS) · [archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS.archives) |
| Windows arm64 | [gedefense-retail-0.2.0-alpha.8-windows-arm64.zip](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/gedefense-retail-0.2.0-alpha.8-windows-arm64.zip) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS) · [archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.8/SHA256SUMS.archives) |

**Vérifiez avant installation :** `sha256sum -c SHA256SUMS` dans l'archive décompressée et
`sha256sum -c SHA256SUMS.archives` pour les archives téléchargées. Les archives et `SHA256SUMS` sont
signés avec cosign keyless ; vérifiez un fichier avec `cosign verify-blob --certificate <fichier>.pem
--signature <fichier>.sig --certificate-oidc-issuer https://token.actions.githubusercontent.com
--certificate-identity-regexp 'https://github.com/visiongaiatechnology/gedefense-retail/.github/workflows/release.yml@refs/tags/v.*' <fichier>` (identité exacte dans
[docs/BUILD-AND-RELEASE.md](docs/BUILD-AND-RELEASE.md)). `SBOM.spdx.json` est le SBOM SPDX des archives et binaires de release ; tous les fichiers du bundle sont couverts par le `SHA256SUMS` du bundle.
**Si un fichier de signature manque, traitez le téléchargement comme non signé.**

Chaque archive contient `bin/` (binaires), `config/` (configuration d'exemple et unités systemd),
`docs/`, `README.md`, `LICENSE`, `VERSION`, `THIRD-PARTY-NOTICES.md`, les scripts d'installation et un
fichier `SHA256SUMS`.

<a id="install-linux"></a>
## Installation — Linux

**Prérequis**

- Linux x86-64 ou arm64 avec systemd.
- Droits d'administrateur pour l'installation.
- Un client de gestion dans le CIDR de la liste blanche prévue (loopback pendant le setup).
- Aucune toolchain Go n'est requise pour les paquets binaires.
- Planifiez la liste blanche et la segmentation OT/gestion **avant** d'activer l'accès à distance.

**1. Télécharger et vérifier**

```bash
tar -xzf gedefense-retail-<version>-linux-amd64.tar.gz
cd gedefense-retail-<version>-linux-amd64
sha256sum -c SHA256SUMS
```

**2. Installer**

```bash
sudo ./install.sh
```

L'installateur crée le ou les comptes de service, installe les unités systemd depuis `config/`
(`gedefense-retail.service`, `gedefense-retailgate.service`), prépare `/etc/gedefense-retail/`,
`/var/lib/gedefense-retail/`, `/var/lib/gedefense-gate/` et `/var/log/gedefense-retail/`, et laisse le
service de surveillance prêt pour le setup au premier lancement. Il ne copie que la **configuration
d'exemple** (`retail.example.json`, `gate.example.json`, `gate-policy.example.json`) et n'écrase jamais
les fichiers existants. La configuration est installée `root:gedefense` (répertoires `0750`, fichiers
`0640`), les répertoires de données appartiennent aux comptes de service et l'installateur s'arrête
si ces étapes de permissions échouent (fail-closed). L'exploitant crée la configuration de production
à partir des exemples :

```bash
sudo cp /etc/gedefense-retail/retail.example.json /etc/gedefense-retail/retail.json
# modifier retail.json : site, utilisateurs, collecteurs, liste blanche de sécurité, cibles/amonts du gate
```

**3. Setup au premier lancement (loopback uniquement)**

```bash
sudo systemctl enable --now gedefense-retail
```

Avec `setup.completed=false`, le premier démarrage n'écoute **que sur loopback** (configurez `listen`
sur `127.0.0.1:8080` pour l'URL ci-dessous). Ouvrez `http://127.0.0.1:8080/setup` sur la passerelle
elle-même (tunnel SSH ou navigateur local) et terminez l'assistant : langue, site/fuseau horaire, liste
blanche d'accès (par exemple `127.0.0.1/32`, `::1/128` plus votre CIDR de gestion), jeton admin (affiché
**une seule fois**), collecteurs facultatifs, finalisation (`restart_required: true`).
`security.setup_token_ttl_s` vaut 3600 secondes par défaut. La liste blanche est fail-closed : sans
entrée, les clients hors loopback reçoivent `403 ip_not_allowed` et aucune page de connexion n'est
exposée.

```bash
sudo systemctl restart gedefense-retail
```

**4. Vérifier**

```bash
systemctl status gedefense-retail --no-pager
retaild version
curl -s http://127.0.0.1:8080/api/v1/health
```

Seules les IP sources situées dans `security.dashboard_whitelist_cidrs` peuvent atteindre le tableau de
bord, l'API, le SSE et les ressources statiques. Une requête provenant de l'extérieur de la liste
blanche reçoit `403 ip_not_allowed` ; il n'existe aucune page de connexion de secours.

**5. Facultatif : activer l'Access Gate**

N'activez le gate qu'une fois la configuration du monitoring terminée. Il exige **à la fois**
`gate.json` et `gate-policy.json` ; sans configuration et politique valides, il refuse de démarrer
(fail-closed).

```bash
sudo cp /etc/gedefense-retail/gate.example.json /etc/gedefense-retail/gate.json
sudo cp /etc/gedefense-retail/gate-policy.example.json /etc/gedefense-retail/gate-policy.json
# modifier les deux fichiers : cibles, utilisateurs, liste blanche, actifs critiques, listes d'autorisation
sudo retailgate hash-password --password "<at least 12 characters>"
sudo retailgate gen-totp
# insérer le hash de mot de passe et le secret TOTP affichés dans gate.json, puis valider et démarrer :
sudo -u gedefense-gate retailgate check --config /etc/gedefense-retail/gate.json
sudo systemctl enable --now gedefense-retailgate
```

Le gate doit fonctionner sur l'appliance/VM distincte à deux NIC (côté gestion et conduit de gestion
OT), pas sur l'hôte de surveillance. Sans segmentation correcte, le gate est contournable.

<a id="install-windows"></a>
## Installation — Windows

**Prérequis**

- Windows 10/11 ou Windows Server 2019+ (x64 ou arm64), PowerShell 5.1+.
- Droits d'administrateur.
- Un client de gestion dans le CIDR de la liste blanche prévue ; le setup s'exécute uniquement via
  loopback.

**1. Télécharger, extraire, vérifier**

```powershell
Expand-Archive .\gedefense-retail-<version>-windows-amd64.zip -DestinationPath .
cd .\gedefense-retail-<version>-windows-amd64
Get-FileHash .\bin\retaild.exe -Algorithm SHA256
# comparer avec les valeurs du fichier SHA256SUMS (tous les fichiers de l'archive)
```

**2. Installer**

```powershell
# PowerShell avec droits d'administrateur
.\install-windows.ps1
```

L'installateur crée le répertoire de programme `C:\Program Files\GeDefense\Retail\` (avec `bin\` et
`config\`), le répertoire de données `C:\ProgramData\GeDefense\Retail\`, et enregistre les services
Windows via `sc.exe` (`gedefense-retail`, `gedefense-retailgate`). Il ne copie que la **configuration
d'exemple** ; l'exploitant crée les fichiers de production `retail.json` / `gate.json` à partir des
exemples dans `config\`. **Les règles de pare-feu ne sont pas créées automatiquement** — n'ajoutez que
les ports de liste blanche et de gestion réellement nécessaires.

**3. Setup au premier lancement**

```powershell
Start-Service gedefense-retail
```

Ouvrez `http://127.0.0.1:8080/setup` sur la passerelle (avec `listen` défini sur `127.0.0.1:8080`),
terminez les six étapes de setup, puis redémarrez :

```powershell
Restart-Service gedefense-retail
Get-Service gedefense-retail
.\bin\retaild.exe version
```

**Permissions Windows (alpha) :** l'installateur exécute les deux services comme
`NT AUTHORITY\LocalService` et applique des ACL `icacls` explicites sans héritage : `config\` en
lecture, `C:\ProgramData\GeDefense\Retail\` en modification pour le service, Administrateurs en
contrôle total, `Users` sans accès. Les modes POSIX ne protègent pas NTFS ; ne réactivez pas les ACL
héritées. La désinstallation ne restaure pas les ACL précédentes.

**4. Facultatif : Access Gate**

```powershell
# exemples de configuration : C:\Program Files\GeDefense\Retail\config\gate.example.json / gate-policy.example.json
# fichiers de production : ...\config\gate.json et ...\config\gate-policy.json (modifier cibles/utilisateurs/listes d'autorisation)
.\bin\retailgate.exe hash-password --password "<at least 12 characters>"
.\bin\retailgate.exe gen-totp
# insérer le hash de mot de passe et le secret TOTP affichés dans gate.json, puis valider et démarrer :
.\bin\retailgate.exe check --config "C:\Program Files\GeDefense\Retail\config\gate.json"
Start-Service gedefense-retailgate
```

Le gate exige les deux fichiers de configuration et refuse de démarrer sans politique valide
(fail-closed). Exécutez-le sur une appliance/VM distincte à deux NIC ; l'installateur Windows ne
configure ni la segmentation ni les règles de pare-feu.

<a id="quickstart"></a>
## Démarrage rapide

1. Installez le paquet correspondant à votre plateforme.
2. Démarrez le service de surveillance et terminez l'assistant de setup en loopback.
3. Ajoutez au moins un CIDR de client de gestion à la liste blanche — sinon toute requête non-loopback
   est refusée.
4. Connectez-vous au tableau de bord avec le jeton admin affiché une seule fois par l'assistant.
5. Pour la simulation ou le développement, exécutez `retail-sim` sur la passerelle (loopback uniquement,
   indicateur de simulation requis) — jamais contre des appareils OT de production.

Depuis les sources (développeurs, Go 1.23+, bibliothèque standard uniquement, pas de CGO) :

```bash
go build ./...
go vet ./...
go test ./...
```

<a id="security"></a>
## Modèle de sécurité

- **Surveillance en lecture seule.** `retaild` ne dispose d'aucun chemin d'écriture OT. Les adaptateurs
  passifs n'envoient jamais de codes de fonction d'écriture, n'effectuent jamais de scans actifs et
  n'envoient jamais de sondes brutes.
- **Chemin de gestion en Default-Deny.** `retailgate` ne transmet que les opérations qui correspondent
  exactement à un plan approuvé ; tout le reste est refusé, audité et signalé.
- **Liaison exacte.** La cible, le protocole, la fonction, l'adresse et la valeur sont approuvés comme un
  tout. Une valeur ou une adresse différente constitue un refus, même à l'intérieur de la fenêtre
  temporelle approuvée.
- **Approbation humaine.** L'auto-approbation est rejetée ; les équipements critiques exigent deux
  approbateurs distincts, dont un `master_admin`. Le jeton à usage unique est affiché une seule fois et
  lié au hachage du plan et à l'IP source.
- **Audit avant effet.** Les opérations refusées et autorisées sont consignées dans un journal d'audit
  chaîné par hachage ; le gate refuse de démarrer si la chaîne est rompue.
- **Fail-closed.** Les problèmes de gate, de stockage, d'horloge ou de politique ferment le chemin de
  gestion ; l'installation continue de fonctionner.
- **Réseau.** L'application de la liste blanche est fail-closed. N'exposez pas le tableau de bord ou le
  gate à Internet ; utilisez un chemin VPN/ZTNA et des paramètres de proxy documentés si vous avez
  besoin d'un accès à distance.
- **Signalement.** Veuillez signaler les vulnérabilités de manière confidentielle comme décrit dans
  [SECURITY.md](SECURITY.md). Ne testez pas contre des équipements frigorifiques de production.
- **Aucune déclaration de conformité.** Voir [SECURITY.md](SECURITY.md) et [NOTICE](NOTICE).

<a id="evidence"></a>
## État de vérification (honnête)

| Domaine | Statut |
|---|---|
| Build, vet, tests unitaires/intégration, détecteur de courses | vert (loopback/CI) |
| Acceptation de bout en bout 0.1 (surveillance) | 39/39 contrôles réussis (loopback/simulation) |
| Bout en bout de l'Access Gate 0.2.0-alpha.1 | 25/25 contrôles réussis (loopback, régulateurs simulés) |
| Design QA | captures d'écran avec données simulées générées ; aucune validation lecteur d'écran/tactile/longue durée |
| Matériel OT réel | pas encore testé (sujet de pilote) |
| Test d'intrusion indépendant du gate | pas encore disponible |
| Conformité/certification | aucune revendiquée |

Les chiffres se rapportent aux campagnes de vérification décrites dans les notes de version ; ils ne
constituent pas une déclaration de maturité de production.

<a id="documentation"></a>
## Documentation

- [README (English)](README.md) · [README (Deutsch)](README.de.md)
- [SECURITY.md](SECURITY.md) — signalement, statut alpha, périmètre
- [CONTRIBUTING.md](CONTRIBUTING.md) — build, tests, invariants de sécurité, pull requests
- [CHANGELOG.md](CHANGELOG.md) — historique des versions
- [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) — dépendances et ressources
- [NOTICE](NOTICE) — mention de copyright et de licence
- [LICENSE](LICENSE) — GNU Affero General Public License v3.0
- [Index de la documentation](docs/README.md)
- [Releases](https://github.com/visiongaiatechnology/gedefense-retail/releases) ·
  [Issues](https://github.com/visiongaiatechnology/gedefense-retail/issues)

<a id="license"></a>
## Licence

GeDefense Retail est distribué sous **GNU Affero General Public License v3.0** (AGPL-3.0).
Voir [LICENSE](LICENSE) et [NOTICE](NOTICE).

Copyright © 2026 VisionGaiaTechnology.
