# Safety Boundaries — GeDefense Retail (unverhandelbare Invarianten)

| Feld | Wert |
|---|---|
| Dokument-ID | DOC-RETAIL-SB-001 |
| Version / Stand | 1.0 / 2026-11-03 |
| Grundlage | Baukonzept §0 (Regeln 5–7), §2.2 (harte Grenzen), §7 (MVP-Nicht-Ziele), §10 (Safety-Abnahme) |
| Charakter | **Normativ.** Jede Invariante ist eine Freigabebedingung. Verletzung = Release-Blocker, unabhängig von Funktionsumfang. |
| Zielgruppe | Implementierung, Test, Code-Review, Pilotfreigabe (technischer Betreiberverantwortlicher) |

**Lesart:** „Technische Durchsetzung“ benennt den Mechanismus, der die Invariante *strukturell* erzwingt (Typen, Interfaces, Konfigvalidierung, Laufzeit-Guard, Prozessgrenze, CI-Gate). „Verifikationsmethode“ benennt, wie die Durchsetzung **nachgewiesen** wird. „Testfall“ ist der verbindliche Name für den automatisierten Nachweis. Ein Test ohne bestandene Ausführung ist **kein** Nachweis.

---

## 0. Durchsetzungsebenen (gemeinsames Modell)

| Ebene | Mechanismus | Wirkung |
|---|---|---|
| E1 Compile/Typen | Interface `ports.Collector` besitzt **keine** schreibenden Methoden; Schreib-Symbole existieren nicht im Adapter-Paket | Code mit Schreibpfad kompiliert nicht bzw. fällt im AST-Gate auf |
| E2 Konfigvalidierung | Config-Validierung erzwingt `ReadOnly=true`; unbekannte/aktive Optionen werden abgewiesen | Fehlkonfiguration startet nicht |
| E3 Laufzeit-Guard | `internal/guard` + `internal/netx`: nur konfigurierte Leseendpunkte, keine Raw-Sockets, kein Routing, keine Paket-Injektion | Adapter kann keine Schreib-/Scan-Pakete senden |
| E4 Prozess-Isolation | Adapter/Core getrennt, Panic-Recovery, bounded Queues | Parserfehler erreicht Core nicht |
| E5 UI-/Datenvertrag | `SecurityAlert` trennt Beobachtung/Hypothese/Maßnahme als eigene Felder; UI rendert drei Abschnitte | Alarmtext kann Beobachtung nicht als Hypothese ausgeben (und umgekehrt) |
| E6 CI-Gate | Statische/AST-Tests, verbotene Begriffe, Regel-Pflichtdatensatz | Verstoß blockiert Merge/Release |
| E7 Architektur | Gateway ist out-of-band (TAP/SPAN), nie inline; kein Rückkanal in die Anlagensteuerung | Ausfall/Kompromittierung des Gateways wirkt nicht auf die Anlage |

**Grundregel:** Eine Invariante gilt nur als durchgesetzt, wenn sie auf **E1–E3** beruht. Organisatorische Ebenen (E5–E7) sind zusätzlich erforderlich, ersetzen aber keine strukturelle Durchsetzung.

---

## 1. Invarianten

### S-01 · Kein Schreibzugriff auf PLC, Regler oder Gebäudeleitsystem
**Invariante:** GeDefense Retail besitzt keinen Code-Pfad, der Sollwerte, Parameter, Betriebsmodi, Programme oder Firmware an PLC/Regler/BMS schreibt — auch nicht „nur zum Testen“.

- **Begründung:** Jeder Schreibpfad ist sowohl Unfall- als auch Angriffsfläche; ein Monitoring-Produkt darf niemals Steuerautorität erhalten (Baukonzept §0 Regel 5, §2.2).
- **Durchsetzung:** E1 (`ports.Collector` besitzt keine Write-Methode; `guard.Capability` ist versiegelt und bietet nur `DenyWrite`), E2 (`ReadOnly` erzwungen), E3 (Guard verbietet Schreib-Frames/PDUs), E6 (AST-Gate).
- **Verifikation:** AST-/Symbol-Scan der Adapter- und Guard-Pakete auf Schreib-Symbole; statische Konfigprüfung; Simulator-Test, dass bei jeder Adapter-Interaktion ausschließlich Leseframes beobachtet werden.
- **Testfälle:** `TestSafety_AdapterSurfaceHasNoWriteMethods`, `TestSafety_ForbiddenWriteSymbols_ASTGate`, `TestSafety_ConfigRejectsWritableMode`, `TestSim_AdapterEmitsOnlyReadFrames`
- **Beweislücke:** Der Test beweist die Abwesenheit im geprüften Code-Stand, nicht die Abwesenheit in allen Builds; deshalb zusätzlich Release-Artefakt-Scan (E6).

### S-02 · Keine Aktorik (Ventile, Verdichter, Lüfter, Kompressoren)
**Invariante:** Keine Ansteuerung physischer Aktoren, keine Abschaltung, kein „Not-Aus“ durch GeDefense.

- **Begründung:** Abschaltung einer Kühlanlage auf Basis einer Cybersecurity-Erkennung kann die Kühlkette *verschlechtern* (Baukonzept §2.2).
- **Durchsetzung:** E1–E3 wie S-01; zusätzlich E5 `safety_constraints[]` in jedem Alert; Response-Funktionen (falls später) nur Managementpfad (S-05).
- **Verifikation:** Scan auf Aktor-/Steuer-Symbole (`Actuate`, `Switch`, `SetOutput`, `Control`, `Shutdown`, `StopPlant`); Negativtest: Alert führt zu **keiner** ausgehenden Verbindung zum Anlagenziel.
- **Testfälle:** `TestSafety_NoActuatorSymbolsInCode`, `TestAlert_DoesNotTriggerPlantAction`, `TestResponse_OnlyManagementPathAllowed`
- **Beweislücke:** Fachliche Aktorik kann über Protokoll-Metadaten nur erkannt, nicht ausgeschlossen werden, wenn das Gerät selbst steuert — das ist Anlagenverhalten, nicht GeDefense-Verhalten.

### S-03 · Kein aktives Scannen produktiver OT
**Invariante:** Keine aktiven Scans, Fuzzing-Aktionen, Verbindungsfluten, Schreibtests oder unaufgeforderte Verbindungsaufbauten gegen produktive OT-Geräte. Keine Login-/Auth-Tests, kein Brute-Force, kein UI-Crawling an Management-Oberflächen (z. B. StoreView/XWEB). Discovery ist passiv (TAP/SPAN, freigegebene Read-only-Polling-Punkte).

- **Begründung:** Aktive Last kann alte Steuerungen zum Absturz bringen; Baukonzept §0 Regel 7, §5 Modul A.
- **Durchsetzung:** E3: `guard.DenyActiveScan` ist der einzige Pfad für Scan-Anfragen und verweigert immer; `netx` erlaubt ausschließlich Verbindungen zu explizit konfigurierten Lese-Endpunkten mit Rate-/Timeout-Budget; kein `AF_PACKET`-Write, kein Raw-Socket-Versand, kein SYN-Scan, keine Broadcast-/Multicast-Stürme; E2: aktive Scan-Option existiert nicht in der Config.
- **Verifikation:** Code-Scan auf Scan-/Raw-Socket-APIs; Laufzeit-Test mit simuliertem OT-Netz, das jede nicht-allowlistete Verbindung protokolliert (Erwartung: keine); Rate-Limit-Test.
- **Testfälle:** `TestDiscovery_PassiveOnly_NoActiveProbe`, `TestNetx_DeniesNichtAllowlisteteVerbindung`, `TestNetx_RateBudgetRespected`, `TestSafety_NoRawSocketSend`
- **Beweislücke:** Ein kompromittiertes Gateway kann technisch alles tun; die Invariante schützt vor Produktverhalten, nicht vor einem Angreifer mit Codeausführung (→ R-05).

### S-04 · GeDefense-Ausfall beeinträchtigt den Anlagenbetrieb nicht
**Invariante:** Ausfall, Neustart, Update, Fehlkonfiguration oder WAN-Verlust von GeDefense darf Kühlung, Lüftung, Alarmierung der Anlage und sonstige Anlagensteuerung **nicht** beeinträchtigen. Kein Inline-Betrieb, kein Fail-Closed der OT, keine Abhängigkeit der Anlage von GeDefense.

- **Begründung:** Monitoring darf nie zur Verfügbarkeitsvoraussetzung werden (Baukonzept §0 Regel 6, §2.1 graceful degradation).
- **Durchsetzung:** E7 (Architektur: out-of-band; keine Netzwerkkomponente im Datenpfad der Anlage), E4 (Prozessisolation), kein Schreib-/Blockierpfad (S-01/S-05).
- **Verifikation:** Integrationstest mit Anlagensimulator: Agent/Gateway stoppen, neustarten, aktualisieren → simulierter Kühlzyklus läuft unverändert weiter; Netzwerkfluss-Analyse zeigt keinen Pfad, der Anlagenkommunikation durch GeDefense führt.
- **Testfälle:** `TestFailSafe_AgentStop_NoImpactOnSimulatedPlant`, `TestFailSafe_GatewayCrash_PlantUnaffected`, `TestFailSafe_UpdateRollback_PlantUnaffected`, `TestTopology_NoInlinePlacement`
- **Beweislücke:** Aussage gilt für die spezifizierte Deployment-Topologie; eine fehlerhafte Installation, die das Gateway inline platziert, würde die Invariante verletzen. Deshalb ist die Topologie Teil der Installationsabnahme.

### S-05 · Keine automatische Isolation der OT-Prozesskommunikation
**Invariante:** GeDefense isoliert, blockiert oder unterbricht **nie automatisch** die Kommunikation zwischen OT-Prozessgeräten. Eine spätere Response-Integration ist ausschließlich auf den dedizierten Management-/Fernwartungspfad begrenzt, explizit freigegeben, protokolliert, reversibel und räumlich/zeitlich begrenzt.

- **Begründung:** Blockade der OT-Prozesskommunikation kann einen sicheren Anlagenbetrieb gefährden (Baukonzept §2.2, §5 Modul C).
- **Durchsetzung:** Es existiert **kein** Code-Pfad von Alert/Detection zu einer Blockieraktion auf OT-Zielen; `safety_constraints[]` verlangt für jede empfohlene Aktion den Zielpfad; Response-Funktionen sind im MVP nicht implementiert; ein späterer Response-Pfad muss eine Allowlist „nur Management-/Fernwartung“ validieren.
- **Verifikation:** AST-/Aufrufgraph-Analyse „Alert → Netzwerkaktion“ (Erwartung: leer); Negativtest: simulierter Angriff erzeugt Alert, aber keine Blockierung; Review-Checkliste für jede künftige Response-Funktion.
- **Testfälle:** `TestSafety_NoAutoIsolationOnAlert`, `TestResponse_TargetMustBeManagementPath`, `TestResponse_RequiresExplicitApprovalAndAudit`
- **Beweislücke:** Ein Betreiber kann außerhalb von GeDefense (Firewall/Netzwerk) blockieren — das ist eine bewusste Betreiberaktion mit eigenem Freigabeprozess, nicht GeDefense-Verhalten.

### S-06 · Alarmtrennung: Beobachtung / Hypothese / empfohlene Prüfung
**Invariante:** Jeder Alarm trennt strukturell drei Kategorien: (1) **beobachtete Fakten** mit Messwerten/Zeitstempeln, (2) **abgeleitete Hypothese** mit Confidence und Alternativerklärungen, (3) **empfohlene Prüfung** (keine automatische Maßnahme). Keine Vermischung in einem Textfeld, keine Hypothese als Tatsache.

- **Begründung:** Ein einzelner Temperaturwert ist kein Cyberangriff; Türöffnung, Warenbeladung, Abtau, Sensorfehler sind gleichwertige Erklärungen (Baukonzept §5 Modul E, §6 Schritt 8, §10 Safety).
- **Durchsetzung:** E5: `domain.Alert.Correlation` (`CorrelationSummary`) trennt `ObservedFacts[]`, `Hypothesis` (String), `AlternativeExplanations[]`, `RecommendedChecks[]`, `Indicators[]`; `Alert.Validate` erzwingt Facts + Hypothese, sobald `Correlation` gesetzt ist; `RecommendedAction.RequiresApproval` markiert, was nie automatisch ausgeführt wird; UI rendert drei getrennte Blöcke.
- **Verifikation:** Schema-/Unit-Test auf Pflichtfelder; UI-Snapshot/Contract-Test; Negativtest, dass eine Hypothese ohne beobachtete Fakten als Validierungsfehler abgelehnt wird.
- **Testfälle:** `TestAlert_ThreeSectionContract`, `TestAlert_HypothesisRequiresObservation`, `TestAlert_AlternativeExplanationsPresent`, `TestUI_RendersThreeSectionsSeparated`
- **Beweislücke:** Semantische Qualität der Formulierungen ist nur über Review-/Copy-Tests teilweise prüfbar (E6 verbotene Behauptungen).

### S-07 · Keine HACCP-, NIS2- oder Zertifizierungsbehauptung
**Invariante:** Keine Aussage in Produkt, UI, Alarmtexten, Marketing oder Doku, die HACCP-Konformität, NIS2-Konformität, Zertifizierung, „garantierte Lebensmittelsicherheit“ oder „verhindert Kühlkettenausfall“ behauptet.

- **Begründung:** Baukonzept §0 Regel 8; regulatorische Aussagen sind ohne unabhängige Prüfung und Rechtsfreigabe unzulässig (vgl. `threat-model.md` §7).
- **Durchsetzung:** E6: Copy-/String-Gate mit Sperrliste (`HACCP-konform`, `NIS2-konform`, `zertifiziert`, `garantiert`, `verhindert jeden`, `lebensmittelsicher`) über UI/i18n/Alarmkatalog/Doku; Freigabeprozess für regulatorische Begriffe.
- **Verifikation:** CI-String-Scan; Review der Alarmtexte; dokumentierte Freigabe nur bei belegter externer Prüfung.
- **Testfälle:** `TestCopy_ForbiddenClaims`, `TestAlertTexts_NoComplianceAssertion`, `TestDocs_NoCertificationClaim`
- **Beweislücke:** Der Scan erkennt Formulierungen, nicht Bedeutung; menschlicher Review bleibt Pflicht.

### S-08 · Keine universellen, hart codierten Temperaturgrenzwerte
**Invariante:** Grenzwerte, Änderungsraten und Modusfenster kommen aus versionierten, betreiberverantworteten Policies je Site/Zone/Asset; der Code enthält keine universellen Produktgrenzwerte.

- **Begründung:** Grenzwerte hängen von Produkt, Gerät, Prozess und gültigen betrieblichen Vorgaben ab (Baukonzept §5 Modul D).
- **Durchsetzung:** E2: Start ohne gültige Policy verweigert Detection-Regeln; jede Policy trägt `site_id`, `version`, `actor`, `reason`; Code-Scan verbietet numerische Temperatur-Konstanten in Detect-Regeln.
- **Verifikation:** Statischer Test auf verbotene Konstanten; Policy-Versionierungs- und Freigabetests; Test „ohne Policy kein Grenzwert-Alarm“.
- **Testfälle:** `TestPolicy_NoDefaultTemperatureThresholds`, `TestDetect_RequiresVersionedPolicy`, `TestPolicy_ChangeHasActorReasonDiff`
- **Beweislücke:** Ein Betreiber kann unsinnige Grenzwerte setzen; GeDefense kann die betriebliche Richtigkeit nicht bewerten.

### S-09 · Datenminimierung und Mandantentrennung
**Invariante:** Standardmäßig keine Paket-Payloads, keine personenbezogenen Inhalte, keine Klartext-Secrets in Config/Logs. Jede Entität ist `site_id`-gescoped; Cross-Site-Zugriff wird serverseitig verweigert.

- **Begründung:** Baukonzept §6 Schritte 12/14, §10 Betrieb.
- **Durchsetzung:** E5: `Event.PayloadMeta` ist auf kleine, nicht-sensitive Metadaten begrenzt (Schlüssel ≤ 64 B, Wert ≤ 256 B); kein Roh-Paket-/Payload-Feld im Schema; Store-API verlangt `site_id` als Pflichtparameter; Authz prüft Rollen-/Site-Scope serverseitig; Secret-Handling über bestehende GeDefense-Mechanismen.
- **Verifikation:** Schema-/Store-Test; Cross-Site-Negativtest; Log- und Config-Scan auf Klartext-Secrets.
- **Testfälle:** `TestPrivacy_NoPayloadFieldsInStore`, `TestStore_CrossSiteQueryRejected`, `TestAuthz_CrossSiteAccessDenied`, `TestSecrets_NoPlaintextInConfigOrLogs`
- **Beweislücke:** Metadaten (IP/MAC) können personenbezogen sein; rechtliche Bewertung bleibt Betreiberaufgabe.

### S-10 · Zeitwahrheit und fail-safe Datenqualität
**Invariante:** Alle Zeitstempel intern UTC (`observed_at`, `received_at`, `source_ts` als Gerätezeit), lokale Anzeige nur in der UI (`Site.Timezone`). Unsichere Zeit wird markiert (`quality=clock_uncertain`), nicht still korrigiert. Fehlende/eingefrorene/unglaubwürdige Telemetrie wird **nie** als „Temperatur in Ordnung“ dargestellt.

- **Begründung:** Zeitmanipulation bricht Korrelation und Wartungsfenster (R-10); ein „grüner“ Zustand ohne Daten ist gefährlicher als ein sichtbarer blinder Fleck (R-04).
- **Durchsetzung:** E5: getrennte Zeitfelder + `Quality`-Werte (`stale`, `frozen`, `missing`, `clock_uncertain`) + `DataQualityPolicy.MaxClockSkewS`; UI-Zustandsmodell unterscheidet `ok`, `stale`, `missing`, `suspect`, `no_data`; niemals `ok` ohne aktuelle valide Messung.
- **Verifikation:** Zeit-Invarianten-Tests; UI-Zustands-Contract-Tests; Negativtest „Lücke wird nicht grün“.
- **Testfälle:** `TestTime_AllTimesPersistedUTC`, `TestTime_TimestampRegression_Flagged`, `TestUI_MissingTelemetryNotGreen`, `TestDetect_TelemetryGap_NotReportedAsOk`
- **Beweislücke:** Manipulation an der Quelle (Geräteuhr) ist ohne Referenz nicht immer erkennbar.

### S-11 · Read-only-Adapterisolierung und Fehlertoleranz
**Invariante:** Adapter sind isoliert; ein Parserfehler, Panic oder Protokollfehler beendet weder Core noch andere Adapter und erzeugt keine Wirkung auf Anlagen. Nicht unterstützte Nachrichten werden als Metrik/Parserfehler gezählt, nicht als Wahrheit interpretiert.

- **Begründung:** Baukonzept §6 Schritt 4; Fehler in einem Protokoll dürfen Grundschutz nicht verhindern.
- **Durchsetzung:** E4 (Prozess-/Goroutine-Isolation mit Recovery, bounded Queues, Deadlines); E2 (sichere Defaults, Start/Stop ohne Anlagenwirkung).
- **Verifikation:** Fehlerinjektion pro Adapter (Panic, Timeout, Riesen-Nachricht, kaputtes Frame); Health-Status; Core-Health bleibt grün.
- **Testfälle:** `TestAdapter_PanicIsContained`, `TestAdapter_MalformedFrameCountedAsMetric`, `TestCore_UnaffectedByAdapterCrash`, `TestAdapter_StartStopNoPlantEffect`
- **Beweislücke:** Speicher-/CPU-Druck auf dem Host kann bei extremen Lasten alle Prozesse beeinflussen; Budgets begrenzen, beseitigen das Risiko nicht.

### S-12 · Kein automatisches Zurückschreiben von Konfigurationen
**Invariante:** GeDefense stellt keine PLC-/Regler-Konfigurationen, Programme oder Firmware wieder her oder zurück. Recovery betrifft ausschließlich GeDefense-Komponenten (Update, Config-Backup, lokale DB, Rollback).

- **Begründung:** Baukonzept §5 Modul F, §6 Schritt 13.
- **Durchsetzung:** E1–E3 (kein Schreibpfad), Recovery-Modul nur auf GeDefense-Artefakte beschränkt; Import-/Restore-Pfad validiert Zieltyp (nur GeDefense-Config).
- **Verifikation:** Restore-Test mit falschem Zieltyp (muss abgelehnt werden); AST-Gate auf Fremdgerät-Restore-Symbole.
- **Testfälle:** `TestRecovery_OnlyGeDefenseArtifacts`, `TestSafety_NoPlantConfigRestore`, `TestUpdate_RollbackScopeGeDefenseOnly`
- **Beweislücke:** Betreiber kann außerhalb von GeDefense Gerätebackups einspielen — separater, dokumentierter Hersteller-/Betreiberprozess.

### S-13 · Menschliche Kontrolle sicherheitskritischer Reaktionen
**Invariante:** Sicherheitskritische Maßnahmen benötigen eine verantwortliche Person und einen freigegebenen Betriebsprozess. GeDefense empfiehlt, führt aber nicht aus (MVP: keine Ausführung).

- **Begründung:** Baukonzept §2.1 human-controlled response, §10 Betrieb.
- **Durchsetzung:** E5: `RecommendedChecks[]` statt Aktion; Incident-Workflow mit `assignee`, `status`, `audit_history`; keine Auto-Response im MVP.
- **Verifikation:** Test, dass Alerts keinen ausführenden Schritt besitzen; Incident-Workflow-Test (Zuweisung/Bestätigung/Abschluss mit Audit).
- **Testfälle:** `TestAlert_ContainsNoExecutableAction`, `TestIncident_RequiresAssigneeAndAudit`
- **Beweislücke:** Betreiber kann falsch entscheiden; GeDefense liefert Evidenz, keine Entscheidung.

---

## 2. Verbotene Fähigkeiten (Capability-Denylist)

| Fähigkeit | Warum verboten | Nachweis der Abwesenheit |
|---|---|---|
| Modbus-Write (FC 5, 6, 15, 16, 22, 23 senden) | S-01/S-02 | AST-Gate + Simulator-Frame-Log |
| BACnet `writeProperty`/`writePropertyMultiple`/`reinitializeDevice` senden | S-01/S-02 | AST-Gate + Frame-Log |
| OPC-UA `Write`/`Call` auf Steuer-Nodes | S-01/S-02 | Session-Read-only + Capability-Test |
| SNMP `SET` | S-01 | Read-only-Credential + Parser-Reject |
| MQTT-Publish auf Kommando-/Steuer-Topics | S-01 | Topic-Allowlist nur Ingest |
| Aktor-/Shutdown-API | S-02 | Symbol-/Callgraph-Gate |
| Raw-Socket-Versand, SYN-Scan, Fuzzing | S-03 | Netzwerk-Guard + Code-Scan |
| Login-/Auth-Tests, Brute-Force, UI-Crawling an Management-Oberflächen | S-03; kann Geräte sperren/alarmieren und ist kein Monitoring | AST-Gate auf Login-/HTTP-Client-Nutzung + Code-Review |
| Automatisches Blocken/Isolieren von OT-Zielen | S-05 | Callgraph-Gate „Alert → Netzwerkaktion“ |
| PLC-Konfigurations-Restore | S-12 | Zieltyp-Validierung + AST-Gate |
| Payload-/PII-Persistenz (Default) | S-09 | Schema-/Store-Test |

**Regel für Ausnahmen:** Jede künftige Erweiterung (z. B. Response in 0.2+) benötigt ein ADR mit Bedrohungsanalyse, Freigabe durch technischen Betreiberverantwortlichen, reversiblen Mechanismus, Audit und einen Test, der beweist, dass OT-Prozesskommunikation nicht betroffen ist. Ohne ADR bleibt die Fähigkeit verboten.

---

## 3. Testmatrix (Safety-Abnahme)

| Invariante | Testfälle | Testart | Blockiert Release |
|---|---|---|---|
| S-01 | `TestSafety_AdapterSurfaceHasNoWriteMethods`, `TestSafety_ForbiddenWriteSymbols_ASTGate`, `TestSafety_ConfigRejectsWritableMode`, `TestSim_AdapterEmitsOnlyReadFrames` | statisch + Integration | **ja (P0)** |
| S-02 | `TestSafety_NoActuatorSymbolsInCode`, `TestAlert_DoesNotTriggerPlantAction` | statisch + Integration | **ja (P0)** |
| S-03 | `TestDiscovery_PassiveOnly_NoActiveProbe`, `TestNetx_DeniesNichtAllowlisteteVerbindung`, `TestSafety_NoRawSocketSend` | Integration | **ja (P0)** |
| S-04 | `TestFailSafe_AgentStop_NoImpactOnSimulatedPlant`, `TestTopology_NoInlinePlacement` | Integration | **ja (P0)** |
| S-05 | `TestSafety_NoAutoIsolationOnAlert`, `TestResponse_TargetMustBeManagementPath` | statisch + Negativ | **ja (P0)** |
| S-06 | `TestAlert_ThreeSectionContract`, `TestUI_RendersThreeSectionsSeparated` | Unit + UI-Contract | **ja (P0)** |
| S-07 | `TestCopy_ForbiddenClaims`, `TestDocs_NoCertificationClaim` | CI-Gate | **ja (P0)** |
| S-08 | `TestPolicy_NoDefaultTemperatureThresholds`, `TestDetect_RequiresVersionedPolicy` | statisch + Unit | ja (P0) |
| S-09 | `TestStore_CrossSiteQueryRejected`, `TestAuthz_CrossSiteAccessDenied`, `TestSecrets_NoPlaintextInConfigOrLogs` | Integration | **ja (P0)** |
| S-10 | `TestTime_AllTimesPersistedUTC`, `TestUI_MissingTelemetryNotGreen` | Unit + UI | **ja (P0)** |
| S-11 | `TestAdapter_PanicIsContained`, `TestCore_UnaffectedByAdapterCrash` | Fehlerinjektion | ja (P0) |
| S-12 | `TestRecovery_OnlyGeDefenseArtifacts`, `TestSafety_NoPlantConfigRestore` | Unit + statisch | ja (P0) |
| S-13 | `TestAlert_ContainsNoExecutableAction`, `TestIncident_RequiresAssigneeAndAudit` | Unit | nein (P1) |

**Abnahmeregel:** Ein Testfall gilt als bestanden nur mit ausgeführtem Lauf, Exitcode 0 und dokumentiertem Ergebnis (vgl. `MVP scope`). „Code vorhanden“ ist kein Nachweis.

---

## 4. Was diese Invarianten nicht leisten

- Sie schützen **nicht** vor einem Angreifer mit Codeausführung/Root auf dem GeDefense-Host (nur Erkennung/Erschwerung, vgl. R-05).
- Sie schützen **nicht** vor physischer Manipulation, Sensor-Drift oder Anlagenfehlern ohne Netzspur.
- Sie ersetzen **keine** Netzwerksegmentierung des Betreibers (nur Beobachtung von Fehlkonfiguration, S-03/R-07).
- Sie garantieren **keine** Vollständigkeit der Erkennung; versprochen ist Nachvollziehbarkeit und definierte Degradation.
- Sie sind **keine** Compliance-Aussage (S-07); regulatorische Bewertung erfolgt durch Betreiber/Rechtsabteilung.

---

## 5. Durchsetzung im Repo (Soll-Zuordnung, Stand vor Implementierung)

| Paket (Retail `src/retail/internal/…`) | Rolle für Safety | Prüfpunkt |
|---|---|---|
| `ports` | E1: read-only Collector-Interface | keine Write-Methoden |
| `adapters/{modbus,bacnet,mqtt,snmp}` | nur Parsing + Lesen; Write-Frames nur **erkennen**, nie senden | AST-Gate, Frame-Log |
| `guard` | E3: Sicherheits-/Fähigkeitsprüfung beim Start | keine Raw-Sockets, keine aktiven Scans |
| `netx` | E3: Allowlist, Rate-Budget, kein Routing | Deny-Test |
| `policy` | E2/E5: versionierte, betreiberverantwortete Grenzwerte | Pflichtfelder, Freigabe |
| `detect` | E5: beobachtete Schreib-FCs/Anomalien → Evidenz, keine Aktion | Callgraph-Gate |
| `alert` | E5: Drei-Abschnitt-Vertrag | Schema-Test |
| `store` | E5/E6: `site_id`-Scoping, Retention, kein Payload | Cross-Site-Test |
| `audit` | E5: Akteur/Zeit/Begründung/Diff, manipulationserschwerend | Audit-Test |
| `webui` | E5: drei Abschnitte, Datenqualitätszustände | UI-Contract-Test |
| `version`, `config` | E2/E6: sichere Defaults, `ReadOnly` erzwungen | Config-Test |

**Hinweis:** Diese Zuordnung ist ein Umsetzungsvorschlag. Bindend ist die tatsächliche Package-Struktur des Go-Moduls (`src/retail`); Abweichungen sind als Änderungsvorschlag an die Architektur zu melden (vgl. `data model` §10).
