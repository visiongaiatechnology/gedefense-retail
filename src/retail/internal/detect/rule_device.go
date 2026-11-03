package detect

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// newAssetRule implements retail.device.new-asset: an asset seen for the first
// time inside the inventory window. Passive observation never claims identity it
// cannot prove.
type newAssetRule struct{ baseRule }

func newNewAssetRule() *newAssetRule {
	return &newAssetRule{baseRule: baseFor(rules.IDDeviceNewAsset)}
}

func (r *newAssetRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if ev.Kind != domain.EventAssetSeen || ev.AssetID == "" {
		return nil
	}
	since, _ := lookbackSince(w, inventoryLookback)
	seenEvents := w.Events(ports.EventQuery{
		SiteID: ev.SiteID,
		Kind:   domain.EventAssetSeen,
		Since:  rfc3339(since),
		Limit:  maxQueryLimit,
	})
	for _, other := range seenEvents {
		if other.EventID == ev.EventID {
			continue
		}
		if other.AssetID == ev.AssetID {
			return nil // already observed before -> not new
		}
	}

	asset, assetKnown := w.Asset(ev.AssetID)
	severity := domain.SeverityMedium
	confidence := 0.60
	if assetKnown {
		if assetCritical(asset) {
			severity = domain.SeverityHigh
			confidence += 0.10
		}
		if assetIsOTController(asset) {
			severity = domain.SeverityHigh
			confidence += 0.10
		}
	}
	if otProtocolName(ev.Protocol) {
		severity = domain.SeverityHigh
		confidence += 0.05
	}
	if zoneKind(w, ev.SiteID, ev.ZoneID) == domain.ZoneExternalMaintenance {
		severity = domain.SeverityHigh
	}
	at := trustedTime(ev)

	draft := &alertDraft{
		spec:         r.spec,
		site:         ev.SiteID,
		severity:     severity,
		confidence:   clampConfidence(confidence, 0.5, 0.8),
		dedupKey:     rules.DedupKey(rules.IDDeviceNewAsset, string(ev.SiteID), string(ev.AssetID)),
		title:        "Neues Asset im Filialnetz",
		hypothesis:   "Ein neu beobachtetes Gerät kann eine Neuinstallation, ein nicht inventarisiertes Bestandsgerät oder ein unautorisierter Teilnehmer am OT-/Retail-Netz sein; ein Angriff ist nicht bewiesen.",
		alternatives: []string{"Neuinstallation oder Inbetriebnahme", "Nicht inventarisiertes Bestandsgerät (Erstaufnahme)", "Dienstleistergerät im Rahmen einer Wartung", "NAT/Routing-Artefakt verändert die beobachtete Identität"},
		checks:       []string{"Asset in das Inventar aufnehmen und klassifizieren", "Betreiber/Dienstleister zur Herkunft des Geräts befragen", "Netzwerksegmentierung und offene Ports prüfen"},
		at:           at,
	}
	if ev.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{ev.ZoneID}
	}
	draft.assetIDs = []domain.AssetID{ev.AssetID}
	if assetKnown {
		draft.addFact(fmt.Sprintf("Erstmalige Beobachtung des Assets %s (%s, Vendor %q, Kritikalität %s) um %s.",
			asset.AssetID, asset.Type, asset.Vendor, asset.Criticality, at.Format(time.RFC3339)))
		draft.addFact(fmt.Sprintf("Keine frühere asset_seen-Beobachtung dieses Assets innerhalb von %s.", humanDuration(inventoryLookback)))
		draft.addEvidence("asset", string(asset.AssetID), fmt.Sprintf("Asset %s (%s)", asset.Name, asset.Type), asset.Source,
			fmt.Sprintf("type=%s confidence=%s criticality=%s", asset.Type, formatFloat(asset.Confidence, 2), asset.Criticality), at, clampConfidence(asset.Confidence, 0, 1))
	} else {
		draft.addFact(fmt.Sprintf("Erstmalige Beobachtung des Assets %s um %s; es liegt noch kein klassifizierter Asset-Datensatz vor.", ev.AssetID, at.Format(time.RFC3339)))
	}
	if ev.Device != nil {
		draft.addFact(fmt.Sprintf("Beobachtete Netzwerkkennung: IP %q, MAC %q, Hostname %q, Vendor %q.", ev.Device.IP, ev.Device.MAC, ev.Device.Hostname, ev.Device.Vendor))
	}
	if ev.Protocol != "" {
		draft.addFact(fmt.Sprintf("Beobachtetes Protokoll: %q.", ev.Protocol))
	}
	draft.addEvidence("event", string(ev.EventID), "Erstmalige Asset-Beobachtung", ev.Source,
		fmt.Sprintf("asset=%s protocol=%s", ev.AssetID, ev.Protocol), at, 0.8)
	return []domain.Alert{draft.build()}
}

// assetLifecycleRule implements retail.asset.lifecycle-exposed as an advisory
// tick rule: critical refrigeration supervisors at end-of-life, and management
// interfaces reachable from outside the management zone. Neither is an attack
// claim.
type assetLifecycleRule struct{ baseRule }

func newAssetLifecycleRule() *assetLifecycleRule {
	return &assetLifecycleRule{baseRule: baseFor(rules.IDAssetLifecycleExposed)}
}

func (r *assetLifecycleRule) OnEvent(ctx context.Context, ev domain.Event, w World) []domain.Alert {
	return nil // advisory state rule, evaluated in the tick
}

func (r *assetLifecycleRule) OnTick(ctx context.Context, w World) []domain.Alert {
	if err := ctx.Err(); err != nil {
		return nil
	}
	now := w.Now()
	if now.IsZero() {
		return nil
	}
	out := make([]domain.Alert, 0, 8)
	since := now.Add(-eventLookback)
	for _, site := range w.Sites() {
		if err := ctx.Err(); err != nil {
			break
		}
		assets := w.Assets(site.SiteID)
		if len(assets) == 0 {
			continue
		}
		var flows []domain.Event
		for _, asset := range assets {
			if asset.Retired || !supervisorAsset(asset) || !assetCritical(asset) {
				continue
			}
			if asset.Lifecycle == domain.LifecycleEOL {
				out = append(out, buildLifecycleAlert(r.spec, site.SiteID, asset, now))
			}
			if asset.ManagementInterface {
				if flows == nil {
					flows = w.Events(ports.EventQuery{
						SiteID: site.SiteID,
						Kind:   domain.EventFlow,
						Since:  rfc3339(since),
						Limit:  maxQueryLimit,
					})
				}
				if observation, ok := managementExposure(w, site.SiteID, asset, flows); ok {
					out = append(out, buildExposureAlert(r.spec, site.SiteID, asset, observation, now))
				}
			}
			if len(out) >= maxTickAlerts {
				return out
			}
		}
	}
	return out
}

// supervisorAsset restricts the advisory to refrigeration supervisors and BMS
// units, matching the operator-facing criticality of those asset types.
func supervisorAsset(asset domain.Asset) bool {
	switch asset.Type {
	case domain.AssetRefrigerationController, domain.AssetBMS:
		return true
	default:
		return false
	}
}

// exposureObservation is one management-UI access from a non-management zone.
type exposureObservation struct {
	sourceAsset domain.Asset
	sourceKnown bool
	zoneKind    domain.ZoneKind
	port        int
	at          time.Time
}

// managementExposure looks for a management-UI flow from an asset outside the
// management zone. Unknown sources are skipped: without a zone the exposure is
// not provable (the management-UI access rule still evaluates the flow itself).
func managementExposure(w World, site domain.SiteID, target domain.Asset, flows []domain.Event) (exposureObservation, bool) {
	targetIPs := make(map[string]struct{}, len(target.NetworkIDs))
	for _, id := range target.NetworkIDs {
		if id.Kind == domain.NetIDIP && strings.TrimSpace(id.Value) != "" {
			targetIPs[strings.TrimSpace(id.Value)] = struct{}{}
		}
	}
	if len(targetIPs) == 0 {
		return exposureObservation{}, false
	}
	for _, flow := range flows {
		if flow.Flow == nil {
			continue
		}
		if _, ok := targetIPs[strings.TrimSpace(flow.Flow.DstIP)]; !ok {
			continue
		}
		if !isManagementUIPort(flow.Flow.DstPort) {
			continue
		}
		source, ok := assetByIP(w, site, flow.Flow.SrcIP)
		if !ok || source.AssetID == target.AssetID {
			continue
		}
		kind := zoneKind(w, site, source.ZoneID)
		switch kind {
		case domain.ZoneManagement, domain.ZoneExternalMaintenance:
			continue // intended paths
		}
		return exposureObservation{
			sourceAsset: source,
			sourceKnown: true,
			zoneKind:    kind,
			port:        flow.Flow.DstPort,
			at:          trustedTime(flow),
		}, true
	}
	return exposureObservation{}, false
}

func buildLifecycleAlert(spec rules.Spec, site domain.SiteID, asset domain.Asset, now time.Time) domain.Alert {
	source := asset.LifecycleSource
	if source == "" {
		source = "asset-datensatz"
	}
	draft := &alertDraft{
		spec:         spec,
		site:         site,
		severity:     domain.SeverityLow,
		confidence:   0.90,
		dedupKey:     rules.DedupKey(rules.IDAssetLifecycleExposed, string(site), string(asset.AssetID), "eol"),
		title:        "Kritischer Kälte-Regler am Lebenszyklusende",
		hypothesis:   "End-of-Life kann fehlende Hersteller-Sicherheitsupdates bedeuten – ein Risikofaktor, kein Angriffsnachweis. Der tatsächliche Patch-/Firmware-Stand ist damit nicht bewiesen.",
		alternatives: []string{"Katalogstand veraltet", "Ersatzbeschaffung bereits in Umsetzung", "Lebenszyklus manuell falsch gepflegt", "Kompatibilitätsbetrieb mit Herstellerfreigabe"},
		checks:       []string{"Ersatz-/Update-Plan und Herstellerfreigabe mit Betreiber prüfen", "Kompensierende Maßnahmen (Segmentierung, Monitoring) prüfen", "Keine automatische Firmware-Aktualisierung durch GeDefense"},
		at:           now,
	}
	if asset.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{asset.ZoneID}
	}
	draft.assetIDs = []domain.AssetID{asset.AssetID}
	draft.addFact(fmt.Sprintf("Asset %s (%s, Vendor %q) mit Kritikalität %s steht laut Datensatz am Lebenszyklusende (eol, Quelle %q).",
		asset.AssetID, asset.Type, asset.Vendor, asset.Criticality, source))
	draft.addEvidence("asset", string(asset.AssetID), fmt.Sprintf("Lebenszyklusstatus eol für %s", asset.AssetID), source,
		fmt.Sprintf("lifecycle=%s source=%s", domain.LifecycleEOL, source), now, 0.9)
	return draft.build()
}

func buildExposureAlert(spec rules.Spec, site domain.SiteID, asset domain.Asset, observation exposureObservation, now time.Time) domain.Alert {
	at := observation.at
	if at.IsZero() {
		at = now
	}
	zoneLabelText := string(observation.zoneKind)
	if observation.zoneKind == "" || observation.zoneKind == domain.ZoneUnknown {
		zoneLabelText = "unbekannte Zone"
	}
	draft := &alertDraft{
		spec:         spec,
		site:         site,
		severity:     domain.SeverityMedium,
		confidence:   0.60,
		dedupKey:     rules.DedupKey(rules.IDAssetLifecycleExposed, string(site), string(asset.AssetID), "management-ui-exposed"),
		title:        "Management-Oberfläche aus anderer Zone erreichbar",
		hypothesis:   "Die Erreichbarkeit der Management-Oberfläche außerhalb der Management-Zone vergrößert die Angriffsfläche (dokumentierter Angriffsweg über Kälte-Supervisor-Web-UIs). Eine Kompromittierung ist dadurch nicht bewiesen.",
		alternatives: []string{"Dienstleisterzugriff außerhalb der vorgesehenen Zone", "Betreiber-Monitoring-/Management-System mit falschem Pfad", "Unvollständige Netzwerksegmentierung", "NAT/Proxy verfälscht die beobachtete Quelladresse"},
		checks:       []string{"Netzwerksegmentierung und Firewall-Regeln prüfen", "Zugriffsquelle und Zweck verifizieren", "Management-Zugang nach Freigabe auf dedizierten Management-Pfad beschränken"},
		at:           now,
	}
	if asset.ZoneID != "" {
		draft.zoneIDs = []domain.ZoneID{asset.ZoneID}
	}
	draft.assetIDs = []domain.AssetID{asset.AssetID}
	draft.addFact(fmt.Sprintf("Management-Oberfläche von %s wurde aus Zone %s durch Asset %s (%s) auf Port %d kontaktiert (Beobachtung %s).",
		asset.AssetID, zoneLabelText, observation.sourceAsset.AssetID, observation.sourceAsset.Type, observation.port, at.UTC().Format(time.RFC3339)))
	draft.addEvidence("flow", "", fmt.Sprintf("Management-UI-Zugriff auf %s aus Zone %s", asset.AssetID, zoneLabelText), "detect:flow",
		fmt.Sprintf("source=%s port=%d", observation.sourceAsset.AssetID, observation.port), at, 0.7)
	draft.addEvidence("asset", string(asset.AssetID), fmt.Sprintf("Zielasset %s (%s), Management-Interface", asset.Name, asset.Type), asset.Source,
		fmt.Sprintf("management_interface=true criticality=%s", asset.Criticality), now, clampConfidence(asset.Confidence, 0, 1))
	return draft.build()
}
