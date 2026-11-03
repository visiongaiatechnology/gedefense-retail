package correlate

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

const (
	// maxIncidentAlerts bounds the alert reference list of one incident.
	maxIncidentAlerts = 64

	// maxIncidentRefs bounds zone/asset reference lists.
	maxIncidentRefs = 32

	// maxIncidentSummaryRunes bounds the incident summary text.
	maxIncidentSummaryRunes = 2000
)

// resolveIncident creates a new incident or merges into an existing open incident
// of the same site + chain that is younger than the dedup window (24 h).
func (e *Engine) resolveIncident(site domain.SiteID, chain chainDef, hits []hit, facts []string, severity domain.Severity, now time.Time) domain.Incident {
	fresh := buildIncident(e.world, site, chain, hits, facts, severity, now)
	if existing, ok := e.findOpenIncident(site, chain.id, now); ok {
		return mergeIncident(existing, fresh, now)
	}
	return fresh
}

// findOpenIncident returns the most recent open/investigating/contained incident
// of the chain that is inside the 24 h dedup window. Closed cases are not
// reopened: a genuine recurrence creates a new case.
func (e *Engine) findOpenIncident(site domain.SiteID, chainID string, now time.Time) (domain.Incident, bool) {
	var best domain.Incident
	found := false
	for _, incident := range e.world.Incidents(site) {
		if incident.Correlation == nil || incident.Correlation.ChainID != chainID {
			continue
		}
		switch incident.Status {
		case domain.IncidentOpen, domain.IncidentInvestigating, domain.IncidentContained:
		default:
			continue
		}
		if incident.LastSeenAt.IsZero() || now.Sub(incident.LastSeenAt) > incidentDedupWindow {
			continue
		}
		if !found || incident.LastSeenAt.After(best.LastSeenAt) {
			best = incident
			found = true
		}
	}
	return best, found
}

func buildIncident(w World, site domain.SiteID, chain chainDef, hits []hit, facts []string, severity domain.Severity, now time.Time) domain.Incident {
	firstSeen, lastSeen := hitRange(hits)
	if firstSeen.IsZero() {
		firstSeen = now
	}
	if lastSeen.IsZero() {
		lastSeen = firstSeen
	}
	zoneIDs, assetIDs := hitContext(w, site, hits)
	correlation := &domain.CorrelationSummary{
		ChainID:                 chain.id,
		ObservedFacts:           append([]string(nil), facts...),
		Hypothesis:              chain.hypothesis,
		AlternativeExplanations: append([]string(nil), chain.alternatives...),
		RecommendedChecks:       append([]string(nil), chain.checks...),
		Indicators:              hitIndicatorKeys(hits),
	}
	return domain.Incident{
		IncidentID:  newIncidentID(),
		SiteID:      site,
		Title:       fmt.Sprintf("%s — Filiale %s", chain.title, site),
		Severity:    severity,
		Status:      domain.IncidentOpen,
		AlertIDs:    unionStrings(nil, hitAlertIDs(hits), maxIncidentAlerts),
		ZoneIDs:     zoneIDs,
		AssetIDs:    assetIDs,
		FirstSeenAt: firstSeen,
		LastSeenAt:  lastSeen,
		Summary:     incidentSummary(chain, facts),
		Correlation: correlation,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// mergeIncident folds a fresh correlation result into an existing open incident.
// It never lowers the severity, never shrinks the timeline and never changes the
// operator-owned status.
func mergeIncident(existing, fresh domain.Incident, now time.Time) domain.Incident {
	merged := existing
	merged.Severity = escalateSeverity(existing.Severity, fresh.Severity)
	if !fresh.FirstSeenAt.IsZero() && (merged.FirstSeenAt.IsZero() || fresh.FirstSeenAt.Before(merged.FirstSeenAt)) {
		merged.FirstSeenAt = fresh.FirstSeenAt
	}
	if fresh.LastSeenAt.After(merged.LastSeenAt) {
		merged.LastSeenAt = fresh.LastSeenAt
	}
	merged.AlertIDs = unionStrings(existing.AlertIDs, fresh.AlertIDs, maxIncidentAlerts)
	merged.ZoneIDs = unionStrings(existing.ZoneIDs, fresh.ZoneIDs, maxIncidentRefs)
	merged.AssetIDs = unionStrings(existing.AssetIDs, fresh.AssetIDs, maxIncidentRefs)
	merged.Summary = fresh.Summary
	merged.Correlation = fresh.Correlation
	merged.UpdatedAt = now
	return merged
}

// incidentSummary renders the operator text: facts, hypothesis, alternative
// explanations and recommended checks stay explicitly separated.
func incidentSummary(chain chainDef, facts []string) string {
	var b strings.Builder
	b.WriteString(chain.name)
	b.WriteString(". Beobachtete Fakten: ")
	for i, fact := range facts {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(strings.TrimSuffix(strings.TrimSpace(fact), "."))
	}
	b.WriteString(". Hypothese: ")
	b.WriteString(strings.TrimSuffix(strings.TrimSpace(chain.hypothesis), "."))
	if len(chain.alternatives) > 0 {
		b.WriteString(". Alternativerklärungen: ")
		b.WriteString(strings.Join(chain.alternatives, "; "))
	}
	if len(chain.checks) > 0 {
		b.WriteString(". Empfohlene Prüfungen: ")
		b.WriteString(strings.Join(chain.checks, "; "))
	}
	b.WriteString(". GeDefense führt keine automatische Anlagenänderung aus.")
	return truncateText(b.String(), maxIncidentSummaryRunes)
}

// chainFacts derives the observed facts from the matched alerts and the World
// context. Facts are facts: they quote rule, title and time, not interpretations.
func chainFacts(w World, site domain.SiteID, hits []hit) []string {
	facts := make([]string, 0, maxFacts)
	for _, match := range hits {
		if len(facts) >= maxFacts-2 {
			break
		}
		facts = append(facts, fmt.Sprintf("%s: %s (Regel %s, %s)",
			match.indicator.label, match.alert.Title, match.alert.RuleID, match.at.UTC().Format(time.RFC3339)))
	}
	if len(hits) > 0 {
		at := hits[0].at
		windows := w.WindowsAt(site, at)
		if len(windows) == 0 {
			facts = append(facts, fmt.Sprintf("Zum Zeitpunkt %s war kein Wartungsfenster aktiv.", at.UTC().Format(time.RFC3339)))
		} else {
			ids := make([]string, 0, len(windows))
			for _, window := range windows {
				ids = append(ids, string(window.WindowID))
			}
			sort.Strings(ids)
			facts = append(facts, fmt.Sprintf("Aktive Wartungsfenster zum Zeitpunkt %s: %s.", at.UTC().Format(time.RFC3339), strings.Join(ids, ", ")))
		}
	}
	for _, assetID := range hitAssetIDs(hits) {
		if asset, ok := w.Asset(assetID); ok {
			facts = append(facts, fmt.Sprintf("Betroffenes Asset %s (%s), Kritikalität %s.", asset.AssetID, asset.Type, asset.Criticality))
			break
		}
	}
	if len(facts) > maxFacts {
		facts = facts[:maxFacts]
	}
	return facts
}

// hitContext collects zone/asset references from the alerts and resolves sensor
// references through the World so the incident workspace has the full context.
func hitContext(w World, site domain.SiteID, hits []hit) ([]domain.ZoneID, []domain.AssetID) {
	sensorIndex := make(map[domain.SensorID]domain.Sensor, 8)
	for _, sensor := range w.Sensors(site) {
		sensorIndex[sensor.SensorID] = sensor
	}
	zones := make([]domain.ZoneID, 0, len(hits))
	assets := make([]domain.AssetID, 0, len(hits))
	for _, match := range hits {
		zones = append(zones, match.alert.ZoneIDs...)
		assets = append(assets, match.alert.AssetIDs...)
		for _, sensorID := range match.alert.SensorIDs {
			sensor, ok := sensorIndex[sensorID]
			if !ok {
				continue
			}
			if sensor.ZoneID != "" {
				zones = append(zones, sensor.ZoneID)
			}
			if sensor.AssetID != "" {
				assets = append(assets, sensor.AssetID)
			}
		}
	}
	return unionStrings(nil, zones, maxIncidentRefs), unionStrings(nil, assets, maxIncidentRefs)
}

func hitRange(hits []hit) (first, last time.Time) {
	for _, match := range hits {
		at := match.at
		if at.IsZero() {
			continue
		}
		if first.IsZero() || at.Before(first) {
			first = at
		}
		if last.IsZero() || at.After(last) {
			last = at
		}
	}
	return first, last
}

// unionStrings merges two slices, removes empty values and duplicates, sorts the
// result (deterministic) and applies an optional bound.
func unionStrings[T ~string](a, b []T, limit int) []T {
	seen := make(map[T]struct{}, len(a)+len(b))
	out := make([]T, 0, len(a)+len(b))
	for _, group := range [][]T{a, b} {
		for _, value := range group {
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func truncateText(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes]) + "…"
}

var incidentFallbackSeq uint64

// newIncidentID returns an unpredictable incident identifier (contract:
// crypto/rand, 16 bytes hex, prefix "inc_"). The counter fallback keeps the
// library panic-free if the OS entropy source is unavailable; it is unique per
// process but documented as the degraded path.
func newIncidentID() domain.IncidentID {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return domain.IncidentID("inc_" + hex.EncodeToString(buf[:]))
	}
	seq := atomic.AddUint64(&incidentFallbackSeq, 1)
	return domain.IncidentID(fmt.Sprintf("inc_%032x", seq))
}
