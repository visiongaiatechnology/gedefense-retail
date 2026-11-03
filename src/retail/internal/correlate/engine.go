package correlate

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

const (
	// cacheWindow bounds the in-memory alert history. It is larger than the
	// chain window so a chain can still be evaluated across slightly delayed
	// pipeline batches.
	cacheWindow = 60 * time.Minute

	// maxRecordsPerSite bounds memory per site; the oldest alerts are dropped.
	maxRecordsPerSite = 512

	// incidentDedupWindow implements the contract rule: one incident per
	// site + chain + 24 h.
	incidentDedupWindow = 24 * time.Hour

	// maxFacts bounds the observed-fact list of an incident.
	maxFacts = 8
)

// record is one recent alert in the in-memory correlation window.
type record struct {
	alert domain.Alert
	at    time.Time
}

// Engine correlates independent rule alerts into documented incidents. It keeps
// a bounded, mutex-protected window of recent alerts; the World owns the durable
// state (incidents, assets, sensors, windows).
type Engine struct {
	world  World
	clock  ports.Clock
	mu     sync.Mutex
	recent map[domain.SiteID][]record
	chains []chainDef
}

// worldClock is the fallback clock when no clock is injected. It delegates to the
// World clock so correlation never uses wall time implicitly.
type worldClock struct {
	world World
}

func (c worldClock) Now() time.Time {
	if c.world == nil {
		return time.Time{}
	}
	return c.world.Now()
}

// NewEngine constructs the correlation engine. A nil clock falls back to the
// World clock; a nil World makes the engine inert instead of panicking.
func NewEngine(w World, clock ports.Clock) *Engine {
	engine := &Engine{
		world:  w,
		recent: make(map[domain.SiteID][]record),
		chains: chains(),
	}
	if clock != nil {
		engine.clock = clock
	} else {
		engine.clock = worldClock{world: w}
	}
	return engine
}

func (e *Engine) now() time.Time {
	if e == nil || e.clock == nil {
		return time.Time{}
	}
	return e.clock.Now().UTC()
}

// Observe merges the given alerts into the correlation window and returns alert
// updates (escalation + correlation summary + incident link) and incidents
// (created or updated, deduplicated per site + chain + 24 h).
func (e *Engine) Observe(ctx context.Context, alerts []domain.Alert) (updates []domain.Alert, incidents []domain.Incident) {
	if e == nil || e.world == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, nil
	}
	now := e.now()
	if now.IsZero() {
		return nil, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	sites := e.ingest(alerts, now)
	if len(sites) == 0 {
		return nil, nil
	}
	for _, site := range sites {
		if err := ctx.Err(); err != nil {
			break
		}
		for _, chain := range e.chains {
			hits := matchChain(e.recent[site], chain, now)
			if len(hits) < chain.minIndicators {
				continue
			}
			chainUpdates, incident, ok := e.correlateChain(site, chain, hits, now)
			if !ok {
				continue
			}
			updates = append(updates, chainUpdates...)
			incidents = append(incidents, incident)
		}
	}
	updates = dedupeUpdates(updates)
	sort.Slice(updates, func(i, j int) bool {
		if updates[i].DedupKey != updates[j].DedupKey {
			return updates[i].DedupKey < updates[j].DedupKey
		}
		return updates[i].AlertID < updates[j].AlertID
	})
	sort.Slice(incidents, func(i, j int) bool { return incidents[i].IncidentID < incidents[j].IncidentID })
	return updates, incidents
}

// ingest merges the incoming alerts into the bounded window and returns the
// sorted list of touched sites.
func (e *Engine) ingest(alerts []domain.Alert, now time.Time) []domain.SiteID {
	touched := make(map[domain.SiteID]struct{}, 2)
	for _, alert := range alerts {
		if alert.SiteID == "" || alert.RuleID == "" {
			continue
		}
		at := alert.FirstSeenAt
		if at.IsZero() {
			at = alert.LastSeenAt
		}
		if at.IsZero() {
			at = now
		}
		at = at.UTC()
		key := recordKey(alert)
		if key == "" {
			continue
		}
		records := e.recent[alert.SiteID]
		replaced := false
		for i := range records {
			if recordKey(records[i].alert) != key {
				continue
			}
			records[i].alert = alert
			if at.Before(records[i].at) {
				records[i].at = at // keep the first observation as indicator time
			}
			replaced = true
			break
		}
		if !replaced {
			records = append(records, record{alert: alert, at: at})
		}
		e.recent[alert.SiteID] = records
		touched[alert.SiteID] = struct{}{}
	}
	for site := range touched {
		e.recent[site] = pruneRecords(e.recent[site], now)
	}
	sites := make([]domain.SiteID, 0, len(touched))
	for site := range touched {
		sites = append(sites, site)
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i] < sites[j] })
	return sites
}

func recordKey(alert domain.Alert) string {
	if alert.DedupKey != "" {
		return alert.DedupKey
	}
	return string(alert.AlertID)
}

// pruneRecords removes records outside the cache window, sorts them by indicator
// time and enforces the per-site bound.
func pruneRecords(records []record, now time.Time) []record {
	cutoff := now.Add(-cacheWindow)
	out := records[:0]
	for _, entry := range records {
		if entry.at.IsZero() || entry.at.Before(cutoff) {
			continue
		}
		out = append(out, entry)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].at.Equal(out[j].at) {
			return out[i].at.Before(out[j].at)
		}
		return out[i].alert.AlertID < out[j].alert.AlertID
	})
	if len(out) > maxRecordsPerSite {
		out = out[len(out)-maxRecordsPerSite:]
	}
	return out
}

// correlateChain escalates the matched alerts, links them to the incident and
// returns the changed alerts plus the created/updated incident.
func (e *Engine) correlateChain(site domain.SiteID, chain chainDef, hits []hit, now time.Time) ([]domain.Alert, domain.Incident, bool) {
	severity := chain.severity
	if !severity.Valid() {
		severity = domain.SeverityHigh
	}
	facts := chainFacts(e.world, site, hits)
	incident := e.resolveIncident(site, chain, hits, facts, severity, now)
	if err := incident.Validate(); err != nil {
		return nil, domain.Incident{}, false
	}
	correlation := &domain.CorrelationSummary{
		ChainID:                 chain.id,
		ObservedFacts:           append([]string(nil), facts...),
		Hypothesis:              chain.hypothesis,
		AlternativeExplanations: append([]string(nil), chain.alternatives...),
		RecommendedChecks:       append([]string(nil), chain.checks...),
		Indicators:              hitIndicatorKeys(hits),
	}
	updates := make([]domain.Alert, 0, len(hits))
	for _, match := range hits {
		alert := match.alert
		changed := false
		if escalated := escalateSeverity(alert.Severity, severity); escalated != alert.Severity {
			alert.Severity = escalated
			changed = true
		}
		if alert.IncidentID != incident.IncidentID {
			alert.IncidentID = incident.IncidentID
			changed = true
		}
		if !sameCorrelation(alert.Correlation, correlation) {
			alert.Correlation = correlation
			changed = true
		}
		if !changed {
			continue
		}
		alert.UpdatedAt = now
		updates = append(updates, alert)
		e.cacheUpdate(site, alert)
	}
	return updates, incident, true
}

// cacheUpdate keeps the correlation window in sync with returned alert updates so
// a repeated evaluation does not re-emit the same update forever.
func (e *Engine) cacheUpdate(site domain.SiteID, alert domain.Alert) {
	records := e.recent[site]
	key := recordKey(alert)
	for i := range records {
		if recordKey(records[i].alert) != key {
			continue
		}
		records[i].alert = alert
		return
	}
}

func sameCorrelation(a, b *domain.CorrelationSummary) bool {
	if a == nil || b == nil {
		return false
	}
	if a.ChainID != b.ChainID || a.Hypothesis != b.Hypothesis {
		return false
	}
	if len(a.ObservedFacts) != len(b.ObservedFacts) || len(a.RecommendedChecks) != len(b.RecommendedChecks) {
		return false
	}
	if len(a.AlternativeExplanations) != len(b.AlternativeExplanations) || len(a.Indicators) != len(b.Indicators) {
		return false
	}
	for i := range a.ObservedFacts {
		if a.ObservedFacts[i] != b.ObservedFacts[i] {
			return false
		}
	}
	for i := range a.Indicators {
		if a.Indicators[i] != b.Indicators[i] {
			return false
		}
	}
	return true
}

func dedupeUpdates(updates []domain.Alert) []domain.Alert {
	if len(updates) < 2 {
		return updates
	}
	index := make(map[string]int, len(updates))
	out := make([]domain.Alert, 0, len(updates))
	for _, alert := range updates {
		key := recordKey(alert)
		if position, ok := index[key]; ok {
			out[position] = alert
			continue
		}
		index[key] = len(out)
		out = append(out, alert)
	}
	return out
}

// escalateSeverity raises a severity but never lowers it (operator workflow rule).
func escalateSeverity(current, target domain.Severity) domain.Severity {
	if target.Rank() > current.Rank() {
		return target
	}
	return current
}
