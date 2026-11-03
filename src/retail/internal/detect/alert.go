package detect

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// alertDraft accumulates everything a rule observed for one alert. The draft is
// the only place where the fact/hypothesis/check separation is assembled, so
// every alert – rule-level and correlated – has the same structure.
type alertDraft struct {
	spec         rules.Spec
	site         domain.SiteID
	zoneIDs      []domain.ZoneID
	assetIDs     []domain.AssetID
	sensorIDs    []domain.SensorID
	severity     domain.Severity
	confidence   float64
	dedupKey     string
	title        string
	facts        []string
	hypothesis   string
	alternatives []string
	checks       []string
	evidence     []domain.Evidence
	at           time.Time
}

func (d *alertDraft) addEvidence(kind, refID, description, source, value string, at time.Time, confidence float64) {
	if len(d.evidence) >= maxEvidenceItems {
		return
	}
	if at.IsZero() {
		at = d.at
	}
	d.evidence = append(d.evidence, domain.Evidence{
		Kind:        kind,
		RefID:       refID,
		Description: description,
		At:          at.UTC(),
		Source:      source,
		Value:       value,
		Confidence:  clampConfidence(confidence, 0, 1),
	})
}

func (d *alertDraft) addFact(fact string) {
	if strings.TrimSpace(fact) == "" {
		return
	}
	d.facts = append(d.facts, fact)
}

// build assembles the domain alert. Timestamps are set to the trusted
// observation instant; the engine overrides creation/update timestamps with the
// injected clock and rejects invalid alerts.
func (d *alertDraft) build() domain.Alert {
	at := d.at
	if at.IsZero() {
		at = time.Unix(0, 0).UTC()
	}
	facts := append([]string(nil), d.facts...)
	if len(facts) == 0 {
		facts = []string{d.title}
	}
	hypothesis := strings.TrimSpace(d.hypothesis)
	if hypothesis == "" {
		hypothesis = "Die Ursache ist nicht bestimmt; ein Angriff ist durch diese Beobachtung allein nicht bewiesen."
	}
	alert := domain.Alert{
		AlertID:            newAlertID(),
		SiteID:             d.site,
		AssetIDs:           append([]domain.AssetID(nil), d.assetIDs...),
		ZoneIDs:            append([]domain.ZoneID(nil), d.zoneIDs...),
		SensorIDs:          append([]domain.SensorID(nil), d.sensorIDs...),
		Category:           d.spec.Category,
		Severity:           d.severity,
		Confidence:         clampConfidence(d.confidence, 0, 1),
		Title:              d.title,
		Summary:            composeSummary(facts, hypothesis, d.checks),
		RuleID:             d.spec.ID,
		RuleVersion:        d.spec.Version,
		FirstSeenAt:        at.UTC(),
		LastSeenAt:         at.UTC(),
		Status:             domain.AlertOpen,
		Evidence:           append([]domain.Evidence(nil), d.evidence...),
		RecommendedActions: append([]domain.RecommendedAction(nil), d.spec.RecommendedActions...),
		SafetyConstraints:  append([]string(nil), d.spec.SafetyConstraints...),
		DedupKey:           d.dedupKey,
		CreatedAt:          at.UTC(),
		UpdatedAt:          at.UTC(),
		Correlation: &domain.CorrelationSummary{
			ObservedFacts:           append([]string(nil), facts...),
			Hypothesis:              hypothesis,
			AlternativeExplanations: append([]string(nil), d.alternatives...),
			RecommendedChecks:       append([]string(nil), d.checks...),
		},
	}
	return alert
}

// composeSummary builds the human-readable alert text with an explicit
// observation / hypothesis / recommended-check separation (hard product rule).
func composeSummary(facts []string, hypothesis string, checks []string) string {
	var b strings.Builder
	b.WriteString("Beobachtung: ")
	for i, fact := range facts {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(strings.TrimSuffix(strings.TrimSpace(fact), "."))
	}
	b.WriteString(". Hypothese: ")
	b.WriteString(strings.TrimSuffix(strings.TrimSpace(hypothesis), "."))
	if len(checks) > 0 {
		b.WriteString(". Empfohlene Prüfung: ")
		limit := 2
		if len(checks) < limit {
			limit = len(checks)
		}
		for i := 0; i < limit; i++ {
			if i > 0 {
				b.WriteString("; ")
			}
			b.WriteString(strings.TrimSuffix(strings.TrimSpace(checks[i]), "."))
		}
	}
	b.WriteString(".")
	return truncateText(b.String(), maxSummaryLen)
}

// truncateText cuts a UTF-8 string at a rune boundary and marks the cut. It
// prevents oversized alert summaries without producing invalid UTF-8.
func truncateText(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes]) + "…"
}

var alertFallbackSeq uint64

// newAlertID returns an unpredictable alert identifier (contract: crypto/rand,
// 16 bytes hex, prefix "alr_"). The fallback only exists so the library cannot
// panic or return an empty identifier if the OS entropy source is unavailable;
// it is monotonic and unique per process, which keeps dedup and audit keys
// usable, but it is intentionally documented as the degraded path.
func newAlertID() domain.AlertID {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return domain.AlertID("alr_" + hex.EncodeToString(buf[:]))
	}
	seq := atomic.AddUint64(&alertFallbackSeq, 1)
	return domain.AlertID(fmt.Sprintf("alr_%032x", seq))
}
