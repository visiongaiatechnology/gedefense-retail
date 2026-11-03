package correlate

import (
	"sort"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Chain identifiers from the product contract (engineering contract §5.11).
const (
	ChainThermalManipulation = "chain-thermal-manipulation"
	ChainSensorIntegrity     = "chain-sensor-integrity"
	ChainRemoteIntrusion     = "chain-remote-intrusion"
)

// chainWindow is the correlation window shared by all chains: indicators must
// fall inside one 30-minute window. A chain that is older than the window is not
// resurrected by unrelated new alerts.
const chainWindow = 30 * time.Minute

// indicator is one independent evidence group of a chain. Every alert matches at
// most one indicator per chain, so a chain can only escalate when several
// different rule families fired.
type indicator struct {
	key     string
	label   string
	ruleIDs []domain.RuleID
}

func (i indicator) matches(ruleID domain.RuleID) bool {
	for _, id := range i.ruleIDs {
		if id == ruleID {
			return true
		}
	}
	return false
}

// chainDef is the declarative description of one correlation chain.
type chainDef struct {
	id            string
	name          string
	title         string
	window        time.Duration
	minIndicators int
	severity      domain.Severity
	category      domain.Category
	indicators    []indicator
	hypothesis    string
	alternatives  []string
	checks        []string
	safety        []string
}

// hit is one matched indicator backed by a concrete alert.
type hit struct {
	indicator indicator
	alert     domain.Alert
	at        time.Time
}

// matchChain returns the best set of independent indicators for the chain inside
// a single chain window. "Best" means: most distinct indicators, then the
// earliest window start (deterministic). The chain must still be active, i.e. its
// newest indicator lies within the window measured from now.
func matchChain(records []record, chain chainDef, now time.Time) []hit {
	if len(records) == 0 {
		return nil
	}
	var (
		best      []hit
		bestStart time.Time
	)
	for i := 0; i < len(records); i++ {
		start := records[i].at
		if start.IsZero() {
			continue
		}
		matched := make(map[string]hit, len(chain.indicators))
		var newest time.Time
		for j := i; j < len(records); j++ {
			at := records[j].at
			if at.IsZero() {
				continue
			}
			if at.Sub(start) > chain.window {
				break
			}
			newest = at
			for _, ind := range chain.indicators {
				if _, done := matched[ind.key]; done {
					continue
				}
				if !ind.matches(records[j].alert.RuleID) {
					continue
				}
				matched[ind.key] = hit{indicator: ind, alert: records[j].alert, at: at}
			}
		}
		if len(matched) < chain.minIndicators {
			continue
		}
		if newest.IsZero() || now.Sub(newest) > chain.window {
			continue // chain is no longer active -> do not resurrect old evidence
		}
		if len(matched) < len(best) {
			continue
		}
		if len(matched) == len(best) && !bestStart.IsZero() && !start.Before(bestStart) {
			continue
		}
		bestStart = start
		best = best[:0]
		for _, ind := range chain.indicators {
			if match, ok := matched[ind.key]; ok {
				best = append(best, match)
			}
		}
	}
	if len(best) == 0 {
		return nil
	}
	sort.SliceStable(best, func(i, j int) bool {
		if !best[i].at.Equal(best[j].at) {
			return best[i].at.Before(best[j].at)
		}
		return best[i].indicator.key < best[j].indicator.key
	})
	return best
}

func hitAlertIDs(hits []hit) []domain.AlertID {
	out := make([]domain.AlertID, 0, len(hits))
	for _, h := range hits {
		if h.alert.AlertID != "" {
			out = append(out, h.alert.AlertID)
		}
	}
	return out
}

// hitAssetIDs returns the distinct asset references of the matched alerts.
func hitAssetIDs(hits []hit) []domain.AssetID {
	seen := make(map[domain.AssetID]struct{}, len(hits))
	out := make([]domain.AssetID, 0, len(hits))
	for _, h := range hits {
		for _, id := range h.alert.AssetIDs {
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func hitIndicatorKeys(hits []hit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.indicator.key)
	}
	return out
}
