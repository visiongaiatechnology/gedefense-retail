package detect

import (
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// baselineLookback returns the operator-configured learning window for the
// communication baseline, or the conservative default.
func baselineLookback(policy domain.Policy) time.Duration {
	if policy.Network.LearnedBaselineWindowS > 0 {
		return time.Duration(policy.Network.LearnedBaselineWindowS) * time.Second
	}
	return eventLookback
}

// priorFlow reports whether the communication pair was observed before the
// current event inside the lookback window. It deliberately excludes the current
// event: the pipeline may already have registered the pair in the peer baseline,
// so "known" must be derived from history, not from the observation itself.
func priorFlow(w World, ev domain.Event, since time.Time, src, dst, protocol string) bool {
	if ev.Flow == nil || since.IsZero() {
		return false
	}
	flows := w.Events(ports.EventQuery{
		SiteID: ev.SiteID,
		Kind:   domain.EventFlow,
		Since:  rfc3339(since),
		Limit:  maxQueryLimit,
	})
	for _, other := range flows {
		if other.EventID == ev.EventID || other.Flow == nil {
			continue
		}
		if strings.TrimSpace(other.Flow.SrcIP) != src || strings.TrimSpace(other.Flow.DstIP) != dst {
			continue
		}
		if strings.ToLower(strings.TrimSpace(other.Flow.Protocol)) != protocol {
			continue
		}
		return true
	}
	return false
}

// pairAllowed checks the operator allowlist of approved communication pairs.
func pairAllowed(policy domain.Policy, ev domain.Event) bool {
	if ev.Flow == nil {
		return false
	}
	for _, pair := range policy.Network.AllowedPairs {
		if pair.Protocol != "" && !strings.EqualFold(strings.TrimSpace(pair.Protocol), strings.TrimSpace(ev.Flow.Protocol)) {
			continue
		}
		if pair.Port != 0 && pair.Port != ev.Flow.DstPort {
			continue
		}
		if pair.TargetAssetID != "" && pair.TargetAssetID != ev.AssetID {
			continue
		}
		if pair.TargetZoneID != "" && pair.TargetZoneID != ev.ZoneID {
			continue
		}
		if pair.TargetAssetID == "" && pair.TargetZoneID == "" {
			continue // a pair without a target does not prove anything
		}
		return true
	}
	return false
}

// graceActive reports whether the site is still inside the operator onboarding
// grace period measured from the first observed flow of the site.
func graceActive(w World, ev domain.Event, graceSeconds int) bool {
	if graceSeconds <= 0 {
		return false
	}
	grace := time.Duration(graceSeconds) * time.Second
	now := w.Now()
	if now.IsZero() {
		return false
	}
	_, sinceStr := lookbackSince(w, grace)
	flows := w.Events(ports.EventQuery{
		SiteID: ev.SiteID,
		Kind:   domain.EventFlow,
		Since:  sinceStr,
		Limit:  maxQueryLimit,
	})
	earliest := time.Time{}
	for _, other := range flows {
		at := other.ObservedAt
		if at.IsZero() {
			at = other.ReceivedAt
		}
		if at.IsZero() {
			continue
		}
		if earliest.IsZero() || at.Before(earliest) {
			earliest = at
		}
	}
	if earliest.IsZero() {
		earliest = trustedTime(ev)
	}
	if earliest.IsZero() || earliest.After(now) {
		return false
	}
	return now.Sub(earliest) < grace
}
