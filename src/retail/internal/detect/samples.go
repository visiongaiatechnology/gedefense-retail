package detect

import (
	"sort"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// seriesPoint is a normalized Celsius sample used by the rate and frozen-value
// rules.
type seriesPoint struct {
	At     time.Time
	ValueC float64
}

// seriesFromSamples normalizes and sorts samples belonging to one metric.
func seriesFromSamples(samples []domain.Sample, metric string) []seriesPoint {
	out := make([]seriesPoint, 0, len(samples))
	for _, sample := range samples {
		if sample.At.IsZero() {
			continue
		}
		if metric != "" && sample.Metric != "" && !strings.EqualFold(sample.Metric, metric) {
			continue
		}
		valueC, ok := temperatureInC(sample.Value, sample.Unit)
		if !ok {
			continue
		}
		out = append(out, seriesPoint{At: sample.At.UTC(), ValueC: valueC})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// latestSampleBefore returns the newest sample strictly before instant.
func latestSampleBefore(samples []domain.Sample, instant time.Time) (domain.Sample, bool) {
	best := domain.Sample{}
	found := false
	for _, sample := range samples {
		if sample.At.IsZero() || !sample.At.Before(instant) {
			continue
		}
		if !found || sample.At.After(best.At) {
			best = sample
			found = true
		}
	}
	return best, found
}

// previousSample returns the newest sample of a sensor strictly before the given
// instant, searched within the standard event lookback. It is used to detect
// changes (setpoint, mode, timestamp monotonicity) without inventing history.
func previousSample(w World, sensor domain.SensorID, before time.Time) (domain.Sample, bool) {
	if before.IsZero() {
		return domain.Sample{}, false
	}
	since := before.Add(-eventLookback)
	if since.IsZero() {
		return domain.Sample{}, false
	}
	samples := w.SamplesFor(sensor, since)
	return latestSampleBefore(samples, before)
}

// latestSample returns the newest sample within the lookback window.
func latestSample(w World, sensor domain.SensorID, lookback time.Duration) (domain.Sample, bool) {
	since, _ := lookbackSince(w, lookback)
	if since.IsZero() {
		return domain.Sample{}, false
	}
	samples := w.SamplesFor(sensor, since)
	return latestSampleBeforeOrAt(samples, w.Now())
}

func latestSampleBeforeOrAt(samples []domain.Sample, instant time.Time) (domain.Sample, bool) {
	best := domain.Sample{}
	found := false
	for _, sample := range samples {
		if sample.At.IsZero() || sample.At.After(instant) {
			continue
		}
		if !found || sample.At.After(best.At) {
			best = sample
			found = true
		}
	}
	return best, found
}
