package api

import (
	"math"
	"sync"
	"time"
)

// rateLimiter is a token-bucket limiter keyed by token digest (or peer address
// for unauthenticated requests). Buckets are bounded and pruned, so a hostile
// client cannot grow the map without limit.
type rateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	ratePerSec float64
	burst      float64
	now        func() time.Time
	lastPrune  time.Time
	maxBuckets int
	idleTTL    time.Duration
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter builds a limiter that allows perMinute requests with the given
// burst capacity.
func newRateLimiter(perMinute, burst int) *rateLimiter {
	rate := float64(perMinute) / 60.0
	return &rateLimiter{
		buckets:    make(map[string]*bucket, 64),
		ratePerSec: rate,
		burst:      float64(burst),
		now:        time.Now,
		lastPrune:  time.Now(),
		maxBuckets: 4096,
		idleTTL:    10 * time.Minute,
	}
}

// allow consumes one token for key. The second return value is the number of
// seconds to wait before the next attempt (used for Retry-After).
func (l *rateLimiter) allow(key string) (bool, int) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastPrune) > l.idleTTL || len(l.buckets) > l.maxBuckets {
		l.pruneLocked(now)
	}

	entry, ok := l.buckets[key]
	if !ok {
		entry = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = entry
	} else {
		elapsed := now.Sub(entry.last).Seconds()
		if elapsed > 0 {
			entry.tokens = math.Min(l.burst, entry.tokens+elapsed*l.ratePerSec)
			entry.last = now
		}
	}
	if entry.tokens >= 1 {
		entry.tokens--
		return true, 0
	}
	missing := 1 - entry.tokens
	retryAfter := int(math.Ceil(missing / l.ratePerSec))
	if retryAfter < 1 {
		retryAfter = 1
	}
	return false, retryAfter
}

// pruneLocked drops buckets that have been idle longer than the TTL and, if the
// map is still too large, the oldest entries.
func (l *rateLimiter) pruneLocked(now time.Time) {
	l.lastPrune = now
	for key, entry := range l.buckets {
		if now.Sub(entry.last) > l.idleTTL {
			delete(l.buckets, key)
		}
	}
	if len(l.buckets) <= l.maxBuckets {
		return
	}
	var oldestKey string
	var oldest time.Time
	for key, entry := range l.buckets {
		if oldestKey == "" || entry.last.Before(oldest) {
			oldestKey, oldest = key, entry.last
		}
	}
	if oldestKey != "" {
		delete(l.buckets, oldestKey)
	}
}
