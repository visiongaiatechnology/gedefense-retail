package api

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/approval"
)

// rateLimiter is a bounded token bucket keyed by session digest or source address.
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

func newRateLimiter(perMinute, burst int) *rateLimiter {
	return &rateLimiter{
		buckets:    make(map[string]*bucket, 64),
		ratePerSec: float64(perMinute) / 60.0,
		burst:      float64(burst),
		now:        time.Now,
		lastPrune:  time.Now(),
		maxBuckets: 4096,
		idleTTL:    10 * time.Minute,
	}
}

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
	retry := int(math.Ceil(missing / l.ratePerSec))
	if retry < 1 {
		retry = 1
	}
	return false, retry
}

func (l *rateLimiter) pruneLocked(now time.Time) {
	l.lastPrune = now
	for key, entry := range l.buckets {
		if now.Sub(entry.last) > l.idleTTL {
			delete(l.buckets, key)
		}
	}
	for len(l.buckets) > l.maxBuckets {
		var oldestKey string
		var oldest time.Time
		for key, entry := range l.buckets {
			if oldestKey == "" || entry.last.Before(oldest) {
				oldestKey, oldest = key, entry.last
			}
		}
		if oldestKey == "" {
			return
		}
		delete(l.buckets, oldestKey)
	}
}

// idempotencyCache replays successful POST responses for a repeated key.
type idempotencyCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]idempotentResponse
	max     int
	now     func() time.Time
}

type idempotentResponse struct {
	requestHash string
	status      int
	body        []byte
	expiresAt   time.Time
}

func newIdempotencyCache(ttl time.Duration) *idempotencyCache {
	return &idempotencyCache{ttl: ttl, entries: make(map[string]idempotentResponse, 64), max: 1024, now: time.Now}
}

func (c *idempotencyCache) lookup(key, requestHash string) (idempotentResponse, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || c.now().After(entry.expiresAt) {
		if ok {
			delete(c.entries, key)
		}
		return idempotentResponse{}, false, true
	}
	if entry.requestHash != requestHash {
		return idempotentResponse{}, false, false
	}
	return entry, true, true
}

func (c *idempotencyCache) store(key, requestHash string, status int, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		for existing := range c.entries {
			delete(c.entries, existing)
			break
		}
	}
	c.entries[key] = idempotentResponse{requestHash: requestHash, status: status, body: body, expiresAt: c.now().Add(c.ttl)}
}

// auditVerifier caches the audit chain verification (health/status/audit).
type auditVerifier struct {
	mu     sync.Mutex
	gate   *approval.Service
	ttl    time.Duration
	status chainStatus
	valid  bool
	now    func() time.Time
}

type chainStatus struct {
	OK        bool
	BadSeq    uint64
	FirstSeq  uint64
	CheckedAt time.Time
	Err       error
}

func newAuditVerifier(gate *approval.Service, ttl time.Duration) *auditVerifier {
	return &auditVerifier{gate: gate, ttl: ttl, now: time.Now}
}

func (v *auditVerifier) setTTL(ttl time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.ttl = ttl
	v.valid = false
}

func (v *auditVerifier) statusOf(ctx context.Context) chainStatus {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now().UTC()
	if v.valid && v.ttl > 0 && now.Sub(v.status.CheckedAt) < v.ttl {
		return v.status
	}
	verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	ok, badSeq, err := v.gate.VerifyAudit(verifyCtx)
	status := chainStatus{OK: ok, BadSeq: badSeq, CheckedAt: now, Err: err}
	if err == nil {
		status.FirstSeq = 1
		if ok {
			if first := v.gate.AuditFirstSeq(); first > 0 {
				status.FirstSeq = first
			}
		} else {
			status.FirstSeq = badSeq
		}
	}
	v.status = status
	v.valid = true
	return status
}

// chainOK reports the cached chain state.
func (v *auditVerifier) chainOK(ctx context.Context) bool {
	status := v.statusOf(ctx)
	return status.Err == nil && status.OK
}
