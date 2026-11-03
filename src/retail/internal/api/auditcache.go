package api

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// defaultAuditVerifyTTL bounds how often the hash chain is re-verified. The chain
// is append-only, so a cached "ok" can only miss newly appended entries (which are
// themselves chained) or an out-of-band tamper for at most this window. The
// checked-at timestamp is surfaced in the health payload so the answer stays
// honest instead of silently suggesting a fresh verification.
const defaultAuditVerifyTTL = 30 * time.Second

// auditVerifyTimeout bounds one verification run independently of the caller's
// request context: a cancelled health probe must not poison the cache.
const auditVerifyTimeout = 10 * time.Second

// chainStatus is the cached result of one audit-chain verification.
type chainStatus struct {
	OK        bool
	BadSeq    uint64
	FirstSeq  uint64
	CheckedAt time.Time
	Err       error
}

// auditVerifier caches the O(audit-log) chain verification. Without the cache an
// unauthenticated GET /health would re-read and re-hash the complete audit trail on
// every single request.
type auditVerifier struct {
	mu     sync.Mutex
	store  ports.AuditStore
	ttl    time.Duration
	now    func() time.Time
	status chainStatus
	valid  bool
	checks atomic.Int64
}

// newAuditVerifier builds a verifier cache for the given audit store.
func newAuditVerifier(store ports.AuditStore, ttl time.Duration) *auditVerifier {
	return &auditVerifier{store: store, ttl: ttl, now: time.Now}
}

// Status returns the cached verification result, refreshing it when the TTL
// expired. The mutex serialises refreshes so concurrent probes cannot stampede the
// audit log.
func (v *auditVerifier) Status(ctx context.Context) chainStatus {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := v.now()
	if v.valid && v.ttl > 0 && now.Sub(v.status.CheckedAt) < v.ttl {
		return v.status
	}

	verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditVerifyTimeout)
	defer cancel()
	v.checks.Add(1)
	ok, badSeq, err := v.store.Verify(verifyCtx)

	status := chainStatus{OK: ok, BadSeq: badSeq, CheckedAt: now, Err: err}
	if err == nil {
		if ok {
			status.FirstSeq = firstAuditSeq(v.store)
		} else {
			status.FirstSeq = badSeq
		}
	}
	v.status = status
	v.valid = true
	return status
}

// Invalidate forces the next Status call to re-verify. It is used by tests and by
// the composition root after a known chain-affecting event.
func (v *auditVerifier) Invalidate() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.valid = false
}

// Checks returns the number of real verifications performed (test/diagnostic).
func (v *auditVerifier) Checks() int64 { return v.checks.Load() }

// firstAuditSeq returns the oldest persisted audit sequence when the store exposes
// it, otherwise 1.
func firstAuditSeq(store ports.AuditStore) uint64 {
	if withFirst, ok := store.(interface{ FirstSeq() uint64 }); ok {
		if seq := withFirst.FirstSeq(); seq > 0 {
			return seq
		}
	}
	return 1
}

// SetAuditVerifyTTL overrides the audit chain verification cache TTL. A value <= 0
// disables caching (every health probe verifies). It is a test/operations hook and
// must be called before the server starts serving.
func (s *Server) SetAuditVerifyTTL(ttl time.Duration) {
	if s.auditChain == nil {
		return
	}
	s.auditChain.mu.Lock()
	defer s.auditChain.mu.Unlock()
	s.auditChain.ttl = ttl
	s.auditChain.valid = false
}
