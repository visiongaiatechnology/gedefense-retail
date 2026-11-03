package identity

import (
	"sync"
	"time"
)

// LockoutPolicy bounds credential guessing per user and source address.
type LockoutPolicy struct {
	Failures int
	Window   time.Duration
	LockFor  time.Duration
}

// DefaultLockoutPolicy locks an identity for five minutes after five failures
// within fifteen minutes.
func DefaultLockoutPolicy() LockoutPolicy {
	return LockoutPolicy{Failures: 5, Window: 15 * time.Minute, LockFor: 5 * time.Minute}
}

// lockoutSet tracks failure counters and lock windows. It is keyed by
// "user|source-ip" so one hostile address cannot lock a vendor out globally.
type lockoutSet struct {
	mu      sync.Mutex
	policy  LockoutPolicy
	entries map[string]*failureEntry
	maxSize int
	now     func() time.Time
}

type failureEntry struct {
	count       int
	first       time.Time
	lockedUntil time.Time
}

func newLockoutSet(policy LockoutPolicy, now func() time.Time) *lockoutSet {
	if policy.Failures < 1 || policy.Window <= 0 || policy.LockFor <= 0 {
		policy = DefaultLockoutPolicy()
	}
	return &lockoutSet{policy: policy, entries: make(map[string]*failureEntry), maxSize: 10000, now: now}
}

// locked reports the remaining lock duration for a key.
func (l *lockoutSet) locked(key string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[key]
	if !ok {
		return 0, false
	}
	now := l.now()
	if now.Before(entry.lockedUntil) {
		return entry.lockedUntil.Sub(now), true
	}
	return 0, false
}

// fail records one failed attempt and locks the key when the threshold is hit.
func (l *lockoutSet) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.entries) >= l.maxSize {
		l.pruneLocked(now)
	}
	entry, ok := l.entries[key]
	if !ok {
		entry = &failureEntry{first: now}
		l.entries[key] = entry
	}
	if now.Sub(entry.first) > l.policy.Window {
		entry.count = 0
		entry.first = now
	}
	entry.count++
	if entry.count >= l.policy.Failures {
		entry.lockedUntil = now.Add(l.policy.LockFor)
		entry.count = 0
		entry.first = now
	}
}

// reset clears the failure state after a successful authentication.
func (l *lockoutSet) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// pruneLocked drops stale entries so a hostile spread of keys cannot grow the map.
func (l *lockoutSet) pruneLocked(now time.Time) {
	for key, entry := range l.entries {
		if now.Sub(entry.first) > l.policy.Window && now.After(entry.lockedUntil) {
			delete(l.entries, key)
		}
	}
}
