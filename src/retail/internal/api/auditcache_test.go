package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
	"github.com/visiongaiatechnology/gedefense/retail/internal/store"
)

// countingAudit wraps a real audit store and counts verification calls.
type countingAudit struct {
	ports.AuditStore
	calls atomic.Int64
	delay time.Duration
}

func (c *countingAudit) Verify(ctx context.Context) (bool, uint64, error) {
	c.calls.Add(1)
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	return c.AuditStore.Verify(ctx)
}

func TestHealthCachesAuditVerification(t *testing.T) {
	counter := &countingAudit{delay: 5 * time.Millisecond}
	h := newAPIHarness(t, apiTestOptions{auditWrapper: func(a *store.AuditLog) ports.AuditStore {
		counter.AuditStore = a
		return counter
	}})
	h.server.SetAuditVerifyTTL(time.Hour)

	start := time.Now()
	first := h.do(t, http.MethodGet, "/api/v1/health", nil, "", nil)
	firstDuration := time.Since(start)
	if first.Code != http.StatusOK {
		t.Fatalf("first health = %d", first.Code)
	}
	firstBody := decode[healthResponse](t, first)
	if !firstBody.Storage.AuditChainOK || firstBody.Storage.AuditCheckedAt.IsZero() {
		t.Errorf("first storage = %+v", firstBody.Storage)
	}
	if calls := counter.calls.Load(); calls != 1 {
		t.Fatalf("verification calls after first probe = %d, want 1", calls)
	}

	start = time.Now()
	second := h.do(t, http.MethodGet, "/api/v1/health", nil, "", nil)
	secondDuration := time.Since(start)
	secondBody := decode[healthResponse](t, second)
	if calls := counter.calls.Load(); calls != 1 {
		t.Fatalf("cached probe triggered %d verification calls, want 1", calls)
	}
	if !secondBody.Storage.AuditCheckedAt.Equal(firstBody.Storage.AuditCheckedAt) {
		t.Errorf("checked_at changed within the TTL: %v vs %v",
			firstBody.Storage.AuditCheckedAt, secondBody.Storage.AuditCheckedAt)
	}
	if secondDuration >= firstDuration {
		t.Errorf("cached probe (%v) was not faster than the first (%v)", secondDuration, firstDuration)
	}
	t.Logf("health latency: first=%v cached=%v", firstDuration, secondDuration)

	// The audit endpoint shares the cache.
	if recorder := h.do(t, http.MethodGet, "/api/v1/audit", nil, viewerToken, nil); recorder.Code != http.StatusOK {
		t.Fatalf("audit endpoint = %d", recorder.Code)
	}
	if calls := counter.calls.Load(); calls != 1 {
		t.Errorf("audit endpoint triggered an extra verification (%d calls)", calls)
	}

	// An expired TTL re-verifies.
	h.server.SetAuditVerifyTTL(time.Nanosecond)
	if recorder := h.do(t, http.MethodGet, "/api/v1/health", nil, "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("health after TTL expiry = %d", recorder.Code)
	}
	if calls := counter.calls.Load(); calls != 2 {
		t.Errorf("verification calls after TTL expiry = %d, want 2", calls)
	}
}

func TestHealthAuditLatencyWithLargeChain(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	ctx := context.Background()
	const entries = 10000
	for i := 0; i < entries; i++ {
		entry := domain.AuditEntry{
			At:         baseTime,
			Actor:      "admin",
			Role:       "admin",
			Action:     "test.bulk",
			ObjectType: "test",
			ObjectID:   fmt.Sprintf("obj-%d", i),
		}
		if _, err := h.audit.Append(ctx, entry); err != nil {
			t.Fatalf("append audit entry %d: %v", i, err)
		}
	}
	h.server.SetAuditVerifyTTL(30 * time.Second)

	start := time.Now()
	first := h.do(t, http.MethodGet, "/api/v1/health", nil, "", nil)
	uncached := time.Since(start)
	if first.Code != http.StatusOK {
		t.Fatalf("first health = %d", first.Code)
	}
	body := decode[healthResponse](t, first)
	if !body.Storage.AuditChainOK {
		t.Fatalf("chain over %d entries reported broken", entries)
	}
	if got := h.server.auditChain.Checks(); got != 1 {
		t.Fatalf("verifications = %d, want 1", got)
	}

	start = time.Now()
	second := h.do(t, http.MethodGet, "/api/v1/health", nil, "", nil)
	cached := time.Since(start)
	if second.Code != http.StatusOK {
		t.Fatalf("second health = %d", second.Code)
	}
	if got := h.server.auditChain.Checks(); got != 1 {
		t.Errorf("cached health ran %d verifications, want 1", got)
	}
	if cached >= uncached {
		t.Errorf("cached health latency %v >= uncached %v", cached, uncached)
	}
	t.Logf("audit chain %d entries: uncached health=%v cached health=%v", entries, uncached, cached)
}

func TestHealthReportsTamperedChainAfterCacheExpiry(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		entry := domain.AuditEntry{
			At: baseTime, Actor: fmt.Sprintf("admin-%d", i+1), Role: "admin",
			Action: "test", ObjectType: "test", ObjectID: "obj-1",
		}
		if _, err := h.audit.Append(ctx, entry); err != nil {
			t.Fatalf("append audit entry: %v", err)
		}
	}
	h.server.SetAuditVerifyTTL(time.Hour)
	healthy := decode[healthResponse](t, h.do(t, http.MethodGet, "/api/v1/health", nil, "", nil))
	if !healthy.Storage.AuditChainOK || healthy.Status != "ok" {
		t.Fatalf("initial health = %+v", healthy)
	}

	// Tamper with the persisted chain after the cached verification.
	files, err := filepath.Glob(filepath.Join(h.dir, "audit", "*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no audit file found: %v", err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	tampered := bytes.Replace(raw, []byte(`"admin-2"`), []byte(`"admin-X"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("tamper replacement did not apply")
	}
	if err := os.WriteFile(files[0], tampered, 0o600); err != nil {
		t.Fatalf("write tampered audit file: %v", err)
	}

	// Within the TTL the cached answer is returned together with its timestamp;
	// this is the documented staleness bound, not a silent lie.
	cached := decode[healthResponse](t, h.do(t, http.MethodGet, "/api/v1/health", nil, "", nil))
	if !cached.Storage.AuditChainOK {
		t.Errorf("cached health reported the tamper before the TTL expired")
	}

	// After the TTL the tamper is detected and surfaced.
	h.server.SetAuditVerifyTTL(time.Nanosecond)
	broken := decode[healthResponse](t, h.do(t, http.MethodGet, "/api/v1/health", nil, "", nil))
	if broken.Storage.AuditChainOK {
		t.Fatal("health still reports a valid audit chain after tampering")
	}
	if broken.Status != "degraded" {
		t.Errorf("status = %q, want degraded", broken.Status)
	}
	audit := decode[auditResponse](t, h.do(t, http.MethodGet, "/api/v1/audit", nil, viewerToken, nil))
	if audit.ChainOK {
		t.Error("audit endpoint reports chain_ok after tampering")
	}
	if audit.FirstVerifiedSeq == 0 {
		t.Error("audit endpoint does not report the first failing sequence")
	}
}
