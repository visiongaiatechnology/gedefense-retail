package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
	"github.com/visiongaiatechnology/gedefense/retail/internal/store"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

var baseTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// newManager opens a policy manager backed by a real hash-chained audit log.
func newManager(t *testing.T, dir string, clock ports.Clock, initial *domain.Policy) (*Manager, *store.AuditLog) {
	t.Helper()
	audit, err := store.OpenAuditLog(store.Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	t.Cleanup(func() {
		if cerr := audit.Close(); cerr != nil {
			t.Errorf("AuditLog.Close: %v", cerr)
		}
	})
	manager, err := OpenManager(Options{Dir: filepath.Join(dir, "policy"), Site: "filiale-001", Clock: clock, Audit: audit, Initial: initial})
	if err != nil {
		t.Fatalf("OpenManager: %v", err)
	}
	return manager, audit
}

func TestOpenManagerBootstrapsDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	manager, _ := newManager(t, dir, clock, nil)

	if got := manager.Count(); got != 1 {
		t.Fatalf("Count = %d, want 1", got)
	}
	current := manager.Current()
	if current.Version != 1 {
		t.Errorf("version = %d, want 1", current.Version)
	}
	if current.SiteID != "filiale-001" {
		t.Errorf("site = %q", current.SiteID)
	}
	if !current.UpdatedAt.Equal(baseTime) {
		t.Errorf("UpdatedAt = %v", current.UpdatedAt)
	}
	if current.Hash == "" {
		t.Error("bootstrap policy must carry a canonical hash")
	}
	versions := manager.Versions(10)
	if len(versions) != 1 || versions[0].Policy.Version != 1 {
		t.Fatalf("Versions = %+v", versions)
	}

	// The atomic mirror must exist and decode.
	if _, err := os.Stat(filepath.Join(dir, "policy", currentFileName)); err != nil {
		t.Errorf("policy.json missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "policy", versionsFileName)); err != nil {
		t.Errorf("policy-versions.jsonl missing: %v", err)
	}
}

func TestOpenManagerUsesInitialPolicy(t *testing.T) {
	initial := domain.DefaultPolicy("filiale-001", baseTime)
	initial.Maintenance.RequireWindow = false
	initial.Retention.EventDays = 14
	manager, _ := newManager(t, t.TempDir(), newFakeClock(baseTime), &initial)

	current := manager.Current()
	if current.Maintenance.RequireWindow {
		t.Error("initial policy not applied")
	}
	if current.Retention.EventDays != 14 {
		t.Errorf("EventDays = %d, want 14", current.Retention.EventDays)
	}
}

func TestUpdateCreatesAuditedVersion(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	manager, audit := newManager(t, dir, clock, nil)

	next := manager.Current()
	next.Maintenance.RequireWindow = false
	maxC := 7.5
	next.Temperature.Limits = []domain.TemperatureLimit{{
		ZoneID: "zone-ot", Metric: "air_temperature", MaxC: &maxC,
	}}
	clock.Advance(time.Minute)

	record, err := manager.Update(next, "admin", "admin", "Kältezone 1 Grenzwerte")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if record.Policy.Version != 2 {
		t.Errorf("version = %d, want 2", record.Policy.Version)
	}
	if record.Policy.Hash == "" || record.Policy.Hash == manager.Versions(2)[1].Policy.Hash {
		t.Errorf("hash not advanced: %q", record.Policy.Hash)
	}
	if record.ChangeNote != "Kältezone 1 Grenzwerte" {
		t.Errorf("change note = %q", record.ChangeNote)
	}
	if record.PrevHash != manager.Versions(2)[1].Policy.Hash {
		t.Error("version record is not hash-linked to its predecessor")
	}

	current := manager.Current()
	if current.Maintenance.RequireWindow {
		t.Error("updated policy not active")
	}
	if len(current.Temperature.Limits) != 1 || *current.Temperature.Limits[0].MaxC != 7.5 {
		t.Errorf("limits = %+v", current.Temperature.Limits)
	}

	versions := manager.Versions(10)
	if len(versions) != 2 || versions[0].Policy.Version != 2 || versions[1].Policy.Version != 1 {
		t.Fatalf("Versions order = %+v", versions)
	}
	if _, ok := manager.Get(2); !ok {
		t.Error("Get(2) missing")
	}
	if _, ok := manager.Get(99); ok {
		t.Error("Get(99) must not exist")
	}

	entries, err := audit.List(context.Background(), 10)
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Action != "policy.update" || entry.Actor != "admin" || entry.Role != "admin" {
		t.Errorf("audit entry = %+v", entry)
	}
	if entry.AfterHash != record.Policy.Hash || entry.BeforeHash != record.PrevHash {
		t.Errorf("audit hashes = before %q after %q", entry.BeforeHash, entry.AfterHash)
	}
	if ok, _, verr := audit.Verify(context.Background()); verr != nil || !ok {
		t.Fatalf("audit chain = %v, %v", ok, verr)
	}
}

func TestUpdateValidation(t *testing.T) {
	manager, _ := newManager(t, t.TempDir(), newFakeClock(baseTime), nil)
	good := manager.Current()

	cases := []struct {
		name   string
		policy domain.Policy
		actor  domain.UserID
		role   string
		reason string
		want   error
	}{
		{"wrong role", good, "admin", "operator", "reason", ErrForbidden},
		{"bad actor", good, "bad id!", "admin", "reason", ErrInvalidActor},
		{"missing reason", good, "admin", "admin", "   ", ErrReasonRequired},
		{"site mismatch", func() domain.Policy { p := good; p.SiteID = "filiale-999"; return p }(), "admin", "admin", "reason", ErrSiteMismatch},
		{"invalid policy", func() domain.Policy { p := good; p.Retention.EventDays = 0; return p }(), "admin", "admin", "reason", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := manager.Update(tc.policy, tc.actor, tc.role, tc.reason)
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if got := manager.Count(); got != 1 {
		t.Errorf("rejected updates must not create versions, Count = %d", got)
	}
}

func TestManagerPersistsAndVerifiesAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	manager, _ := newManager(t, dir, clock, nil)

	next := manager.Current()
	next.Maintenance.RequireWindow = false
	record, err := manager.Update(next, "admin", "admin", "disable window requirement")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	firstHash := manager.Versions(2)[1].Policy.Hash

	reopened, _ := newManager(t, dir, clock, nil)
	if got := reopened.Count(); got != 2 {
		t.Fatalf("Count after reopen = %d, want 2", got)
	}
	if current := reopened.Current(); current.Hash != record.Policy.Hash {
		t.Errorf("current hash = %q, want %q", current.Hash, record.Policy.Hash)
	}
	if reopened.Versions(2)[1].Policy.Hash != firstHash {
		t.Error("version history changed on reopen")
	}
	// A second update must continue the hash chain.
	third := reopened.Current()
	third.DataQuality.TelemetryGapS = 1200
	if _, uerr := reopened.Update(third, "admin", "admin", "tune gap window"); uerr != nil {
		t.Fatalf("Update after reopen: %v", uerr)
	}
	if got := reopened.Versions(1)[0].Policy.Version; got != 3 {
		t.Errorf("newest version = %d, want 3", got)
	}
}

func TestReloadFromFile(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	manager, audit := newManager(t, dir, clock, nil)

	// Operator edits the atomic mirror directly, then asks for a reload.
	path := filepath.Join(dir, "policy", currentFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy.json: %v", err)
	}
	var edited domain.Policy
	if uerr := jsonUnmarshal(raw, &edited); uerr != nil {
		t.Fatalf("unmarshal policy: %v", uerr)
	}
	edited.Network.BaselineRequired = true
	editedBytes, err := jsonMarshal(edited)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	if err := os.WriteFile(path, editedBytes, 0o600); err != nil {
		t.Fatalf("write policy.json: %v", err)
	}

	record, err := manager.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if record.Policy.Version != 2 {
		t.Errorf("version = %d, want 2", record.Policy.Version)
	}
	if !manager.Current().Network.BaselineRequired {
		t.Error("reloaded policy not active")
	}
	entries, err := audit.List(context.Background(), 10)
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	if len(entries) != 1 || entries[0].Action != "policy.reload" {
		t.Errorf("audit entries = %+v", entries)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove policy.json: %v", err)
	}
	if _, err := manager.Reload(); !errors.Is(err, ErrNoPolicyFile) {
		t.Errorf("Reload without file = %v, want ErrNoPolicyFile", err)
	}
}

func TestCorruptVersionHistoryIsRejected(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	manager, _ := newManager(t, dir, clock, nil)
	next := manager.Current()
	next.Maintenance.RequireWindow = false
	if _, err := manager.Update(next, "admin", "admin", "change"); err != nil {
		t.Fatalf("Update: %v", err)
	}

	versionsPath := filepath.Join(dir, "policy", versionsFileName)
	raw, err := os.ReadFile(versionsPath)
	if err != nil {
		t.Fatalf("read versions: %v", err)
	}
	// Flip one character inside the persisted policy content.
	corrupted := make([]byte, len(raw))
	copy(corrupted, raw)
	idx := indexOf(corrupted, []byte(`"require_window":false`))
	if idx < 0 {
		t.Skip("expected marker not found in version history")
	}
	copy(corrupted[idx:], []byte(`"require_window":true `))
	if err := os.WriteFile(versionsPath, corrupted, 0o600); err != nil {
		t.Fatalf("write corrupt versions: %v", err)
	}
	if _, err := OpenManager(Options{Dir: filepath.Join(dir, "policy"), Site: "filiale-001", Clock: clock, Audit: openAudit(t, dir, clock)}); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("Open on corrupt history = %v, want ErrCorruptState", err)
	}
}

func TestOpenManagerRejectsMissingAudit(t *testing.T) {
	if _, err := OpenManager(Options{Dir: t.TempDir(), Site: "filiale-001"}); err == nil {
		t.Fatal("expected error for missing audit store")
	}
	if _, err := OpenManager(Options{Site: "filiale-001", Audit: openAudit(t, t.TempDir(), newFakeClock(baseTime))}); err == nil {
		t.Fatal("expected error for missing dir")
	}
}

func TestCanonicalHashIsStable(t *testing.T) {
	p := domain.DefaultPolicy("filiale-001", baseTime)
	first, err := canonicalHash(p)
	if err != nil {
		t.Fatalf("canonicalHash: %v", err)
	}
	second, err := canonicalHash(p)
	if err != nil {
		t.Fatalf("canonicalHash: %v", err)
	}
	if first != second || len(first) != 64 {
		t.Fatalf("hash = %q / %q", first, second)
	}
	// The hash field itself must not influence the canonical hash.
	p.Hash = "ignored"
	third, err := canonicalHash(p)
	if err != nil {
		t.Fatalf("canonicalHash: %v", err)
	}
	if third != first {
		t.Error("hash field influenced the canonical hash")
	}
	// A time zone offset must not change the canonical hash.
	p.UpdatedAt = baseTime.In(time.FixedZone("CET", 3600))
	fourth, err := canonicalHash(p)
	if err != nil {
		t.Fatalf("canonicalHash: %v", err)
	}
	if fourth != first {
		t.Error("timestamp zone influenced the canonical hash")
	}
}

func TestConcurrentUpdates(t *testing.T) {
	manager, audit := newManager(t, t.TempDir(), newFakeClock(baseTime), nil)
	var wg sync.WaitGroup
	for worker := 0; worker < 10; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			next := manager.Current()
			next.DataQuality.TelemetryGapS = 600 + worker
			if _, err := manager.Update(next, "admin", "admin", fmt.Sprintf("worker %d", worker)); err != nil {
				t.Errorf("Update: %v", err)
			}
		}(worker)
	}
	wg.Wait()
	if got := manager.Count(); got != 11 {
		t.Fatalf("Count = %d, want 11", got)
	}
	versions := manager.Versions(20)
	for i := 1; i < len(versions); i++ {
		if versions[i-1].PrevHash != versions[i].Policy.Hash {
			t.Fatalf("version chain broken between %d and %d", versions[i].Policy.Version, versions[i-1].Policy.Version)
		}
	}
	entries, err := audit.List(context.Background(), 20)
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	if len(entries) != 10 {
		t.Errorf("audit entries = %d, want 10", len(entries))
	}
	if ok, _, verr := audit.Verify(context.Background()); verr != nil || !ok {
		t.Fatalf("audit chain = %v, %v", ok, verr)
	}
}

// openAudit opens a fresh audit log for the test.
func openAudit(t *testing.T, dir string, clock ports.Clock) *store.AuditLog {
	t.Helper()
	audit, err := store.OpenAuditLog(store.Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	t.Cleanup(func() {
		if cerr := audit.Close(); cerr != nil {
			t.Errorf("AuditLog.Close: %v", cerr)
		}
	})
	return audit
}

// jsonMarshal / jsonUnmarshal keep the test imports explicit.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func jsonUnmarshal(raw []byte, dst any) error { return json.Unmarshal(raw, dst) }

// indexOf returns the byte index of needle inside haystack.
func indexOf(haystack, needle []byte) int { return bytes.Index(haystack, needle) }
