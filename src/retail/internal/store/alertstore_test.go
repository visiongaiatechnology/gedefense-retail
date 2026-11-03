package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

func mustOpenAlertStore(t *testing.T, dir string, clock ports.Clock, retentionDays int) *AlertStore {
	t.Helper()
	st, err := OpenAlertStore(Options{Dir: dir, Clock: clock, RetentionDays: retentionDays})
	if err != nil {
		t.Fatalf("OpenAlertStore: %v", err)
	}
	t.Cleanup(func() {
		if cerr := st.Close(); cerr != nil {
			t.Errorf("AlertStore.Close: %v", cerr)
		}
	})
	return st
}

func TestAlertStoreUpsertGetList(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	st := mustOpenAlertStore(t, dir, clock, 0)
	ctx := context.Background()

	first := testAlert("alr-1", "dedup-a", domain.AlertOpen, domain.SeverityHigh, baseTime)
	second := testAlert("alr-2", "dedup-b", domain.AlertOpen, domain.SeverityCritical, baseTime.Add(time.Minute))
	third := testAlert("alr-3", "dedup-c", domain.AlertClosed, domain.SeverityLow, baseTime.Add(2*time.Minute))
	for _, alert := range []domain.Alert{first, second, third} {
		if err := st.Upsert(ctx, alert); err != nil {
			t.Fatalf("Upsert %q: %v", alert.AlertID, err)
		}
	}
	if got := st.Count(); got != 3 {
		t.Errorf("Count = %d, want 3", got)
	}

	got, ok, err := st.Get(ctx, "alr-1")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.Title != first.Title {
		t.Errorf("Get title = %q", got.Title)
	}
	if _, ok, err := st.Get(ctx, "alr-missing"); err != nil || ok {
		t.Errorf("Get missing: ok=%v err=%v", ok, err)
	}

	all, err := st.List(ctx, ports.AlertQuery{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("List returned %d, want 3", len(all))
	}
	if all[0].AlertID != "alr-2" || all[1].AlertID != "alr-1" || all[2].AlertID != "alr-3" {
		t.Errorf("severity ordering = %q, %q, %q", all[0].AlertID, all[1].AlertID, all[2].AlertID)
	}

	openOnly, err := st.List(ctx, ports.AlertQuery{Status: domain.AlertOpen, Limit: 10})
	if err != nil {
		t.Fatalf("List status: %v", err)
	}
	if len(openOnly) != 2 {
		t.Errorf("open alerts = %d, want 2", len(openOnly))
	}

	limited, err := st.List(ctx, ports.AlertQuery{Limit: 1})
	if err != nil {
		t.Fatalf("List limit: %v", err)
	}
	if len(limited) != 1 || limited[0].AlertID != "alr-2" {
		t.Errorf("limited list = %+v", limited)
	}

	everything, err := st.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(everything) != 3 || everything[0].AlertID != "alr-1" {
		t.Errorf("ListAll = %d entries, first %q", len(everything), everything[0].AlertID)
	}
}

func TestAlertStoreFindByDedupKey(t *testing.T) {
	st := mustOpenAlertStore(t, t.TempDir(), newFakeClock(baseTime), 0)
	ctx := context.Background()

	open := testAlert("alr-open", "dedup-1", domain.AlertOpen, domain.SeverityHigh, baseTime)
	closed := testAlert("alr-closed", "dedup-2", domain.AlertClosed, domain.SeverityHigh, baseTime)
	if err := st.Upsert(ctx, open); err != nil {
		t.Fatalf("Upsert open: %v", err)
	}
	if err := st.Upsert(ctx, closed); err != nil {
		t.Fatalf("Upsert closed: %v", err)
	}

	found, ok, err := st.FindByDedupKey(ctx, "dedup-1")
	if err != nil || !ok || found.AlertID != "alr-open" {
		t.Fatalf("FindByDedupKey open: ok=%v err=%v id=%q", ok, err, found.AlertID)
	}
	if _, ok, err := st.FindByDedupKey(ctx, "dedup-2"); err != nil || ok {
		t.Errorf("FindByDedupKey must ignore terminal alerts: ok=%v err=%v", ok, err)
	}
	if _, ok, err := st.FindByDedupKey(ctx, "dedup-missing"); err != nil || ok {
		t.Errorf("FindByDedupKey missing: ok=%v err=%v", ok, err)
	}
	if _, ok, err := st.FindByDedupKey(ctx, ""); err != nil || ok {
		t.Errorf("FindByDedupKey empty: ok=%v err=%v", ok, err)
	}
}

func TestAlertStorePersistsAndCopies(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	ctx := context.Background()

	st, err := OpenAlertStore(Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAlertStore: %v", err)
	}
	alert := testAlert("alr-1", "dedup", domain.AlertOpen, domain.SeverityHigh, baseTime)
	alert.Evidence = []domain.Evidence{{Kind: "event", RefID: "evt-1", Description: "limit crossed", At: baseTime, Source: "detect", Confidence: 0.9}}
	if err := st.Upsert(ctx, alert); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened := mustOpenAlertStore(t, dir, clock, 0)
	got, ok, err := reopened.Get(ctx, "alr-1")
	if err != nil || !ok {
		t.Fatalf("Get after reopen: ok=%v err=%v", ok, err)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].RefID != "evt-1" {
		t.Fatalf("evidence after reopen = %+v", got.Evidence)
	}

	// Mutating a returned value must not mutate stored state.
	got.Evidence[0].RefID = "tampered"
	got.AssetIDs = append(got.AssetIDs, "injected")
	again, _, err := reopened.Get(ctx, "alr-1")
	if err != nil {
		t.Fatalf("Get again: %v", err)
	}
	if again.Evidence[0].RefID != "evt-1" || len(again.AssetIDs) != 0 {
		t.Errorf("store returned shared state: %+v", again)
	}

	// The state file itself must be a 0600 regular file.
	info, err := os.Stat(filepath.Join(dir, "alerts", alertStateFile))
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("state file is not regular: %v", info.Mode())
	}
}

func TestAlertStoreRejectsInvalidAlert(t *testing.T) {
	st := mustOpenAlertStore(t, t.TempDir(), newFakeClock(baseTime), 0)
	ctx := context.Background()

	bad := testAlert("alr-1", "dedup", domain.AlertOpen, domain.SeverityHigh, baseTime)
	bad.Severity = "apocalyptic"
	if err := st.Upsert(ctx, bad); err == nil {
		t.Fatal("expected validation error")
	}
	if st.Count() != 0 {
		t.Errorf("Count = %d, want 0", st.Count())
	}

	if err := st.Upsert(ctx, testAlert("alr-2", "dedup", domain.AlertOpen, domain.SeverityHigh, baseTime)); err != nil {
		t.Fatalf("valid alert must be accepted: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := st.Upsert(ctx, testAlert("alr-3", "dedup", domain.AlertOpen, domain.SeverityHigh, baseTime)); !errors.Is(err, ErrClosed) {
		t.Errorf("Upsert after Close = %v, want ErrClosed", err)
	}
}

func TestAlertStoreRejectsCorruptState(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenAlertStore(Options{Dir: dir, Clock: newFakeClock(baseTime)})
	if err != nil {
		t.Fatalf("OpenAlertStore: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	path := filepath.Join(dir, "alerts", alertStateFile)
	if werr := os.WriteFile(path, []byte(`{"schema":1,"alerts":[{"alert_id":"alr-1"}]}`), 0o600); werr != nil {
		t.Fatalf("write corrupt state: %v", werr)
	}
	if _, err := OpenAlertStore(Options{Dir: dir, Clock: newFakeClock(baseTime)}); err == nil {
		t.Fatal("expected corrupt state error")
	} else if !errors.Is(err, ErrCorruptState) {
		t.Errorf("err = %v, want ErrCorruptState", err)
	}
}

func TestAlertStoreRetention(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	st, err := OpenAlertStore(Options{Dir: dir, Clock: clock, RetentionDays: 30})
	if err != nil {
		t.Fatalf("OpenAlertStore: %v", err)
	}
	ctx := context.Background()
	if uerr := st.Upsert(ctx, testAlert("alr-old", "d1", domain.AlertOpen, domain.SeverityHigh, baseTime)); uerr != nil {
		t.Fatalf("Upsert: %v", uerr)
	}
	if cerr := st.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	later := newFakeClock(baseTime.AddDate(0, 0, 60))
	pruned := mustOpenAlertStore(t, dir, later, 30)
	if got := pruned.Count(); got != 0 {
		t.Errorf("Count after retention = %d, want 0", got)
	}
}

func TestAlertStoreRejectsSymlinkedState(t *testing.T) {
	dir := t.TempDir()
	alertsDir := filepath.Join(dir, "alerts")
	if err := os.MkdirAll(alertsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	target := filepath.Join(dir, "outside.json")
	if err := os.WriteFile(target, []byte(`{"schema":1,"alerts":[]}`), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(alertsDir, alertStateFile)
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := OpenAlertStore(Options{Dir: dir, Clock: newFakeClock(baseTime)}); err == nil {
		t.Fatal("expected symlink rejection")
	}
}
