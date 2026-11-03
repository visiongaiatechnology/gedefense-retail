package state

import (
	"errors"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func testWindow(id string, startsAt, endsAt time.Time, status domain.MaintenanceWindowStatus) domain.MaintenanceWindow {
	return domain.MaintenanceWindow{
		WindowID:  domain.MaintenanceWindowID(id),
		SiteID:    "filiale-001",
		ZoneIDs:   []domain.ZoneID{"zone-ot"},
		Vendor:    "ServiceCo",
		StartsAt:  startsAt,
		EndsAt:    endsAt,
		Status:    status,
		CreatedBy: "admin",
		CreatedAt: startsAt,
	}
}

func TestWindowsLifecycle(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))

	if err := r.UpsertWindow(testWindow("win-1", baseTime, baseTime.Add(2*time.Hour), domain.WindowPlanned)); err != nil {
		t.Fatalf("UpsertWindow: %v", err)
	}
	if got := len(r.Windows("filiale-001")); got != 1 {
		t.Fatalf("Windows = %d, want 1", got)
	}
	window, ok := r.Window("win-1")
	if !ok || window.Vendor != "ServiceCo" {
		t.Fatalf("Window = %+v, %v", window, ok)
	}

	active := r.WindowsAt("filiale-001", baseTime.Add(time.Hour))
	if len(active) != 1 {
		t.Errorf("WindowsAt inside = %d, want 1", len(active))
	}
	if got := r.WindowsAt("filiale-001", baseTime.Add(3*time.Hour)); len(got) != 0 {
		t.Errorf("WindowsAt outside = %d, want 0", len(got))
	}

	closed, err := r.CloseWindow("win-1", "admin")
	if err != nil {
		t.Fatalf("CloseWindow: %v", err)
	}
	if closed.Status != domain.WindowClosed {
		t.Errorf("status = %q", closed.Status)
	}
	if _, err := r.CloseWindow("win-1", "admin"); !errors.Is(err, ErrConflict) {
		t.Errorf("second close = %v, want ErrConflict", err)
	}
	if _, err := r.CloseWindow("win-missing", "admin"); !errors.Is(err, ErrNotFound) {
		t.Errorf("close missing = %v, want ErrNotFound", err)
	}
	if _, err := r.CloseWindow("win-1", "bad id!"); err == nil {
		t.Error("invalid actor must be rejected")
	}
	// A closed window cannot be reopened by an upsert.
	if err := r.UpsertWindow(testWindow("win-1", baseTime, baseTime.Add(2*time.Hour), domain.WindowPlanned)); !errors.Is(err, ErrConflict) {
		t.Errorf("upsert closed window = %v, want ErrConflict", err)
	}
}

func TestUpsertWindowRejectsInvalid(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	invalid := testWindow("win-1", baseTime, baseTime.Add(-time.Hour), domain.WindowPlanned)
	if err := r.UpsertWindow(invalid); err == nil {
		t.Fatal("expected validation error for inverted window")
	}
	noVendor := testWindow("win-2", baseTime, baseTime.Add(time.Hour), "")
	noVendor.Vendor = ""
	if err := r.UpsertWindow(noVendor); err == nil {
		t.Fatal("expected validation error for missing vendor")
	}
	// An empty status defaults to planned.
	ok := testWindow("win-3", baseTime, baseTime.Add(time.Hour), "")
	if err := r.UpsertWindow(ok); err != nil {
		t.Fatalf("UpsertWindow with default status: %v", err)
	}
	window, _ := r.Window("win-3")
	if window.Status != domain.WindowPlanned {
		t.Errorf("default status = %q, want planned", window.Status)
	}
}

func testIncident(id string, at time.Time) domain.Incident {
	return domain.Incident{
		IncidentID:  domain.IncidentID(id),
		SiteID:      "filiale-001",
		Title:       "Possible thermal manipulation",
		Severity:    domain.SeverityCritical,
		Status:      domain.IncidentOpen,
		FirstSeenAt: at,
		LastSeenAt:  at,
		Summary:     "Three independent indicators matched within 30 minutes.",
		AlertIDs:    []domain.AlertID{"alr-1"},
		CreatedAt:   at,
		UpdatedAt:   at,
	}
}

func TestIncidentLifecycle(t *testing.T) {
	clock := newFakeClock(baseTime)
	r := newTestRegistry(t, clock)

	if err := r.UpsertIncident(testIncident("inc-1", baseTime)); err != nil {
		t.Fatalf("UpsertIncident: %v", err)
	}
	incident, ok := r.Incident("inc-1")
	if !ok || incident.Title != "Possible thermal manipulation" {
		t.Fatalf("Incident = %+v, %v", incident, ok)
	}
	if got := len(r.Incidents("filiale-001")); got != 1 {
		t.Errorf("Incidents = %d, want 1", got)
	}

	note := domain.IncidentNote{Actor: "operator-1", Role: "operator", Note: "Betreiber kontaktiert"}
	updated, err := r.AddIncidentNote("inc-1", note)
	if err != nil {
		t.Fatalf("AddIncidentNote: %v", err)
	}
	if len(updated.Notes) != 1 || !updated.Notes[0].At.Equal(baseTime) {
		t.Errorf("notes = %+v", updated.Notes)
	}
	if _, err := r.AddIncidentNote("inc-missing", note); !errors.Is(err, ErrNotFound) {
		t.Errorf("add note missing = %v, want ErrNotFound", err)
	}
	if _, err := r.AddIncidentNote("inc-1", domain.IncidentNote{Actor: "operator-1"}); !errors.Is(err, ErrInvalidNote) {
		t.Errorf("empty note = %v, want ErrInvalidNote", err)
	}
	if _, err := r.AddIncidentNote("inc-1", domain.IncidentNote{Note: "x"}); !errors.Is(err, ErrInvalidNote) {
		t.Errorf("missing actor = %v, want ErrInvalidNote", err)
	}
	if _, err := r.AddIncidentNote("inc-1", domain.IncidentNote{Actor: "operator-1", Note: string(make([]byte, maxNoteLength+1))}); !errors.Is(err, ErrInvalidNote) {
		t.Errorf("oversized note = %v, want ErrInvalidNote", err)
	}
}

func TestUpsertIncidentMergesWithoutLosingNotes(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	first := testIncident("inc-1", baseTime)
	if err := r.UpsertIncident(first); err != nil {
		t.Fatalf("UpsertIncident: %v", err)
	}
	if _, err := r.AddIncidentNote("inc-1", domain.IncidentNote{Actor: "operator-1", Role: "operator", Note: "first note"}); err != nil {
		t.Fatalf("AddIncidentNote: %v", err)
	}

	// A re-observation must not rewrite first-seen, creation time or notes.
	update := testIncident("inc-1", baseTime.Add(-time.Hour))
	update.LastSeenAt = baseTime.Add(30 * time.Minute)
	update.AlertIDs = []domain.AlertID{"alr-2"}
	if err := r.UpsertIncident(update); err != nil {
		t.Fatalf("UpsertIncident update: %v", err)
	}
	incident, _ := r.Incident("inc-1")
	if !incident.FirstSeenAt.Equal(baseTime.Add(-time.Hour)) {
		t.Errorf("FirstSeenAt = %v", incident.FirstSeenAt)
	}
	if len(incident.Notes) != 1 {
		t.Errorf("notes lost: %+v", incident.Notes)
	}
	if len(incident.AlertIDs) != 2 {
		t.Errorf("alert ids = %v", incident.AlertIDs)
	}
	if !incident.LastSeenAt.Equal(baseTime.Add(30 * time.Minute)) {
		t.Errorf("LastSeenAt = %v", incident.LastSeenAt)
	}

	invalid := testIncident("inc-bad", baseTime)
	invalid.Status = "unknown-status"
	if err := r.UpsertIncident(invalid); err == nil {
		t.Error("invalid incident must be rejected")
	}
}

func TestIncidentsSortedByActivity(t *testing.T) {
	r := newTestRegistry(t, newFakeClock(baseTime))
	older := testIncident("inc-1", baseTime)
	newer := testIncident("inc-2", baseTime.Add(time.Minute))
	newer.LastSeenAt = baseTime.Add(time.Hour)
	if err := r.UpsertIncident(older); err != nil {
		t.Fatalf("UpsertIncident: %v", err)
	}
	if err := r.UpsertIncident(newer); err != nil {
		t.Fatalf("UpsertIncident: %v", err)
	}
	incidents := r.Incidents("filiale-001")
	if len(incidents) != 2 || incidents[0].IncidentID != "inc-2" {
		t.Errorf("incident order = %+v", incidents)
	}
	if got := r.Incidents("filiale-999"); len(got) != 0 {
		t.Errorf("other site incidents = %d, want 0", len(got))
	}
}
