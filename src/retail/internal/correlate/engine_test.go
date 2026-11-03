package correlate_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/correlate"
	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestObserveBelowThreshold(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	engine := newTestEngine(world, baseTime)
	alerts := []domain.Alert{
		buildAlert(rules.IDAccessOffWindow, baseTime.Add(-5*time.Minute), domain.SeverityMedium, testAsset),
		buildAlert(rules.IDUnknownPeer, baseTime.Add(-4*time.Minute), domain.SeverityHigh, testAsset),
	}
	updates, incidents := engine.Observe(context.Background(), alerts)
	if len(updates) != 0 {
		t.Fatalf("two indicators must not escalate, got %d updates", len(updates))
	}
	requireNoIncidents(t, incidents)
}

func TestThermalManipulationChain(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	alerts := thermalTrail(baseTime)
	engine := newTestEngine(world, baseTime)
	updates, incidents := engine.Observe(context.Background(), alerts)
	if len(incidents) != 1 {
		t.Fatalf("expected exactly one incident, got %d", len(incidents))
	}
	incident := requireIncident(t, incidents, correlate.ChainThermalManipulation)
	if incident.Severity != domain.SeverityCritical {
		t.Fatalf("thermal manipulation chain must escalate to critical, got %s", incident.Severity)
	}
	if !strings.Contains(incident.Summary, "Beobachtete Fakten:") || !strings.Contains(incident.Summary, "Hypothese:") {
		t.Fatalf("incident summary must separate facts and hypothesis: %q", incident.Summary)
	}
	if !strings.Contains(incident.Summary, "Alternativerklärungen:") || !strings.Contains(incident.Summary, "Empfohlene Prüfungen:") {
		t.Fatalf("incident summary must list alternatives and checks: %q", incident.Summary)
	}
	if len(incident.AlertIDs) != 3 {
		t.Fatalf("expected 3 linked alerts, got %v", incident.AlertIDs)
	}
	if incident.Correlation.ChainID != correlate.ChainThermalManipulation {
		t.Fatalf("unexpected chain id %q", incident.Correlation.ChainID)
	}
	facts := strings.Join(incident.Correlation.ObservedFacts, " ")
	for _, ruleID := range []domain.RuleID{rules.IDAccessOffWindow, rules.IDThermalSetpoint, rules.IDThermalRate} {
		if !strings.Contains(facts, string(ruleID)) {
			t.Fatalf("fact list does not reference %q: %v", ruleID, incident.Correlation.ObservedFacts)
		}
	}
	if !strings.Contains(facts, "kein Wartungsfenster aktiv") {
		t.Fatalf("fact list does not document the missing maintenance window: %v", incident.Correlation.ObservedFacts)
	}
	if len(updates) != 3 {
		t.Fatalf("expected 3 alert updates, got %d", len(updates))
	}
	for _, update := range updates {
		if update.IncidentID != incident.IncidentID {
			t.Fatalf("update %q not linked to incident: %q", update.RuleID, update.IncidentID)
		}
		if update.Correlation == nil || update.Correlation.ChainID != correlate.ChainThermalManipulation {
			t.Fatalf("update %q has no chain correlation", update.RuleID)
		}
		if update.Severity != domain.SeverityCritical {
			t.Fatalf("update %q must be escalated to critical, got %s", update.RuleID, update.Severity)
		}
	}
	// The off-window access alert started at medium and must have been escalated.
	offWindow := requireUpdate(t, updates, rules.IDAccessOffWindow)
	if offWindow.Severity != domain.SeverityCritical {
		t.Fatalf("expected escalation to critical, got %s", offWindow.Severity)
	}
}

func TestThermalChainWindowFactWithActiveWindow(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	world.addWindow(windowFixture(baseTime.Add(-20*time.Minute), baseTime.Add(20*time.Minute)))
	engine := newTestEngine(world, baseTime)
	_, incidents := engine.Observe(context.Background(), thermalTrail(baseTime))
	incident := requireIncident(t, incidents, correlate.ChainThermalManipulation)
	facts := strings.Join(incident.Correlation.ObservedFacts, " ")
	if !strings.Contains(facts, "Aktive Wartungsfenster") {
		t.Fatalf("expected active-window fact, got %v", incident.Correlation.ObservedFacts)
	}
}

func TestRemoteIntrusionChain(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	alerts := []domain.Alert{
		buildAlert(rules.IDUnknownPeer, baseTime.Add(-10*time.Minute), domain.SeverityHigh, testAsset),
		buildAlert(rules.IDAccessManagementUI, baseTime.Add(-8*time.Minute), domain.SeverityHigh, testAsset),
		buildAlert(rules.IDDeviceNewAsset, baseTime.Add(-5*time.Minute), domain.SeverityHigh, testAsset),
	}
	engine := newTestEngine(world, baseTime)
	_, incidents := engine.Observe(context.Background(), alerts)
	incident := requireIncident(t, incidents, correlate.ChainRemoteIntrusion)
	if incident.Severity != domain.SeverityHigh {
		t.Fatalf("remote intrusion chain must stay high, got %s", incident.Severity)
	}
	if len(incidents) != 1 {
		t.Fatalf("expected only the remote-intrusion chain, got %d incidents", len(incidents))
	}
	alternatives := strings.Join(incident.Correlation.AlternativeExplanations, " ")
	if !strings.Contains(alternatives, "Firmware") {
		t.Fatalf("alternative explanations must mention firmware updates: %v", incident.Correlation.AlternativeExplanations)
	}
}

func TestSensorIntegrityChainNeverCritical(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	world.addSensor(sensorFixture())
	alerts := []domain.Alert{
		buildAlert(rules.IDDataQualityFrozen, baseTime.Add(-10*time.Minute), domain.SeverityMedium),
		buildAlert(rules.IDThermalSensorDivergence, baseTime.Add(-8*time.Minute), domain.SeverityMedium, testAsset),
		buildAlert(rules.IDDataQualityGap, baseTime.Add(-5*time.Minute), domain.SeverityMedium),
	}
	engine := newTestEngine(world, baseTime)
	updates, incidents := engine.Observe(context.Background(), alerts)
	incident := requireIncident(t, incidents, correlate.ChainSensorIntegrity)
	if incident.Severity == domain.SeverityCritical {
		t.Fatal("sensor integrity chain must not become critical")
	}
	if incident.Severity != domain.SeverityHigh {
		t.Fatalf("expected high severity, got %s", incident.Severity)
	}
	if len(updates) != 3 {
		t.Fatalf("expected 3 updates, got %d", len(updates))
	}
	for _, update := range updates {
		if update.Severity == domain.SeverityCritical {
			t.Fatalf("data-quality alert escalated to critical: %+v", update)
		}
	}
}

func TestIncidentDedupWithin24Hours(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	now := baseTime.Add(10 * time.Minute)
	engine := newTestEngine(world, now)

	_, incidents := engine.Observe(context.Background(), thermalTrail(baseTime))
	first := requireIncident(t, incidents, correlate.ChainThermalManipulation)
	world.addIncident(first) // simulate state.UpsertIncident from the pipeline

	// The same case observed again inside the 24 h window must update the same
	// incident instead of creating a duplicate.
	_, again := engine.Observe(context.Background(), thermalTrail(baseTime))
	if len(again) != 1 {
		t.Fatalf("expected one deduplicated incident, got %d", len(again))
	}
	if again[0].IncidentID != first.IncidentID {
		t.Fatalf("expected incident dedup, got %q vs %q", again[0].IncidentID, first.IncidentID)
	}
	if !again[0].UpdatedAt.Equal(now) {
		t.Fatalf("expected the deduplicated incident to be refreshed at %v, got %v", now, again[0].UpdatedAt)
	}
	if again[0].LastSeenAt.Before(first.LastSeenAt) {
		t.Fatalf("dedup must not shrink the incident timeline: %v < %v", again[0].LastSeenAt, first.LastSeenAt)
	}
	if again[0].Severity != domain.SeverityCritical {
		t.Fatalf("deduplicated incident must keep critical severity, got %s", again[0].Severity)
	}
}

func TestIncidentDedupWindowExpiresAfter24Hours(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	world.addIncident(existingIncident(correlate.ChainThermalManipulation, domain.IncidentOpen, baseTime.Add(-25*time.Hour)))
	engine := newTestEngine(world, baseTime)
	_, incidents := engine.Observe(context.Background(), thermalTrail(baseTime))
	incident := requireIncident(t, incidents, correlate.ChainThermalManipulation)
	if incident.IncidentID == "inc_existing" {
		t.Fatal("an incident older than 24 h must not be reused")
	}
}

func TestClosedIncidentIsNotReopened(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	world.addIncident(existingIncident(correlate.ChainThermalManipulation, domain.IncidentClosed, baseTime.Add(-time.Hour)))
	engine := newTestEngine(world, baseTime)
	_, incidents := engine.Observe(context.Background(), thermalTrail(baseTime))
	incident := requireIncident(t, incidents, correlate.ChainThermalManipulation)
	if incident.IncidentID == "inc_existing" {
		t.Fatal("a closed incident must not be reopened/merged")
	}
	if incident.Status != domain.IncidentOpen {
		t.Fatalf("recurrence must create a new open case, got %s", incident.Status)
	}
}

func TestEscalationOnlyIncreases(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	alerts := []domain.Alert{
		buildAlert(rules.IDAccessOffWindow, baseTime.Add(-10*time.Minute), domain.SeverityCritical, testAsset),
		buildAlert(rules.IDThermalSetpoint, baseTime.Add(-8*time.Minute), domain.SeverityLow, testAsset),
		buildAlert(rules.IDThermalRate, baseTime.Add(-5*time.Minute), domain.SeverityHigh, testAsset),
	}
	engine := newTestEngine(world, baseTime)
	updates, incidents := engine.Observe(context.Background(), alerts)
	requireIncident(t, incidents, correlate.ChainThermalManipulation)
	offWindow := requireUpdate(t, updates, rules.IDAccessOffWindow)
	if offWindow.Severity != domain.SeverityCritical {
		t.Fatalf("severity must never be lowered, got %s", offWindow.Severity)
	}
	low := requireUpdate(t, updates, rules.IDThermalSetpoint)
	if low.Severity != domain.SeverityCritical {
		t.Fatalf("expected escalation of low severity, got %s", low.Severity)
	}
}

func TestOldChainIsNotResurrected(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	engine := newTestEngine(world, baseTime)
	alerts := []domain.Alert{
		buildAlert(rules.IDAccessOffWindow, baseTime.Add(-90*time.Minute), domain.SeverityMedium, testAsset),
		buildAlert(rules.IDThermalSetpoint, baseTime.Add(-80*time.Minute), domain.SeverityHigh, testAsset),
		buildAlert(rules.IDThermalRate, baseTime.Add(-70*time.Minute), domain.SeverityHigh, testAsset),
	}
	updates, incidents := engine.Observe(context.Background(), alerts)
	requireNoIncidents(t, incidents)
	if len(updates) != 0 {
		t.Fatalf("old chain must not be escalated, got %d updates", len(updates))
	}
}

func TestObserveNilAndCanceledContext(t *testing.T) {
	t.Parallel()
	alerts := thermalTrail(baseTime)

	engine := correlate.NewEngine(nil, nil)
	updates, incidents := engine.Observe(context.Background(), alerts)
	if updates != nil || incidents != nil {
		t.Fatal("nil world must be inert")
	}

	world := newWorld()
	engine = newTestEngine(world, baseTime)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	updates, incidents = engine.Observe(ctx, alerts)
	if updates != nil || incidents != nil {
		t.Fatal("canceled context must stop correlation")
	}

	var zero *correlate.Engine
	updates, incidents = zero.Observe(context.Background(), alerts)
	if updates != nil || incidents != nil {
		t.Fatal("nil engine must be inert")
	}
}

func TestConcurrentObserve(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	engine := newTestEngine(world, baseTime)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allIncidents []domain.Incident
	var allUpdates []domain.Alert
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(offset time.Duration) {
			defer wg.Done()
			alerts := thermalTrail(baseTime.Add(offset))
			updates, incidents := engine.Observe(context.Background(), alerts)
			mu.Lock()
			allUpdates = append(allUpdates, updates...)
			allIncidents = append(allIncidents, incidents...)
			mu.Unlock()
		}(time.Duration(i) * time.Minute)
	}
	wg.Wait()
	for _, incident := range allIncidents {
		if err := incident.Validate(); err != nil {
			t.Fatalf("invalid incident from concurrent observation: %v", err)
		}
	}
	for _, update := range allUpdates {
		if update.IncidentID == "" {
			t.Fatalf("update without incident link: %+v", update)
		}
	}
	if len(allIncidents) == 0 {
		t.Fatal("expected at least one incident from concurrent observation")
	}
}

func TestAlertsWithoutSiteOrRuleAreIgnored(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(newWorld(), baseTime)
	alerts := []domain.Alert{
		{RuleID: rules.IDThermalRate},
		{SiteID: testSite},
		{SiteID: testSite, RuleID: rules.IDThermalRate, FirstSeenAt: baseTime, LastSeenAt: baseTime},
	}
	updates, incidents := engine.Observe(context.Background(), alerts)
	if len(updates) != 0 {
		t.Fatalf("incomplete alerts must be ignored, got %d updates", len(updates))
	}
	requireNoIncidents(t, incidents)
}

func TestIncidentReferencesAlerts(t *testing.T) {
	t.Parallel()
	world := newWorld()
	world.addAsset(assetFixture())
	alerts := thermalTrail(baseTime)
	engine := newTestEngine(world, baseTime)
	updates, incidents := engine.Observe(context.Background(), alerts)
	incident := requireIncident(t, incidents, correlate.ChainThermalManipulation)
	linked := make(map[domain.AlertID]bool, len(incident.AlertIDs))
	for _, id := range incident.AlertIDs {
		linked[id] = true
	}
	for _, update := range updates {
		if !linked[update.AlertID] {
			t.Fatalf("updated alert %q is not referenced by the incident", update.AlertID)
		}
	}
	if len(alertIDs(alerts)) != len(updates) {
		t.Fatalf("expected every matched alert to be updated: %d vs %d", len(alerts), len(updates))
	}
}
