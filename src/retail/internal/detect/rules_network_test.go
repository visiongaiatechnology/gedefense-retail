package detect_test

import (
	"context"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestUnknownPeerRule(t *testing.T) {
	t.Parallel()
	type testCase struct {
		name         string
		setup        func(*fakeWorld)
		event        func() domain.Event
		wantAlert    bool
		wantSeverity domain.Severity
	}
	baselineRequired := func(w *fakeWorld) {
		w.setPolicy(func(p *domain.Policy) {
			p.Network.BaselineRequired = true
			p.Network.UnknownPeerGraceS = 0
		})
		w.addAsset(assetFixture())
	}
	cases := []testCase{
		{
			name:      "baseline required and OT target critical",
			setup:     baselineRequired,
			event:     func() domain.Event { return flow("10.0.1.7", "10.0.0.5", 502, "modbus_tcp", baseTime) },
			wantAlert: true, wantSeverity: domain.SeverityHigh,
		},
		{
			name: "observe-first onboarding does not alert",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
			},
			event:     func() domain.Event { return flow("10.0.1.7", "10.0.0.5", 502, "modbus_tcp", baseTime) },
			wantAlert: false,
		},
		{
			name: "previously observed pair is baseline",
			setup: func(w *fakeWorld) {
				baselineRequired(w)
				w.addEvent(flow("10.0.1.7", "10.0.0.5", 502, "modbus_tcp", baseTime.Add(-2*time.Minute)))
			},
			event:     func() domain.Event { return flow("10.0.1.7", "10.0.0.5", 502, "modbus_tcp", baseTime) },
			wantAlert: false,
		},
		{
			name: "onboarding grace suppresses unknown peer",
			setup: func(w *fakeWorld) {
				baselineRequired(w)
				w.setPolicy(func(p *domain.Policy) { p.Network.UnknownPeerGraceS = 3600 })
			},
			event:     func() domain.Event { return flow("10.0.1.7", "10.0.0.5", 502, "modbus_tcp", baseTime) },
			wantAlert: false,
		},
		{
			name: "monitored ports exclude non-OT flow",
			setup: func(w *fakeWorld) {
				baselineRequired(w)
				w.setPolicy(func(p *domain.Policy) { p.Network.MonitoredPorts = []int{502} })
			},
			event:     func() domain.Event { return flow("10.0.1.7", "10.0.0.5", 9999, "http", baseTime) },
			wantAlert: false,
		},
		{
			name: "explicitly allowed pair is baseline",
			setup: func(w *fakeWorld) {
				baselineRequired(w)
				w.setPolicy(func(p *domain.Policy) {
					p.Network.AllowedPairs = []domain.AllowedPair{{TargetAssetID: testAsset, Protocol: "modbus_tcp", Port: 502}}
				})
			},
			event: func() domain.Event {
				ev := flow("10.0.1.7", "10.0.0.5", 502, "modbus_tcp", baseTime)
				ev.AssetID = testAsset
				return ev
			},
			wantAlert: false,
		},
		{
			name: "incomplete flow metadata is not judged",
			setup: func(w *fakeWorld) {
				baselineRequired(w)
			},
			event:     func() domain.Event { return flow("", "10.0.0.5", 502, "modbus_tcp", baseTime) },
			wantAlert: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			world := newWorld()
			tc.setup(world)
			engine := newTestEngine(world)
			alerts := engine.EvaluateEvent(context.Background(), tc.event())
			if tc.wantAlert {
				alert := requireAlert(t, alerts, rules.IDUnknownPeer)
				if alert.Severity != tc.wantSeverity {
					t.Fatalf("expected severity %s, got %s", tc.wantSeverity, alert.Severity)
				}
				if len(alert.SensorIDs) != 0 {
					t.Fatalf("unknown-peer alert must not claim sensors: %v", alert.SensorIDs)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDUnknownPeer)
			}
			requireNoCritical(t, alerts)
		})
	}
}

func TestWriteAttemptRule(t *testing.T) {
	t.Parallel()
	type testCase struct {
		name      string
		setup     func(*fakeWorld)
		attempt   func() domain.Event
		wantAlert bool
	}
	cases := []testCase{
		{
			name:  "write attempt without maintenance window",
			setup: func(w *fakeWorld) { w.addAsset(assetFixture()) },
			attempt: func() domain.Event {
				return writeAttempt(domain.WriteAttempt{Protocol: "modbus_tcp", Source: "10.0.1.7", Target: "10.0.0.5", Function: "fc6_write_single_register", Register: "40001", Allowed: false}, baseTime)
			},
			wantAlert: true,
		},
		{
			name: "approved write inside maintenance window is normal",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.addWindow(maintenanceWindow("win-1", baseTime.Add(-10*time.Minute), baseTime.Add(20*time.Minute), testAsset))
			},
			attempt: func() domain.Event {
				ev := writeAttempt(domain.WriteAttempt{Protocol: "modbus_tcp", Source: "10.0.1.7", Target: "10.0.0.5", Function: "fc6_write_single_register", Register: "40001", Allowed: true}, baseTime)
				ev.AssetID = testAsset
				return ev
			},
			wantAlert: false,
		},
		{
			name:  "allowed write outside window is still high",
			setup: func(w *fakeWorld) { w.addAsset(assetFixture()) },
			attempt: func() domain.Event {
				ev := writeAttempt(domain.WriteAttempt{Protocol: "modbus_tcp", Source: "10.0.1.7", Target: "10.0.0.5", Function: "fc6_write_single_register", Register: "40001", Allowed: true}, baseTime)
				ev.AssetID = testAsset
				return ev
			},
			wantAlert: true,
		},
		{
			name: "explicitly disallowed write inside window is high",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.addWindow(maintenanceWindow("win-1", baseTime.Add(-10*time.Minute), baseTime.Add(20*time.Minute), testAsset))
			},
			attempt: func() domain.Event {
				ev := writeAttempt(domain.WriteAttempt{Protocol: "modbus_tcp", Source: "10.0.1.7", Target: "10.0.0.5", Function: "fc6_write_single_register", Register: "40001", Allowed: false}, baseTime)
				ev.AssetID = testAsset
				return ev
			},
			wantAlert: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			world := newWorld()
			tc.setup(world)
			engine := newTestEngine(world)
			alerts := engine.EvaluateEvent(context.Background(), tc.attempt())
			if tc.wantAlert {
				alert := requireAlert(t, alerts, rules.IDWriteAttempt)
				if alert.Severity != domain.SeverityHigh {
					t.Fatalf("write attempt must be high priority, got %s", alert.Severity)
				}
				if alert.Category != domain.CategoryNetwork {
					t.Fatalf("write attempt category must be network, got %s", alert.Category)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDWriteAttempt)
			}
			requireNoCritical(t, alerts)
		})
	}
}
