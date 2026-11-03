package detect_test

import (
	"context"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestIntegrityChangeRule(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		setup   func(*fakeWorld)
		event   func() domain.Event
		want    bool
		wantSev domain.Severity
	}{
		{
			name: "unapproved change on critical asset is high",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
			},
			event: func() domain.Event {
				return integrityEvent(testAsset, domain.IntegrityMeta{Subject: "controller_parameters", Changed: true, Approved: false, SHA256: "abc123"}, baseTime)
			},
			want: true, wantSev: domain.SeverityHigh,
		},
		{
			name: "approved change inside maintenance window is normal",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.addWindow(maintenanceWindow("win-1", baseTime.Add(-10*time.Minute), baseTime.Add(20*time.Minute), testAsset))
			},
			event: func() domain.Event {
				return integrityEvent(testAsset, domain.IntegrityMeta{Subject: "controller_parameters", Changed: true, Approved: true, SHA256: "abc123"}, baseTime)
			},
			want: false,
		},
		{
			name: "approved change outside window is medium",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
			},
			event: func() domain.Event {
				return integrityEvent(testAsset, domain.IntegrityMeta{Subject: "controller_parameters", Changed: true, Approved: true, SHA256: "abc123"}, baseTime)
			},
			want: true, wantSev: domain.SeverityMedium,
		},
		{
			name: "unchanged state is not an alert",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
			},
			event: func() domain.Event {
				return integrityEvent(testAsset, domain.IntegrityMeta{Subject: "controller_parameters", Changed: false}, baseTime)
			},
			want: false,
		},
		{
			name: "unapproved change on non-critical asset is medium",
			setup: func(w *fakeWorld) {
				asset := assetFixture()
				asset.Criticality = domain.CriticalityMedium
				w.addAsset(asset)
			},
			event: func() domain.Event {
				return integrityEvent(testAsset, domain.IntegrityMeta{Subject: "controller_parameters", Changed: true, SHA256: "abc123"}, baseTime)
			},
			want: true, wantSev: domain.SeverityMedium,
		},
		{
			name: "config change without integrity metadata is advisory",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
			},
			event: func() domain.Event {
				return domain.Event{
					EventID: nextEventID(domain.EventConfigChange), Kind: domain.EventConfigChange,
					SiteID: testSite, ZoneID: testZone, AssetID: testAsset,
					ObservedAt: baseTime, ReceivedAt: baseTime, Source: "test.integrity",
					Collection: "operator_export", Confidence: 0.7,
					PayloadMeta: map[string]string{"change": "controller_parameters"},
				}
			},
			want: true, wantSev: domain.SeverityLow,
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
			if tc.want {
				alert := requireAlert(t, alerts, rules.IDIntegrityChange)
				if alert.Severity != tc.wantSev {
					t.Fatalf("expected %s, got %s", tc.wantSev, alert.Severity)
				}
				if alert.Category != domain.CategoryIntegrity {
					t.Fatalf("integrity change category must be integrity, got %s", alert.Category)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDIntegrityChange)
			}
			requireNoCritical(t, alerts)
		})
	}
}

func TestNewAssetRule(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		setup   func(*fakeWorld)
		event   func() domain.Event
		want    bool
		wantSev domain.Severity
	}{
		{
			name: "new critical OT asset is high",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
			},
			event: func() domain.Event {
				return assetSeen(testAsset, "10.0.0.5", "modbus_tcp", baseTime)
			},
			want: true, wantSev: domain.SeverityHigh,
		},
		{
			name: "previously observed asset is baseline",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.addEvent(assetSeen(testAsset, "10.0.0.5", "modbus_tcp", baseTime.Add(-time.Hour)))
			},
			event: func() domain.Event {
				return assetSeen(testAsset, "10.0.0.5", "modbus_tcp", baseTime)
			},
			want: false,
		},
		{
			name: "unknown asset speaking OT protocol is high",
			setup: func(w *fakeWorld) {
				// no asset record on purpose
			},
			event: func() domain.Event {
				return assetSeen("asset-unknown", "10.0.0.77", "modbus_tcp", baseTime)
			},
			want: true, wantSev: domain.SeverityHigh,
		},
		{
			name: "unknown asset without OT reference is medium",
			setup: func(w *fakeWorld) {
				// no asset record on purpose
			},
			event: func() domain.Event {
				return assetSeen("asset-unknown-2", "10.0.0.78", "http", baseTime)
			},
			want: true, wantSev: domain.SeverityMedium,
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
			if tc.want {
				alert := requireAlert(t, alerts, rules.IDDeviceNewAsset)
				if alert.Severity != tc.wantSev {
					t.Fatalf("expected %s, got %s", tc.wantSev, alert.Severity)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDDeviceNewAsset)
			}
			requireNoCritical(t, alerts)
		})
	}
}

func TestAssetLifecycleExposedRule(t *testing.T) {
	t.Parallel()
	eolAsset := func() domain.Asset {
		asset := assetFixture()
		asset.Lifecycle = domain.LifecycleEOL
		asset.LifecycleSource = "ot-catalog:test"
		return asset
	}
	switchAsset := func(zone domain.ZoneID) domain.Asset {
		return domain.Asset{
			AssetID: "asset-switch", SiteID: testSite, ZoneID: zone, Name: "Switch",
			Type: domain.AssetNetworkDevice, Criticality: domain.CriticalityMedium, Confidence: 0.8,
			NetworkIDs: []domain.NetworkIdentifier{{Kind: domain.NetIDIP, Value: "10.0.1.7", Source: "test", Confidence: 0.8}},
		}
	}
	cases := []struct {
		name     string
		setup    func(*fakeWorld)
		wantKind string
		wantSev  domain.Severity
	}{
		{
			name: "end-of-life supervisor advisory",
			setup: func(w *fakeWorld) {
				w.addAsset(eolAsset())
			},
			wantKind: "eol", wantSev: domain.SeverityLow,
		},
		{
			name: "management UI reachable from retail IT",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.addAsset(switchAsset("zone-retail-it"))
				w.addEvent(flow("10.0.1.7", "10.0.0.5", 443, "https", baseTime.Add(-5*time.Minute)))
			},
			wantKind: "management-ui-exposed", wantSev: domain.SeverityMedium,
		},
		{
			name: "management UI from management zone is intended",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.addAsset(switchAsset("zone-management"))
				w.addEvent(flow("10.0.1.7", "10.0.0.5", 443, "https", baseTime.Add(-5*time.Minute)))
			},
			wantKind: "", // no exposure alert
		},
		{
			name: "non-critical supervisor is not an advisory target",
			setup: func(w *fakeWorld) {
				asset := eolAsset()
				asset.Criticality = domain.CriticalityMedium
				w.addAsset(asset)
			},
			wantKind: "",
		},
		{
			name: "retired asset is ignored",
			setup: func(w *fakeWorld) {
				asset := eolAsset()
				asset.Retired = true
				w.addAsset(asset)
			},
			wantKind: "",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			world := newWorld()
			tc.setup(world)
			engine := newTestEngine(world)
			alerts := engine.EvaluateTick(context.Background())
			if tc.wantKind == "" {
				requireNoAlert(t, alerts, rules.IDAssetLifecycleExposed)
				return
			}
			matched := alertsFor(alerts, rules.IDAssetLifecycleExposed)
			if len(matched) == 0 {
				t.Fatalf("expected lifecycle advisory, got rules %v", ruleIDs(alerts))
			}
			var found domain.Alert
			for _, alert := range matched {
				if contains(tc.wantKind, string(alert.DedupKey)) {
					found = alert
					break
				}
			}
			if found.RuleID == "" {
				t.Fatalf("advisory with dedup kind %q not found in %+v", tc.wantKind, matched)
			}
			requireValidAlert(t, found)
			if found.Severity != tc.wantSev {
				t.Fatalf("expected %s, got %s", tc.wantSev, found.Severity)
			}
			if found.Category != domain.CategoryDeviceHealth {
				t.Fatalf("lifecycle advisory must be device_health, got %s", found.Category)
			}
		})
	}
}
