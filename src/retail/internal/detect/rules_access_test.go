package detect_test

import (
	"context"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestOffWindowAccessRule(t *testing.T) {
	t.Parallel()
	target := domain.AccessMeta{Vendor: "FremdService", Method: "vpn", TargetAsset: testAsset}
	cases := []struct {
		name      string
		setup     func(*fakeWorld)
		access    domain.AccessMeta
		wantAlert bool
		severity  domain.Severity
	}{
		{
			name:      "access without any window",
			setup:     func(w *fakeWorld) { w.addAsset(assetFixture()) },
			access:    target,
			wantAlert: true,
			severity:  domain.SeverityHigh,
		},
		{
			name: "approved window covers access",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.addWindow(maintenanceWindow("win-1", baseTime.Add(-10*time.Minute), baseTime.Add(20*time.Minute), testAsset))
			},
			access:    target,
			wantAlert: false,
		},
		{
			name: "grace period tolerates late session",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.setPolicy(func(p *domain.Policy) { p.Maintenance.GracePeriodS = 300 })
				w.addWindow(maintenanceWindow("win-1", baseTime.Add(-20*time.Minute), baseTime.Add(-2*time.Minute), testAsset))
			},
			access:    target,
			wantAlert: false,
		},
		{
			name: "policy without window requirement is medium",
			setup: func(w *fakeWorld) {
				asset := assetFixture()
				asset.Criticality = domain.CriticalityMedium
				w.addAsset(asset)
				w.setPolicy(func(p *domain.Policy) { p.Maintenance.RequireWindow = false })
			},
			access:    target,
			wantAlert: true,
			severity:  domain.SeverityMedium,
		},
		{
			name: "claimed window that does not cover the access is high",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.addWindow(maintenanceWindow("win-active", baseTime.Add(-10*time.Minute), baseTime.Add(20*time.Minute), testAsset))
			},
			access: func() domain.AccessMeta {
				claimed := target
				claimed.WindowID = "win-other"
				return claimed
			}(),
			wantAlert: true,
			severity:  domain.SeverityHigh,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			world := newWorld()
			tc.setup(world)
			engine := newTestEngine(world)
			alerts := engine.EvaluateEvent(context.Background(), accessEvent(tc.access, baseTime))
			if tc.wantAlert {
				alert := requireAlert(t, alerts, rules.IDAccessOffWindow)
				if alert.Severity != tc.severity {
					t.Fatalf("expected severity %s, got %s", tc.severity, alert.Severity)
				}
				if alert.Category != domain.CategoryAccess {
					t.Fatalf("off-window category must be access, got %s", alert.Category)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDAccessOffWindow)
			}
			requireNoCritical(t, alerts)
		})
	}
}

func TestUntrustedVendorRule(t *testing.T) {
	t.Parallel()
	accessFor := func(vendor string) domain.AccessMeta {
		return domain.AccessMeta{Vendor: vendor, Method: "vpn", TargetAsset: testAsset}
	}
	cases := []struct {
		name      string
		setup     func(*fakeWorld)
		access    domain.AccessMeta
		wantAlert bool
		severity  domain.Severity
	}{
		{
			name: "trusted vendor does not alert",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.setPolicy(func(p *domain.Policy) { p.Maintenance.TrustedVendors = []string{"Kältetechnik Müller"} })
			},
			access:    accessFor("Kältetechnik Müller"),
			wantAlert: false,
		},
		{
			name: "untrusted vendor with configured trust baseline",
			setup: func(w *fakeWorld) {
				asset := assetFixture()
				asset.Criticality = domain.CriticalityMedium
				w.addAsset(asset)
				w.setPolicy(func(p *domain.Policy) { p.Maintenance.TrustedVendors = []string{"Kältetechnik Müller"} })
			},
			access:    accessFor("FremdService"),
			wantAlert: true,
			severity:  domain.SeverityMedium,
		},
		{
			name: "vendor mismatch with active window",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.addWindow(maintenanceWindow("win-1", baseTime.Add(-10*time.Minute), baseTime.Add(20*time.Minute), testAsset))
			},
			access:    accessFor("FremdService"),
			wantAlert: true,
			severity:  domain.SeverityHigh,
		},
		{
			name: "no trust baseline and no window: off-window rule owns the case",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
			},
			access:    accessFor("FremdService"),
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
			alerts := engine.EvaluateEvent(context.Background(), accessEvent(tc.access, baseTime))
			if tc.wantAlert {
				alert := requireAlert(t, alerts, rules.IDAccessUntrustedVendor)
				if alert.Severity != tc.severity {
					t.Fatalf("expected severity %s, got %s", tc.severity, alert.Severity)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDAccessUntrustedVendor)
			}
		})
	}
	// Empty vendor claim cannot be judged.
	world := newWorld()
	world.addAsset(assetFixture())
	engine := newTestEngine(world)
	alerts := engine.EvaluateEvent(context.Background(), accessEvent(domain.AccessMeta{Method: "vpn", TargetAsset: testAsset}, baseTime))
	requireNoAlert(t, alerts, rules.IDAccessUntrustedVendor)
}

func TestManagementUIAccessRule(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		setup     func(*fakeWorld)
		event     func() domain.Event
		wantAlert bool
		severity  domain.Severity
	}{
		{
			name: "unknown source outside window on critical supervisor",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
			},
			event:     func() domain.Event { return flow("10.0.1.7", "10.0.0.5", 443, "https", baseTime) },
			wantAlert: true,
			severity:  domain.SeverityHigh,
		},
		{
			name: "unknown source inside approved window",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.addWindow(maintenanceWindow("win-1", baseTime.Add(-10*time.Minute), baseTime.Add(20*time.Minute), testAsset))
			},
			event:     func() domain.Event { return flow("10.0.1.7", "10.0.0.5", 443, "https", baseTime) },
			wantAlert: true,
			severity:  domain.SeverityMedium,
		},
		{
			name: "known source inside approved window is low",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
				w.addWindow(maintenanceWindow("win-1", baseTime.Add(-10*time.Minute), baseTime.Add(20*time.Minute), testAsset))
				w.addEvent(flow("10.0.1.7", "10.0.0.5", 443, "https", baseTime.Add(-5*time.Minute)))
			},
			event:     func() domain.Event { return flow("10.0.1.7", "10.0.0.5", 443, "https", baseTime) },
			wantAlert: true,
			severity:  domain.SeverityLow,
		},
		{
			name: "non-supervisor target is not judged",
			setup: func(w *fakeWorld) {
				w.addAsset(domain.Asset{
					AssetID: "asset-switch", SiteID: testSite, ZoneID: "zone-retail-it", Name: "Switch",
					Type: domain.AssetNetworkDevice, Criticality: domain.CriticalityMedium, Confidence: 0.7,
					NetworkIDs: []domain.NetworkIdentifier{{Kind: domain.NetIDIP, Value: "10.0.0.9", Source: "test", Confidence: 0.7}},
				})
			},
			event:     func() domain.Event { return flow("10.0.1.7", "10.0.0.9", 443, "https", baseTime) },
			wantAlert: false,
		},
		{
			name: "modbus flow is not a management UI access",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
			},
			event:     func() domain.Event { return flow("10.0.1.7", "10.0.0.5", 502, "modbus_tcp", baseTime) },
			wantAlert: false,
		},
		{
			name: "unknown target asset is not judged",
			setup: func(w *fakeWorld) {
				w.addAsset(assetFixture())
			},
			event:     func() domain.Event { return flow("10.0.1.7", "10.0.9.9", 443, "https", baseTime) },
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
				alert := requireAlert(t, alerts, rules.IDAccessManagementUI)
				if alert.Severity != tc.severity {
					t.Fatalf("expected severity %s, got %s", tc.severity, alert.Severity)
				}
				if alert.Category != domain.CategoryAccess {
					t.Fatalf("management-ui category must be access, got %s", alert.Category)
				}
				if len(alert.AssetIDs) == 0 || alert.AssetIDs[0] != testAsset {
					t.Fatalf("management-ui alert must reference the target asset: %v", alert.AssetIDs)
				}
			} else {
				requireNoAlert(t, alerts, rules.IDAccessManagementUI)
			}
			requireNoCritical(t, alerts)
		})
	}
}
