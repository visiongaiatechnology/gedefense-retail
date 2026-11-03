package rules_test

import (
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/retail/internal/detect/rules"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestDedupKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		id    domain.RuleID
		parts []string
		want  string
	}{
		{
			name:  "stable dimensions are joined with a separator",
			id:    rules.IDUnknownPeer,
			parts: []string{"filiale-001", "10.0.1.7", "10.0.0.5", "modbus_tcp"},
			want:  "retail.net.unknown-peer|filiale-001|10.0.1.7|10.0.0.5|modbus_tcp",
		},
		{
			name:  "unsafe characters are sanitised",
			id:    rules.IDAccessOffWindow,
			parts: []string{"site 1", "vendor|injected", "10.0.0.5; drop"},
			want:  "retail.access.off-window|site_1|vendor_injected|10.0.0.5__drop",
		},
		{
			name:  "empty parts are skipped",
			id:    rules.IDDataQualityGap,
			parts: []string{"", "filiale-001", "", "sensor-1"},
			want:  "retail.dq.gap|filiale-001|sensor-1",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := rules.DedupKey(tc.id, tc.parts...); got != tc.want {
				t.Fatalf("DedupKey() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDedupKeyBounds(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 500)
	key := rules.DedupKey(rules.IDThermalLimit, long, long, long, long, long)
	if len(key) > 256 {
		t.Fatalf("dedup key longer than 256 bytes: %d", len(key))
	}
	if !strings.HasPrefix(key, string(rules.IDThermalLimit)+"|") {
		t.Fatalf("dedup key does not start with the rule id: %q", key)
	}
}

func TestAllReturnsCompleteDefensiveCatalogue(t *testing.T) {
	t.Parallel()
	first := rules.All()
	if len(first) != 15 {
		t.Fatalf("expected 15 rules, got %d", len(first))
	}
	seen := make(map[domain.RuleID]bool, len(first))
	previous := domain.RuleID("")
	for _, spec := range first {
		if spec.ID == "" {
			t.Fatal("rule with empty id")
		}
		if seen[spec.ID] {
			t.Fatalf("duplicate rule %q", spec.ID)
		}
		seen[spec.ID] = true
		if previous != "" && spec.ID < previous {
			t.Fatalf("catalogue not sorted: %q after %q", spec.ID, previous)
		}
		previous = spec.ID
		if spec.Version != "1" {
			t.Fatalf("rule %q: version = %q, want 1", spec.ID, spec.Version)
		}
		if spec.Name == "" || spec.Category == "" || spec.Description == "" {
			t.Fatalf("rule %q: missing identity/description", spec.ID)
		}
		if !spec.Category.Valid() {
			t.Fatalf("rule %q: invalid category %q", spec.ID, spec.Category)
		}
		if spec.Baseline == "" || spec.Confidence == "" {
			t.Fatalf("rule %q: missing baseline/confidence documentation", spec.ID)
		}
		if !strings.HasPrefix(spec.DedupKeyTemplate, string(spec.ID)) {
			t.Fatalf("rule %q: dedup template does not start with the id: %q", spec.ID, spec.DedupKeyTemplate)
		}
		if len(spec.SeverityMatrix) == 0 {
			t.Fatalf("rule %q: empty severity matrix", spec.ID)
		}
		if len(spec.SafetyConstraints) == 0 {
			t.Fatalf("rule %q: missing safety constraints", spec.ID)
		}
		if !strings.Contains(strings.Join(spec.SafetyConstraints, " "), "passiv") {
			t.Fatalf("rule %q: safety constraints do not declare the passive product invariant", spec.ID)
		}
		if len(spec.RecommendedActions) == 0 {
			t.Fatalf("rule %q: missing recommended actions", spec.ID)
		}
		for _, action := range spec.RecommendedActions {
			if action.Action == "" {
				t.Fatalf("rule %q: empty recommended action", spec.ID)
			}
			if action.RequiresApproval && action.SafetyNote == "" {
				t.Fatalf("rule %q: approval action %q has no safety note", spec.ID, action.Action)
			}
		}
		if len(spec.FalsePositiveBoundaries) == 0 {
			t.Fatalf("rule %q: missing false-positive boundaries", spec.ID)
		}
	}
	// Mutating the returned slice must not change the catalogue.
	first[0].Name = "mutated"
	first[0].SafetyConstraints[0] = "mutated"
	second := rules.All()
	if second[0].Name == "mutated" || second[0].SafetyConstraints[0] == "mutated" {
		t.Fatal("All() must return a defensive copy")
	}
}

func TestByID(t *testing.T) {
	t.Parallel()
	spec, ok := rules.ByID(rules.IDAccessManagementUI)
	if !ok {
		t.Fatal("management-UI rule must be part of the pack")
	}
	if spec.ID != rules.IDAccessManagementUI {
		t.Fatalf("unexpected rule: %q", spec.ID)
	}
	if spec.Category != domain.CategoryAccess {
		t.Fatalf("management-UI rule must be category access, got %q", spec.Category)
	}
	if _, ok := rules.ByID(domain.RuleID("retail.does.not-exist")); ok {
		t.Fatal("unknown rule must not resolve")
	}
}

func TestRuleVersionIsStable(t *testing.T) {
	t.Parallel()
	if rules.Version != "1" {
		t.Fatalf("rule pack version = %q, want 1", rules.Version)
	}
	for _, spec := range rules.All() {
		if spec.Version != rules.Version {
			t.Fatalf("rule %q version %q differs from pack version %q", spec.ID, spec.Version, rules.Version)
		}
	}
}
