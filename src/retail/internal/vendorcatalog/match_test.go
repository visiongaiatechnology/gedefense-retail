package vendorcatalog

import (
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestMatchFamilyFromHostname(t *testing.T) {
	t.Parallel()
	catalog := Load(writeFixture(t, "", "", ""))
	family, ok := catalog.MatchFamily("Danfoss", "", "storeview-ak-sm-800.filiale.local")
	if !ok || family.ID != "danfoss_ak_sm_800" {
		t.Fatalf("match = %+v / %v", family, ok)
	}
	if family.LifecycleStatus() != domain.LifecycleEOL {
		t.Fatalf("lifecycle = %q", family.LifecycleStatus())
	}
	if !family.HasManagementUI() {
		t.Fatal("family should expose a management UI")
	}
}

func TestMatchFamilyFromModel(t *testing.T) {
	t.Parallel()
	catalog := Load(writeFixture(t, "", "", ""))
	family, ok := catalog.MatchFamily("", "AK-SM 800A", "")
	if !ok || family.ID != "danfoss_ak_sm_800a" {
		t.Fatalf("match = %+v / %v", family, ok)
	}
	if family.LifecycleStatus() != domain.LifecycleActive {
		t.Fatalf("lifecycle = %q", family.LifecycleStatus())
	}
}

func TestMatchFamilyRequiresFamilyEvidence(t *testing.T) {
	t.Parallel()
	catalog := Load(writeFixture(t, "", "", ""))
	cases := []struct{ vendor, model, hostname string }{
		{"", "", ""},
		{"Danfoss", "", ""},
		{"Carel", "unknown-model", "unknown-hostname"},
		{"Thermo King", "XYZ-1", ""},
	}
	for _, tc := range cases {
		if family, ok := catalog.MatchFamily(tc.vendor, tc.model, tc.hostname); ok {
			t.Fatalf("unexpected match for %+v: %+v", tc, family)
		}
	}
}

func TestMatchFamilyWithoutCatalog(t *testing.T) {
	t.Parallel()
	var catalog *Catalog
	if _, ok := catalog.MatchFamily("Danfoss", "AK-SM 800", ""); ok {
		t.Fatal("nil catalog must not match")
	}
	disabled := Load(filepathMissing(t))
	if _, ok := disabled.MatchFamily("Danfoss", "AK-SM 800", ""); ok {
		t.Fatal("disabled catalog must not match")
	}
}

func TestMatchFamilyPrefersCurrentLifecycleOnTie(t *testing.T) {
	t.Parallel()
	// Two families share the same name token; the active one must win.
	vendors := strings.Replace(fixtureVendors,
		`"name": "AK-SM 800A", "category": "store_supervisor"`,
		`"name": "AK-SM 800", "category": "store_supervisor"`, 1)
	catalog := Load(writeFixture(t, vendors, "", ""))
	family, ok := catalog.MatchFamily("", "AK-SM 800", "")
	if !ok {
		t.Fatal("expected a family match")
	}
	if family.LifecycleStatus() != domain.LifecycleActive {
		t.Fatalf("lifecycle = %q, want active", family.LifecycleStatus())
	}
}

func TestLifecycleMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		want domain.LifecycleStatus
	}{
		{"current", domain.LifecycleActive},
		{"legacy_but_supported", domain.LifecycleApproachingEOL},
		{"eol_2021_05", domain.LifecycleEOL},
		{"unknown", domain.LifecycleUnknown},
		{"", domain.LifecycleUnknown},
		{"something_else", domain.LifecycleUnknown},
	}
	for _, tc := range cases {
		family := DeviceFamily{Lifecycle: tc.raw}
		if got := family.LifecycleStatus(); got != tc.want {
			t.Fatalf("lifecycle %q = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestAdvisory(t *testing.T) {
	t.Parallel()
	catalog := Load(writeFixture(t, "", "", ""))
	if note, known := catalog.Advisory("modbus_tcp"); !known || note == "" {
		t.Fatalf("modbus advisory = %q / %v", note, known)
	}
	if note, known := catalog.Advisory("http"); !known || note == "" {
		t.Fatalf("http advisory = %q / %v", note, known)
	}
	if note, known := catalog.Advisory("bacnet_ip"); known || note == "" {
		t.Fatalf("undocumented protocol advisory = %q / %v", note, known)
	}
	// Only low-evidence surfaces must not be reported as known.
	lowOnly := strings.ReplaceAll(fixtureSurfaces, `"confidence": "high"`, `"confidence": "low"`)
	catalogLow := Load(writeFixture(t, "", lowOnly, ""))
	if note, known := catalogLow.Advisory("modbus_tcp"); known || !strings.Contains(note, "niedriger Evidence") {
		t.Fatalf("low evidence advisory = %q / %v", note, known)
	}
	var disabled *Catalog
	if note, known := disabled.Advisory("modbus_tcp"); known || note == "" {
		t.Fatalf("nil catalog advisory = %q / %v", note, known)
	}
	if note, known := Load(filepathMissing(t)).Advisory("modbus_tcp"); known || note == "" {
		t.Fatalf("missing catalog advisory = %q / %v", note, known)
	}
}

// filepathMissing returns a path that does not exist.
func filepathMissing(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/missing/vendors.json"
}
