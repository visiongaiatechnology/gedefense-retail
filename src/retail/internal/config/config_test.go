package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

const validConfigJSON = `{
  "listen": "127.0.0.1:18080",
  "data_dir": "./var/lib/test",
  "log_level": "debug",
  "site": {
    "site_id": "filiale-001",
    "name": "Markt Nord",
    "country": "DE",
    "timezone": "Europe/Berlin",
    "zones": [
      {"zone_id": "zone-ot", "site_id": "filiale-001", "name": "OT", "kind": "ot_process", "critical": true}
    ]
  },
  "users": [
    {"user_id": "admin", "name": "Admin", "role": "admin", "token_sha256": %s},
    {"user_id": "tech", "name": "Technik", "role": "operator", "token_sha256": %s}
  ],
  "collectors": [
    {"adapter_id": "modbus.pool1", "enabled": true, "zone_id": "zone-ot", "options": {"address": "10.0.0.5:502"}}
  ],
  "central": {"url": "https://central.example.invalid:8443/api", "timeout_s": 15, "batch_size": 50, "spool_max_mb": 256},
  "simulation": {"enabled": true}
}`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "retail.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func mustTime() time.Time { return time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC) }

func TestLoadValidConfiguration(t *testing.T) {
	body := strings.Replace(validConfigJSON, "%s", `"`+tokenHash("admin-token-0123456789")+`"`, 1)
	body = strings.Replace(body, "%s", `"`+tokenHash("tech-token-0123456789")+`"`, 1)
	path := writeConfig(t, body)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:18080" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.Site.SiteID != domain.SiteID("filiale-001") {
		t.Errorf("site id = %q", cfg.Site.SiteID)
	}
	if len(cfg.Users) != 2 || !cfg.Users[0].Role.Allows(RoleAdmin) {
		t.Fatalf("users = %+v", cfg.Users)
	}
	if cfg.Users[0].TokenSHA256 != tokenHash("admin-token-0123456789") {
		t.Errorf("token hash not normalised: %q", cfg.Users[0].TokenSHA256)
	}
	if cfg.Central == nil || cfg.Central.TimeoutS != 15 {
		t.Errorf("central = %+v", cfg.Central)
	}
	if !cfg.SimulationEnabled() {
		t.Error("simulation should be enabled")
	}
	if cfg.EffectiveDataDir() == "" {
		t.Error("effective data dir is empty")
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	body := `{
	  "site": {"site_id": "filiale-002", "name": "Markt Sued", "zones": []},
	  "users": [{"user_id": "admin", "role": "admin", "token_sha256": "` + tokenHash("tok-1") + `"}]
	}`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != DefaultListen {
		t.Errorf("listen default = %q", cfg.Listen)
	}
	if cfg.DataDir != DefaultDataDir {
		t.Errorf("data_dir default = %q", cfg.DataDir)
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("log_level default = %q", cfg.LogLevel)
	}
	if cfg.Site.Status != domain.SiteUnknown {
		t.Errorf("site status default = %q", cfg.Site.Status)
	}
	if cfg.Users[0].Name != "admin" {
		t.Errorf("user name default = %q", cfg.Users[0].Name)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	body := `{"listen": "127.0.0.1:8080", "site": {"site_id": "s1", "name": "n", "zones": []},
	  "users": [{"user_id": "admin", "role": "admin", "token_sha256": "` + tokenHash("tok-2") + `"}],
	  "dangerous_unknown": true}`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
	if !errors.Is(err, ErrUnknownField) {
		t.Errorf("error = %v, want ErrUnknownField", err)
	}
}

func TestLoadRejectsTrailingContent(t *testing.T) {
	body := `{"site": {"site_id": "s1", "name": "n", "zones": []},
	  "users": [{"user_id": "admin", "role": "admin", "token_sha256": "` + tokenHash("tok-3") + `"}]} {"extra": 1}`
	_, err := Load(writeConfig(t, body))
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
	if _, err := Load("  "); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestValidateRejectsWeakUsers(t *testing.T) {
	good := tokenHash("good-token")
	cases := []struct {
		name  string
		users []User
	}{
		{"no users", nil},
		{"no admin", []User{{UserID: "u1", Role: RoleViewer, TokenSHA256: good}}},
		{"bad role", []User{{UserID: "u1", Role: "root", TokenSHA256: good}}},
		{"short hash", []User{{UserID: "u1", Role: RoleAdmin, TokenSHA256: "abc"}}},
		{"plaintext token", []User{{UserID: "u1", Role: RoleAdmin, TokenSHA256: "supersecret"}}},
		{"placeholder", []User{{UserID: "u1", Role: RoleAdmin, TokenSHA256: tokenHash("changeme")}}},
		{"zero hash", []User{{UserID: "u1", Role: RoleAdmin, TokenSHA256: strings.Repeat("0", 64)}}},
		{"duplicate id", []User{
			{UserID: "u1", Role: RoleAdmin, TokenSHA256: good},
			{UserID: "u1", Role: RoleViewer, TokenSHA256: tokenHash("other")},
		}},
		{"duplicate token", []User{
			{UserID: "u1", Role: RoleAdmin, TokenSHA256: good},
			{UserID: "u2", Role: RoleViewer, TokenSHA256: good},
		}},
		{"invalid id", []User{{UserID: "bad id!", Role: RoleAdmin, TokenSHA256: good}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.Users = tc.users
			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func baseConfig() Config {
	return Config{
		Site: domain.Site{
			SiteID: "filiale-001",
			Name:   "Markt Nord",
			Status: domain.SiteOnline,
			Zones:  []domain.Zone{{ZoneID: "zone-ot", SiteID: "filiale-001", Name: "OT", Kind: domain.ZoneOTProcess}},
		},
		Users: []User{
			{UserID: "admin", Name: "Admin", Role: RoleAdmin, TokenSHA256: tokenHash("base-admin")},
		},
		Collectors: []AdapterConfig{},
	}
}

func TestValidateRejectsUnsafeSimulation(t *testing.T) {
	cfg := baseConfig()
	cfg.Listen = "0.0.0.0:8080"
	cfg.Simulation = &SimulationConfig{Enabled: true}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error = %v, want loopback validation error", err)
	}

	cfg.Listen = "127.0.0.1:8080"
	cfg.Simulation = &SimulationConfig{Enabled: true, Listen: "0.0.0.0:9090"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "simulation.listen") {
		t.Fatalf("error = %v, want simulation.listen validation error", err)
	}

	cfg.Simulation = &SimulationConfig{Enabled: true}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loopback simulation must be valid: %v", err)
	}
}

func TestValidateRejectsBadListen(t *testing.T) {
	for _, listen := range []string{"127.0.0.1", ":8080", "127.0.0.1:0", "127.0.0.1:70000", "bad host!:8080"} {
		cfg := baseConfig()
		cfg.Listen = listen
		if err := cfg.Validate(); err == nil {
			t.Errorf("listen %q: expected validation error", listen)
		}
	}
	cfg := baseConfig()
	cfg.Listen = "0.0.0.0:8080" // explicit all-interface bind is allowed
	if err := cfg.Validate(); err != nil {
		t.Errorf("0.0.0.0 without simulation must be valid: %v", err)
	}
}

func TestValidateRejectsBadDataDir(t *testing.T) {
	for _, dir := range []string{".", "/"} {
		cfg := baseConfig()
		cfg.DataDir = dir
		if err := cfg.Validate(); err == nil {
			t.Errorf("data_dir %q: expected validation error", dir)
		}
	}
}

func TestValidateCollectors(t *testing.T) {
	cases := []struct {
		name string
		cfg  func(*Config)
		ok   bool
	}{
		{"empty adapter id", func(c *Config) { c.Collectors = []AdapterConfig{{Enabled: true}} }, false},
		{"duplicate adapter", func(c *Config) {
			c.Collectors = []AdapterConfig{{AdapterID: "a", Enabled: true}, {AdapterID: "a", Enabled: true}}
		}, false},
		{"undeclared zone", func(c *Config) {
			c.Collectors = []AdapterConfig{{AdapterID: "a", Enabled: true, ZoneID: "zone-unknown"}}
		}, false},
		{"declared zone", func(c *Config) {
			c.Collectors = []AdapterConfig{{AdapterID: "a", Enabled: true, ZoneID: "zone-ot"}}
		}, true},
		{"bad option", func(c *Config) {
			c.Collectors = []AdapterConfig{{AdapterID: "a", Enabled: true, Options: map[string]string{"": "x"}}}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			tc.cfg(&cfg)
			err := cfg.Validate()
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateCentralRequiresTLS(t *testing.T) {
	cases := []struct {
		name string
		url  string
		ok   bool
	}{
		{"https", "https://central.example.invalid/api", true},
		{"http remote", "http://central.example.invalid/api", false},
		{"http loopback", "http://127.0.0.1:9000/api", true},
		{"no scheme", "central.example.invalid/api", false},
		{"credentials in url", "https://user:pass@central.example.invalid/api", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig().WithDefaults()
			cfg.Central = &CentralConfig{URL: tc.url}
			cfg = cfg.WithDefaults()
			err := cfg.Validate()
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	cfg := baseConfig().WithDefaults()
	cfg.Central = &CentralConfig{URL: "https://central.example.invalid/api", ClientCertFile: "client.pem"}
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "client_key_file") {
		t.Fatalf("error = %v, want client_key_file pairing error", err)
	}
}

func TestValidatePolicySiteMatch(t *testing.T) {
	cfg := baseConfig().WithDefaults()
	p := domain.DefaultPolicy("filiale-999", mustTime())
	p.Hash = ""
	cfg.Policy = &p
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want site mismatch", err)
	}

	p2 := domain.DefaultPolicy("filiale-001", mustTime())
	cfg.Policy = &p2
	if err := cfg.Validate(); err != nil {
		t.Fatalf("matching policy must validate: %v", err)
	}
}

func TestParseRejectsNonObject(t *testing.T) {
	if _, err := Parse(strings.NewReader(`[]`)); err == nil {
		t.Fatal("expected error for array document")
	}
	if _, err := Parse(strings.NewReader(`null`)); err == nil {
		t.Fatal("expected error for null document")
	}
}

func TestRoleRankAndAllows(t *testing.T) {
	cases := []struct {
		have, need Role
		ok         bool
	}{
		{RoleViewer, RoleViewer, true},
		{RoleViewer, RoleOperator, false},
		{RoleOperator, RoleAdmin, false},
		{RoleAdmin, RoleOperator, true},
		{Role("root"), RoleViewer, false},
	}
	for _, tc := range cases {
		if got := tc.have.Allows(tc.need); got != tc.ok {
			t.Errorf("%q allows %q = %v, want %v", tc.have, tc.need, got, tc.ok)
		}
	}
	if Role("nonsense").Valid() {
		t.Error("unknown role must not be valid")
	}
}

func TestIsLoopbackHost(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1": true, "::1": true, "[::1]": true, "localhost": true, "LOCALHOST": true,
		"127.0.0.2": true, "0.0.0.0": false, "10.1.2.3": false, "example.com": false, "": false,
	}
	for host, want := range cases {
		if got := IsLoopbackHost(host); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestUserLookup(t *testing.T) {
	cfg := baseConfig()
	if u, ok := cfg.User("admin"); !ok || u.Role != RoleAdmin {
		t.Fatalf("user lookup failed: %+v %v", u, ok)
	}
	if _, ok := cfg.User("missing"); ok {
		t.Fatal("unknown user must not be found")
	}
}
