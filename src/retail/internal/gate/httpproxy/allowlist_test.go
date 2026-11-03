package httpproxy

import (
	"strings"
	"testing"
)

func TestAllowlistMatch(t *testing.T) {
	t.Parallel()
	list, err := newAllowlist([]string{"/", "/cgi-bin/*"})
	if err != nil {
		t.Fatalf("new allowlist: %v", err)
	}
	cases := map[string]bool{
		"/":                     true,
		"/cgi-bin/config":       true,
		"/cgi-bin/":             true,
		"/cgi-bin":              false,
		"/admin":                false,
		"/cgi-bin/config/extra": true,
	}
	for path, want := range cases {
		if got := list.Match(path); got != want {
			t.Fatalf("Match(%q) = %v, want %v", path, got, want)
		}
	}
	if list.Len() != 2 {
		t.Fatalf("len = %d", list.Len())
	}
}

func TestAllowlistRejectsUnsafePatterns(t *testing.T) {
	t.Parallel()
	for _, pattern := range []string{
		"", "cgi-bin", "/cgi*bin", "/*/x", "/a?b", "/a#b", "/a\\b", "/../etc", strings.Repeat("a", 300),
	} {
		if _, err := newAllowlist([]string{pattern}); err == nil {
			t.Fatalf("pattern %q accepted", pattern)
		}
	}
}

func TestCanonicalWritePath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"/cgi-bin/config", "/cgi-bin/config", false},
		{"/cgi-bin/config/", "/cgi-bin/config", false},
		{"/", "/", false},
		{"", "", true},
		{"cgi-bin/config", "", true},
		{"/../etc/passwd", "", true},
		{"/a/../../b", "", true},
	}
	for _, tc := range cases {
		got, err := canonicalWritePath(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%q accepted as %q", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("%q -> %q (%v)", tc.in, got, err)
		}
	}
}

func TestHeaderAllowlistRejectsCredentials(t *testing.T) {
	t.Parallel()
	for _, forbidden := range []string{"Authorization", "Cookie", "X-Forwarded-For", "Proxy-Authorization", "Connection"} {
		if _, err := buildHeaderAllowlist([]string{forbidden}); err == nil {
			t.Fatalf("header %q accepted in the outbound allowlist", forbidden)
		}
	}
	allow, err := buildHeaderAllowlist(nil)
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if _, ok := allow["accept"]; !ok {
		t.Fatal("default allowlist misses Accept")
	}
}

func TestParseCertPins(t *testing.T) {
	t.Parallel()
	if pins, err := parseCertPins(nil); err != nil || len(pins) != 0 {
		t.Fatalf("empty pins: %v %v", pins, err)
	}
	pin := strings.Repeat("ab", 32)
	pins, err := parseCertPins([]string{strings.ToUpper(pin)})
	if err != nil || len(pins) != 1 || len(pins[0]) != 32 {
		t.Fatalf("valid pin: %v %v", pins, err)
	}
	for _, invalid := range []string{"", "abc", strings.Repeat("zz", 32)} {
		if _, err := parseCertPins([]string{invalid}); err == nil {
			t.Fatalf("pin %q accepted", invalid)
		}
	}
}

func FuzzAllowlist(f *testing.F) {
	f.Add("/cgi-bin/config")
	f.Add("/")
	f.Add("../etc")
	f.Add(strings.Repeat("a", 300))
	list, _ := newAllowlist([]string{"/", "/cgi-bin/*"})
	f.Fuzz(func(t *testing.T, path string) {
		if len(path) > 1024 {
			return
		}
		_ = list.Match(path)
		_, _ = canonicalWritePath(path)
		_ = looksLikeJSON(path)
	})
}

func looksLikeJSON(value string) bool {
	trimmed := strings.TrimSpace(value)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}
