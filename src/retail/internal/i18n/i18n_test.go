package i18n

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

func TestSupportedLanguages(t *testing.T) {
	t.Parallel()
	languages := SupportedLanguages()
	want := []Language{English, German, French, Italian, Spanish, Japanese, Chinese, Russian}
	if len(languages) != len(want) {
		t.Fatalf("language count = %d, want %d", len(languages), len(want))
	}
	for i := range want {
		if languages[i] != want[i] {
			t.Fatalf("language[%d] = %q, want %q", i, languages[i], want[i])
		}
		if !languages[i].IsSupported() {
			t.Fatalf("%q reports not supported", languages[i])
		}
	}
	// The returned slice is a copy.
	languages[0] = "xx"
	if SupportedLanguages()[0] != English {
		t.Fatal("SupportedLanguages must return a copy")
	}
	if Language("pt").IsSupported() {
		t.Fatal("unsupported language accepted")
	}
}

func TestNormalize(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		want Language
		ok   bool
	}{
		{"de", German, true},
		{"de-DE", German, true},
		{"DE-at", German, true},
		{"en_us", English, true},
		{"zh-Hans-CN", Chinese, true},
		{"zh_hant", Chinese, true},
		{"fr-CA", French, true},
		{"pt-BR", "", false},
		{"", "", false},
		{"   ", "", false},
		{"*", "", false},
		{"iw", "", false}, // Hebrew is not part of the catalog set
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			got, ok := Normalize(tc.raw)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("Normalize(%q) = %q,%t; want %q,%t", tc.raw, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestDefaultFrom(t *testing.T) {
	t.Parallel()
	cases := map[string]Language{
		"":       English,
		"de":     German,
		"de-AT":  German,
		"zh-CN":  Chinese,
		"xx":     English,
		"ignore": English,
	}
	for raw, want := range cases {
		if got := DefaultFrom(raw); got != want {
			t.Fatalf("DefaultFrom(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestParseAcceptLanguage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		header string
		want   []Language
	}{
		{"empty", "", nil},
		{"wildcard only", "*", nil},
		{"single", "de", []Language{German}},
		{"duplicate region collapses", "de-DE,de;q=0.9", []Language{German}},
		{"q ordering", "fr;q=0.5,de;q=0.9,it;q=0.7", []Language{German, Italian, French}},
		{"unknown skipped", "pt-BR,en;q=0.8", []Language{English}},
		{"invalid q skipped", "de;q=2,fr;q=0.4", []Language{French}},
		{"non numeric q skipped", "de;q=abc,fr;q=0.4", []Language{French}},
		{"zero q skipped", "de;q=0,fr;q=0.5", []Language{French}},
		{"equal q keeps header order", "ja,ru", []Language{Japanese, Russian}},
		{"whitespace tolerated", "  es ; q=0.5 , , zh ; q=0.9 ", []Language{Chinese, Spanish}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ParseAcceptLanguage(tc.header)
			if len(got) != len(tc.want) {
				t.Fatalf("ParseAcceptLanguage(%q) = %v, want %v", tc.header, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("ParseAcceptLanguage(%q) = %v, want %v", tc.header, got, tc.want)
				}
			}
		})
	}
}

func TestNegotiate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		header   string
		fallback Language
		want     Language
	}{
		{"explicit wins", "fr-FR,fr;q=0.9,en;q=0.5", English, French},
		{"wildcard uses fallback", "*", German, German},
		{"empty header uses fallback", "", German, German},
		{"unknown header uses fallback", "pt-BR,xx", German, German},
		{"invalid fallback becomes en", "pt-BR", Language("xx"), English},
		{"q ordering", "es;q=0.2,ja;q=0.9", German, Japanese},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Negotiate(tc.header, tc.fallback); got != tc.want {
				t.Fatalf("Negotiate(%q,%q) = %q, want %q", tc.header, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestCatalogValidationAndParity(t *testing.T) {
	t.Parallel()
	if err := Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	summary := Describe()
	if len(summary.Languages) != 8 {
		t.Fatalf("summary languages = %v", summary.Languages)
	}
	if summary.Keys != len(AllKeys()) {
		t.Fatalf("summary keys = %d, declared = %d", summary.Keys, len(AllKeys()))
	}
	for _, lang := range SupportedLanguages() {
		catalog := Catalog(lang)
		if catalog == nil {
			t.Fatalf("%q catalog is nil", lang)
		}
		if len(catalog) != summary.Keys {
			t.Fatalf("%q catalog has %d keys, want %d", lang, len(catalog), summary.Keys)
		}
		for _, key := range AllKeys() {
			value, ok := catalog[key]
			if !ok {
				t.Fatalf("%q missing key %q", lang, key)
			}
			if strings.TrimSpace(value) == "" {
				t.Fatalf("%q key %q is empty", lang, key)
			}
		}
	}
	// Catalog returns a defensive copy.
	catalog := Catalog(German)
	catalog[KeyErrorForbidden] = "mutated"
	if Catalog(German)[KeyErrorForbidden] == "mutated" {
		t.Fatal("Catalog must return a copy")
	}
}

func TestPlaceholderParity(t *testing.T) {
	t.Parallel()
	for _, lang := range SupportedLanguages() {
		catalog := Catalog(lang)
		for _, key := range AllKeys() {
			english := PlaceholderTokens(Catalog(English)[key])
			translated := PlaceholderTokens(catalog[key])
			if len(english) != len(translated) {
				t.Fatalf("%q/%q placeholders = %v, want %v", lang, key, translated, english)
			}
			for i := range english {
				if english[i] != translated[i] {
					t.Fatalf("%q/%q placeholders = %v, want %v", lang, key, translated, english)
				}
			}
		}
	}
	if got := PlaceholderTokens("Detected request address: %s"); len(got) != 1 || got[0] != "%s" {
		t.Fatalf("PlaceholderTokens = %v", got)
	}
	if got := PlaceholderTokens("100 % sicher"); len(got) != 0 {
		t.Fatalf("lone percent must not count as placeholder: %v", got)
	}
}

func TestErrorCodeCoverage(t *testing.T) {
	t.Parallel()
	codes := ErrorCodes()
	if len(codes) < 11 {
		t.Fatalf("expected at least 11 stable codes, got %d", len(codes))
	}
	for _, code := range codes {
		if !IsKnownErrorCode(code) {
			t.Fatalf("%q is not a known error code", code)
		}
		key := ErrorKey(code)
		if key != "error."+code {
			t.Fatalf("ErrorKey(%q) = %q", code, key)
		}
		for _, lang := range SupportedLanguages() {
			message := Code(lang, code)
			if strings.TrimSpace(message) == "" || message == key {
				t.Fatalf("%q/%q message missing: %q", lang, code, message)
			}
		}
	}
	if ErrorKey("something_new") != KeyErrorUnknown {
		t.Fatal("unknown code must map to error.unknown")
	}
	if IsKnownErrorCode("") {
		t.Fatal("empty code must not be known")
	}
}

func TestTranslationsDifferPerLanguage(t *testing.T) {
	t.Parallel()
	coreCodes := []string{"unauthorized", "forbidden", "invalid_request", "ip_not_allowed", "setup_required", "internal"}
	for _, code := range coreCodes {
		english := Code(English, code)
		seen := map[string]Language{english: English}
		for _, lang := range SupportedLanguages() {
			if lang == English {
				continue
			}
			message := Code(lang, code)
			if message == english {
				t.Fatalf("%q/%q is identical to English (%q)", lang, code, message)
			}
			if other, duplicate := seen[message]; duplicate {
				t.Fatalf("%q/%q duplicates %q message %q", lang, code, other, message)
			}
			seen[message] = lang
		}
	}
}

func TestFallbackChainAndMissingKeys(t *testing.T) {
	t.Parallel()
	chains := map[Language][]Language{
		English: {English, German},
		German:  {German, English},
		French:  {French, English, German},
		Russian: {Russian, English, German},
	}
	for lang, want := range chains {
		got := fallbackChain(lang)
		if len(got) != len(want) {
			t.Fatalf("fallbackChain(%q) = %v, want %v", lang, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("fallbackChain(%q) = %v, want %v", lang, got, want)
			}
		}
	}
	// Unsupported languages fall back to English.
	if got := For(Language("pt")).Language(); got != English {
		t.Fatalf("For(pt) language = %q", got)
	}
	// Unknown keys are returned verbatim instead of being rendered as blanks.
	if got := For(German).T("no.such.key"); got != "no.such.key" {
		t.Fatalf("unknown key = %q", got)
	}
	if got := For(German).T(""); got != "" {
		t.Fatalf("empty key = %q", got)
	}
}

func TestFormatAndContext(t *testing.T) {
	t.Parallel()
	formatted := Format(German, KeySetupHintRemoteIP, "10.20.30.40")
	if !strings.Contains(formatted, "10.20.30.40") {
		t.Fatalf("formatted message = %q", formatted)
	}
	if got := Translate(Japanese, KeyErrorForbidden); got != ConfirmedJapaneseForbidden {
		t.Fatalf("Japanese forbidden = %q", got)
	}
	ctx := WithLanguage(context.Background(), French)
	lang, ok := LanguageFromContext(ctx)
	if !ok || lang != French {
		t.Fatalf("context language = %q,%t", lang, ok)
	}
	if _, ok := LanguageFromContext(context.Background()); ok {
		t.Fatal("empty context must not report a language")
	}
	if _, ok := LanguageFromContext(nil); ok {
		t.Fatal("nil context must not report a language")
	}
	// Unsupported languages are normalized to the default before storage.
	ctx = WithLanguage(context.Background(), Language("pt"))
	if lang, ok := LanguageFromContext(ctx); !ok || lang != English {
		t.Fatalf("unsupported context language = %q,%t", lang, ok)
	}
}

// ConfirmedJapaneseForbidden pins one spot translation so a full-file regression
// (for example an encoding accident) fails loudly.
const ConfirmedJapaneseForbidden = "アクセスが拒否されました。"

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+[a-z0-9._-]{8,}`),
	regexp.MustCompile(`(?i)(password|passwd|secret|hmac|api[_-]?key)\s*[:=]\s*\S`),
	regexp.MustCompile(`-----BEGIN [A-Z ]+-----`),
	regexp.MustCompile(`\b[A-Fa-f0-9]{32,}\b`),
	regexp.MustCompile(`\b(ghp_|sk-|AKIA)[A-Za-z0-9]{8,}`),
	regexp.MustCompile(`(?i)token\s*[:=]\s*[A-Za-z0-9._-]{8,}`),
}

func TestMessagesContainNoSecrets(t *testing.T) {
	t.Parallel()
	for _, lang := range SupportedLanguages() {
		catalog := Catalog(lang)
		for key, value := range catalog {
			for _, pattern := range secretPatterns {
				if pattern.MatchString(value) {
					t.Fatalf("%q/%q contains secret-like content %q (pattern %q)", lang, key, value, pattern)
				}
			}
		}
	}
}

func TestDescribeIsStable(t *testing.T) {
	t.Parallel()
	first := Describe()
	second := Describe()
	if first.Keys != second.Keys || len(first.Languages) != len(second.Languages) {
		t.Fatalf("Describe not stable: %+v vs %+v", first, second)
	}
	for _, lang := range first.Languages {
		if first.PerLang[string(lang)] != len(AllKeys()) {
			t.Fatalf("%q per-language count = %d", lang, first.PerLang[string(lang)])
		}
	}
}
