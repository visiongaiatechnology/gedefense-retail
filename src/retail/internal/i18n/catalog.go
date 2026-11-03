package i18n

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// catalogs is the immutable bundle of all language catalogs. The locale files
// (locales_<lang>.go) define the per-language maps; a language is never added
// here without a corresponding file and test coverage.
var catalogs = map[Language]map[string]string{
	English:  localeEn,
	German:   localeDe,
	French:   localeFr,
	Italian:  localeIt,
	Spanish:  localeEs,
	Japanese: localeJa,
	Chinese:  localeZh,
	Russian:  localeRu,
}

// Translator renders messages for one language with the documented fallback
// chain: requested language, then English, then German, then the key itself.
type Translator struct {
	lang Language
}

// For returns the translator for a language. Unsupported input falls back to the
// package default; it never panics on untrusted request data.
func For(lang Language) Translator {
	if !lang.IsSupported() {
		lang = DefaultLanguage
	}
	return Translator{lang: lang}
}

// Language reports the translator's language.
func (t Translator) Language() Language { return t.lang }

// T returns the localized message for a key.
func (t Translator) T(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	for _, lang := range fallbackChain(t.lang) {
		catalog, ok := catalogs[lang]
		if !ok {
			continue
		}
		if value, found := catalog[key]; found && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return key
}

// Code returns the localized message for a stable API error code. The code
// itself is never translated; unknown codes use the generic message.
func (t Translator) Code(code string) string {
	return t.T(ErrorKey(code))
}

// Format resolves a message template and formats it with fmt.Sprintf semantics.
func (t Translator) Format(key string, args ...any) string {
	return fmt.Sprintf(t.T(key), args...)
}

// Translate is the package-level convenience wrapper for one-off rendering.
func Translate(lang Language, key string) string { return For(lang).T(key) }

// Code is the package-level convenience wrapper for error codes.
func Code(lang Language, code string) string { return For(lang).Code(code) }

// Format is the package-level convenience wrapper for templates.
func Format(lang Language, key string, args ...any) string {
	return For(lang).Format(key, args...)
}

func fallbackChain(lang Language) []Language {
	if !lang.IsSupported() {
		lang = DefaultLanguage
	}
	switch lang {
	case English:
		return []Language{English, German}
	case German:
		return []Language{German, English}
	default:
		return []Language{lang, English, German}
	}
}

// Catalog returns a copy of one language catalog (QA and diagnostics).
func Catalog(lang Language) map[string]string {
	source, ok := catalogs[lang]
	if !ok {
		return nil
	}
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

var placeholderPattern = regexp.MustCompile(`%[sdvq]`)

// PlaceholderTokens returns the sorted, de-duplicated printf directives of a
// template. QA uses it to prove that every translation keeps the same placeholders
// as the English original.
func PlaceholderTokens(template string) []string {
	matches := placeholderPattern.FindAllString(template, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if _, duplicate := seen[match]; duplicate {
			continue
		}
		seen[match] = struct{}{}
		out = append(out, match)
	}
	sort.Strings(out)
	return out
}

// Validate checks the complete bundle: key parity with the English catalog, no
// empty values, no extra keys and identical placeholder sets. It is called by the
// test suite; a failure means a language file is incomplete.
func Validate() error {
	english := catalogs[English]
	if len(english) != len(allKeys) {
		return fmt.Errorf("i18n: english catalog has %d keys, %d declared", len(english), len(allKeys))
	}
	for _, key := range allKeys {
		if _, ok := english[key]; !ok {
			return fmt.Errorf("i18n: english catalog is missing declared key %q", key)
		}
	}
	declared := make(map[string]struct{}, len(allKeys))
	for _, key := range allKeys {
		declared[key] = struct{}{}
	}
	var problems []string
	for _, lang := range supportedLanguages {
		catalog, ok := catalogs[lang]
		if !ok || catalog == nil {
			problems = append(problems, fmt.Sprintf("%s: no catalog", lang))
			continue
		}
		if len(catalog) != len(allKeys) {
			problems = append(problems, fmt.Sprintf("%s: %d keys, expected %d", lang, len(catalog), len(allKeys)))
		}
		for _, key := range allKeys {
			value, exists := catalog[key]
			if !exists {
				problems = append(problems, fmt.Sprintf("%s: missing key %q", lang, key))
				continue
			}
			if strings.TrimSpace(value) == "" {
				problems = append(problems, fmt.Sprintf("%s: empty value for %q", lang, key))
				continue
			}
			if lang == English {
				continue
			}
			want := PlaceholderTokens(english[key])
			got := PlaceholderTokens(value)
			if !equalStrings(want, got) {
				problems = append(problems, fmt.Sprintf("%s: placeholders for %q differ (%v vs %v)", lang, key, got, want))
			}
		}
		for key := range catalog {
			if _, ok := declared[key]; !ok {
				problems = append(problems, fmt.Sprintf("%s: undeclared key %q", lang, key))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("i18n: catalog validation failed: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Summary is a compact machine-readable catalog description for QA reports.
type Summary struct {
	Languages []Language     `json:"languages"`
	Keys      int            `json:"keys"`
	PerLang   map[string]int `json:"per_language"`
}

// Describe returns the catalog summary.
func Describe() Summary {
	summary := Summary{Languages: SupportedLanguages(), Keys: len(allKeys), PerLang: make(map[string]int, len(supportedLanguages))}
	for _, lang := range supportedLanguages {
		summary.PerLang[string(lang)] = len(catalogs[lang])
	}
	return summary
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
