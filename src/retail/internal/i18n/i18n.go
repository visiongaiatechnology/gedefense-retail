// Package i18n provides server-side localization for GeDefense Retail.
//
// The package covers the operator-facing texts that the server itself emits:
//
//   - API error messages for every stable error.code (the code stays English and
//     machine readable; only the human message is localized),
//   - setup-manager hints and validation messages,
//   - setup step names and role labels that the server may return.
//
// Eight languages are supported: English, German, French, Italian, Spanish,
// Japanese, Chinese (Simplified) and Russian. Catalogs are plain Go maps so a
// missing key is caught by tests instead of at runtime; Validate enforces key
// parity, non-empty values and identical placeholder sets across languages.
//
// Language selection for HTTP requests is handled by ParseAcceptLanguage and
// Negotiate: q-values are ordered, region subtags are mapped to their primary
// language, a wildcard falls back to the configured default, and unknown or
// invalid languages never break the request (they fall back to English, then
// German). The api package stores the resolved language in the request context
// and uses it in the error responder.
package i18n

import "context"

// Language is a supported BCP-47 primary language subtag.
type Language string

// The eight supported server languages.
const (
	English  Language = "en"
	German   Language = "de"
	French   Language = "fr"
	Italian  Language = "it"
	Spanish  Language = "es"
	Japanese Language = "ja"
	Chinese  Language = "zh" // Simplified Chinese
	Russian  Language = "ru"
)

// DefaultLanguage is the built-in fallback when nothing else is configured.
const DefaultLanguage Language = English

var supportedLanguages = []Language{English, German, French, Italian, Spanish, Japanese, Chinese, Russian}

// SupportedLanguages returns the supported languages in stable display order.
func SupportedLanguages() []Language {
	out := make([]Language, len(supportedLanguages))
	copy(out, supportedLanguages)
	return out
}

// IsSupported reports whether the language is part of the catalog set.
func (l Language) IsSupported() bool {
	for _, supported := range supportedLanguages {
		if supported == l {
			return true
		}
	}
	return false
}

// String implements fmt.Stringer.
func (l Language) String() string { return string(l) }

// Normalize maps a language tag such as "de-DE", "zh-Hans-CN" or "EN_us" onto a
// supported primary language. The second return value is false for unsupported or
// empty tags.
func Normalize(raw string) (Language, bool) {
	tag := normalizeTag(raw)
	if tag == "" {
		return "", false
	}
	for _, supported := range supportedLanguages {
		if string(supported) == tag {
			return supported, true
		}
	}
	return "", false
}

// DefaultFrom resolves the configured default language. An empty, invalid or
// unsupported value falls back to DefaultLanguage; it never fails a server start
// because a language setting is not a safety property.
func DefaultFrom(raw string) Language {
	if lang, ok := Normalize(raw); ok {
		return lang
	}
	return DefaultLanguage
}

// contextKey is private so callers cannot collide with the language value.
type contextKey struct{}

// WithLanguage stores the resolved request language in the context.
func WithLanguage(ctx context.Context, lang Language) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if !lang.IsSupported() {
		lang = DefaultLanguage
	}
	return context.WithValue(ctx, contextKey{}, lang)
}

// LanguageFromContext returns the request language set by the middleware.
func LanguageFromContext(ctx context.Context) (Language, bool) {
	if ctx == nil {
		return "", false
	}
	lang, ok := ctx.Value(contextKey{}).(Language)
	if !ok || !lang.IsSupported() {
		return "", false
	}
	return lang, true
}
