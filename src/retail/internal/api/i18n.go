package api

import (
	"net/http"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/i18n"
)

// requestLanguage resolves the response language for one request. Precedence:
// explicit ?lang= query parameter, then the X-Lang header, then Accept-Language,
// then the configured default language (setup.language). Invalid explicit values
// are ignored instead of failing the request, and an unknown/unparsable
// Accept-Language header falls back to the default language.
func (s *Server) requestLanguage(r *http.Request) i18n.Language {
	if r == nil {
		return s.defaultLanguage
	}
	if lang, ok := explicitLanguage(r.URL.Query().Get("lang")); ok {
		return lang
	}
	if lang, ok := explicitLanguage(r.Header.Get("X-Lang")); ok {
		return lang
	}
	return i18n.Negotiate(r.Header.Get("Accept-Language"), s.defaultLanguage)
}

// explicitLanguage normalizes an explicitly requested language. An empty or
// unsupported value reports false so the next source in the precedence chain is
// used.
func explicitLanguage(raw string) (i18n.Language, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	return i18n.Normalize(raw)
}

// localizedError localizes an API error message for the request language.
//
// English keeps the caller-provided detail: the existing contract messages are
// English and API clients/tests depend on them. Every other language uses the
// stable code's catalog message; unknown codes fall back to the generic
// "error.unknown" text. The machine-readable code and the HTTP status are never
// translated or changed.
func localizedError(lang i18n.Language, code, fallback string) string {
	if !lang.IsSupported() || lang == i18n.English {
		return fallback
	}
	return i18n.Code(lang, code)
}
