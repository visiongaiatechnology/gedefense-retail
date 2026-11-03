package i18n

import (
	"sort"
	"strconv"
	"strings"
)

// preference is one parsed Accept-Language entry.
type preference struct {
	lang Language
	q    float64
}

// normalizeTag lowercases a language tag, maps "_" to "-" and returns the primary
// subtag. Chinese script/region variants collapse to "zh"; legacy aliases that
// the catalogs do not cover are returned as-is and then rejected by Normalize.
func normalizeTag(raw string) string {
	tag := strings.ToLower(strings.TrimSpace(raw))
	tag = strings.ReplaceAll(tag, "_", "-")
	if tag == "" {
		return ""
	}
	if index := strings.IndexByte(tag, '-'); index >= 0 {
		tag = tag[:index]
	}
	switch tag {
	case "iw":
		return "he"
	case "in":
		return "id"
	}
	return tag
}

// ParseAcceptLanguage parses an Accept-Language header and returns the supported
// languages ordered by descending q-value (stable for equal values). Wildcards
// are not returned; use Negotiate for request resolution.
func ParseAcceptLanguage(header string) []Language {
	preferences := parsePreferences(header)
	out := make([]Language, 0, len(preferences))
	for _, preference := range preferences {
		out = append(out, preference.lang)
	}
	return out
}

func parsePreferences(header string) []preference {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	preferences := make([]preference, 0, 4)
	seen := make(map[Language]struct{}, 4)
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(part, ";")
		token := strings.TrimSpace(fields[0])
		if token == "" || token == "*" {
			continue // wildcard handled by Negotiate
		}
		q := 1.0
		valid := true
		for _, parameter := range fields[1:] {
			parameter = strings.TrimSpace(parameter)
			if !strings.HasPrefix(strings.ToLower(parameter), "q=") {
				continue
			}
			value := strings.TrimSpace(parameter[2:])
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil || parsed < 0 || parsed > 1 {
				valid = false
				break
			}
			q = parsed
		}
		if !valid || q == 0 {
			continue
		}
		lang, ok := Normalize(token)
		if !ok {
			continue
		}
		if _, duplicate := seen[lang]; duplicate {
			continue
		}
		seen[lang] = struct{}{}
		preferences = append(preferences, preference{lang: lang, q: q})
	}
	sort.SliceStable(preferences, func(i, j int) bool { return preferences[i].q > preferences[j].q })
	return preferences
}

// Negotiate resolves the request language from an Accept-Language header:
// explicit supported languages win by q-value, a wildcard (or an empty/invalid
// header) falls back to the configured default, and unknown languages are
// skipped.
func Negotiate(header string, fallback Language) Language {
	if !fallback.IsSupported() {
		fallback = DefaultLanguage
	}
	preferences := parsePreferences(header)
	if len(preferences) > 0 {
		return preferences[0].lang
	}
	return fallback
}
