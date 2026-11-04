package vendorcatalog

import (
	"sort"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// MatchFamily derives a documented device family from passive evidence: the
// vendor hint (OUI, observed vendor name), the model hint and the hostname. It
// only returns a family when the evidence contains a family-specific token
// (family name or, together with a vendor match, the family id). A vendor name
// alone is never enough to claim a specific family.
func (c *Catalog) MatchFamily(vendor, model, hostname string) (DeviceFamily, bool) {
	if c == nil || !c.enabled || len(c.families) == 0 {
		return DeviceFamily{}, false
	}
	vendorNorm := normalizeText(vendor)
	tokens := hintTokens(vendor, model, hostname)
	// Tokens that merely repeat the vendor name are not family evidence: a bare
	// vendor hint must never select a specific device family.
	familyTokens := vendorNeutralTokens(tokens, vendorNorm)
	haystack := normalizeText(vendor + " " + model + " " + hostname)
	if haystack == "" {
		return DeviceFamily{}, false
	}

	type candidate struct {
		family DeviceFamily
		score  int
	}
	var candidates []candidate
	for _, family := range c.families {
		nameNorm := normalizeText(family.Name)
		idNorm := normalizeText(family.ID)
		mgmtNorm := normalizeText(family.ManagementInterface)

		strongName := false
		score := 0
		if len(nameNorm) >= 4 && strings.Contains(haystack, nameNorm) {
			strongName = true
			score += 100 + len(nameNorm)
		}
		for _, token := range familyTokens {
			if len(nameNorm) >= 3 && strings.Contains(nameNorm, token) {
				strongName = true
				score += 40 + len(token)
			}
			if len(token) >= 2 && containsNameToken(nameNorm, token) {
				strongName = true
				score += 40 + len(token)
			}
		}

		vendorMatch := c.vendorMatches(family.VendorID, vendorNorm)
		idMatch := false
		for _, token := range familyTokens {
			if len(token) >= 4 && strings.Contains(idNorm, token) {
				idMatch = true
				score += 20
			}
		}
		mgmtMatch := false
		for _, token := range familyTokens {
			if len(token) >= 4 && strings.Contains(mgmtNorm, token) {
				mgmtMatch = true
				score += 5
			}
		}
		if !strongName && !(vendorMatch && idMatch) {
			continue
		}
		if vendorMatch {
			score += 4
		}
		if mgmtMatch {
			score++
		}
		candidates = append(candidates, candidate{family: family, score: score})
	}
	if len(candidates) == 0 {
		return DeviceFamily{}, false
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		left, right := candidates[i].family.LifecycleStatus(), candidates[j].family.LifecycleStatus()
		if lifecycleRank(left) != lifecycleRank(right) {
			return lifecycleRank(left) > lifecycleRank(right)
		}
		return candidates[i].family.ID < candidates[j].family.ID
	})
	return candidates[0].family, true
}

// vendorMatches reports whether the normalized vendor hint matches the vendor of
// a family by id, name or legal name.
func (c *Catalog) vendorMatches(vendorID, vendorNorm string) bool {
	if vendorNorm == "" {
		return false
	}
	vendor, ok := c.Vendor(vendorID)
	if !ok {
		return false
	}
	fields := []string{vendor.ID, vendor.Name, vendor.LegalName}
	for _, field := range fields {
		normalized := normalizeText(field)
		if len(normalized) < 3 {
			continue
		}
		if strings.Contains(vendorNorm, normalized) || strings.Contains(normalized, vendorNorm) {
			return true
		}
	}
	return false
}

// LifecycleStatus maps the catalog lifecycle vocabulary onto the domain enum.
func (f DeviceFamily) LifecycleStatus() domain.LifecycleStatus {
	value := strings.ToLower(strings.TrimSpace(f.Lifecycle))
	switch {
	case value == "":
		return domain.LifecycleUnknown
	case strings.HasPrefix(value, "eol"):
		return domain.LifecycleEOL
	case value == "current" || value == "active" || value == "supported":
		return domain.LifecycleActive
	case strings.Contains(value, "legacy"), strings.Contains(value, "approaching"), strings.Contains(value, "near_eol"):
		return domain.LifecycleApproachingEOL
	default:
		return domain.LifecycleUnknown
	}
}

// HasManagementUI reports whether the family exposes a documented HTTP(S)
// management interface.
func (f DeviceFamily) HasManagementUI() bool {
	for _, protocol := range f.Protocols {
		if strings.EqualFold(strings.TrimSpace(protocol), "http_https_management") {
			return true
		}
	}
	return false
}

// lifecycleRank orders lifecycle states for deterministic tie-breaking.
func lifecycleRank(status domain.LifecycleStatus) int {
	switch status {
	case domain.LifecycleActive:
		return 3
	case domain.LifecycleApproachingEOL:
		return 2
	case domain.LifecycleEOL:
		return 1
	default:
		return 0
	}
}

// hintTokens splits the passive hints into normalized tokens. Two-character
// tokens are only kept when they contain a digit (E2/E3 controller series), all
// other tokens need at least three characters.
func hintTokens(values ...string) []string {
	var tokens []string
	seen := make(map[string]bool, 8)
	for _, value := range values {
		current := ""
		flush := func() {
			if len(current) >= 3 || (len(current) == 2 && strings.ContainsAny(current, "0123456789")) {
				if !seen[current] {
					seen[current] = true
					tokens = append(tokens, current)
				}
			}
			current = ""
		}
		for _, char := range strings.ToLower(value) {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
				current += string(char)
				continue
			}
			flush()
		}
		flush()
	}
	return tokens
}

// vendorNeutralTokens removes tokens that only repeat the vendor hint. Evidence
// must point at the family itself, not at the manufacturer.
func vendorNeutralTokens(tokens []string, vendorNorm string) []string {
	if vendorNorm == "" {
		return tokens
	}
	out := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if strings.Contains(vendorNorm, token) || strings.Contains(token, vendorNorm) {
			continue
		}
		out = append(out, token)
	}
	return out
}

// containsNameToken reports whether a normalized name contains the token on a
// word boundary. normalizeText strips separators, so the check is a plain
// substring test with length guards.
func containsNameToken(normalizedName, token string) bool {
	if len(token) < 2 || len(normalizedName) < 2 {
		return false
	}
	return strings.Contains(normalizedName, token)
}

// normalizeText lower-cases and removes every separator so "AK-SM 800" matches
// "ak_sm_800" and "storeview-ak-sm-800".
func normalizeText(value string) string {
	lower := strings.ToLower(value)
	var out strings.Builder
	out.Grow(len(lower))
	for _, char := range lower {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			out.WriteRune(char)
		}
	}
	return out.String()
}
