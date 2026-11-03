package rules

// catalog is the assembled rule pack. It is a package-level value that is
// initialised once from the domain-grouped spec files and never mutated; All and
// ByID return defensive copies.
var catalog = concatSpecs(networkSpecs, accessSpecs, thermalSpecs, dataQualitySpecs, integritySpecs, deviceSpecs)

func concatSpecs(groups ...[]Spec) []Spec {
	total := 0
	for _, group := range groups {
		total += len(group)
	}
	out := make([]Spec, 0, total)
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}
