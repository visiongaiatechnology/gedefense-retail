// Package version carries the immutable product identity of GeDefense Retail.
//
// No side effects, no I/O, no build-time code generation: the linker is the
// only writer of the variable values (see Makefile target build).
package version

// Product identity. These strings are part of the audit trail and must not be
// changed without a product decision.
const (
	Product    = "GeDefense Retail"
	Edition    = "ColdChain & Store Infrastructure Security"
	ModulePath = "github.com/visiongaiatechnology/gedefense/retail"
	Binary     = "retaild"
	SimBinary  = "retail-sim"
)

// Build metadata. Variables (not constants) so that -ldflags can inject the
// release values: -X .../internal/version.Version=...
var (
	Version   = "0.1.0-dev"
	Commit    = "dev"
	BuildDate = "unknown"
)

// Info is a snapshot used by the API and the self-check.
type Info struct {
	Product   string `json:"product"`
	Edition   string `json:"edition"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	HTTPAPI   string `json:"http_api"`
}

// Current returns the compile-time identity of this binary.
func Current() Info {
	return Info{
		Product:   Product,
		Edition:   Edition,
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		HTTPAPI:   "v1",
	}
}
