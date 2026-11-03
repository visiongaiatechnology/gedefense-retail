package i18n

// Message keys. The constants are the single source of truth for the catalog
// keys; tests assert that every constant exists in every language.
const (
	// Error messages, keyed by the stable API error.code.
	KeyErrorUnauthorized  = "error.unauthorized"
	KeyErrorForbidden     = "error.forbidden"
	KeyErrorNotFound      = "error.not_found"
	KeyErrorInvalidReq    = "error.invalid_request"
	KeyErrorConflict      = "error.conflict"
	KeyErrorRateLimited   = "error.rate_limited"
	KeyErrorUnavailable   = "error.unavailable"
	KeyErrorInternal      = "error.internal"
	KeyErrorIPNotAllowed  = "error.ip_not_allowed"
	KeyErrorSetupRequired = "error.setup_required"
	KeyErrorSetupConflict = "error.setup_conflict"
	KeyErrorUnknown       = "error.unknown"

	// Setup manager hints and validation messages.
	KeySetupHintLoopbackOnly      = "setup.hint.loopback_only"
	KeySetupHintRemoteIP          = "setup.hint.remote_ip"
	KeySetupHintWhitelistRequired = "setup.hint.whitelist_required"
	KeySetupHintWhitelistEmpty    = "setup.hint.whitelist_empty"
	KeySetupHintTokenOnce         = "setup.hint.token_once"
	KeySetupHintRestartRequired   = "setup.hint.restart_required"
	KeySetupHintAdminRequired     = "setup.hint.admin_required"
	KeySetupHintSetupComplete     = "setup.hint.setup_complete"
	KeySetupHintLanguageInvalid   = "setup.hint.language_invalid"
	KeySetupHintCIDRInvalid       = "setup.hint.cidr_invalid"
	KeySetupValidationRequired    = "setup.validation.required"

	// Setup wizard step names (server-side state responses).
	KeySetupStepLanguage   = "setup.step.language"
	KeySetupStepSite       = "setup.step.site"
	KeySetupStepWhitelist  = "setup.step.whitelist"
	KeySetupStepAdmin      = "setup.step.admin"
	KeySetupStepCollectors = "setup.step.collectors"
	KeySetupStepSummary    = "setup.step.summary"

	// Role labels, if the server renders them.
	KeyLabelRoleViewer   = "label.role.viewer"
	KeyLabelRoleOperator = "label.role.operator"
	KeyLabelRoleAdmin    = "label.role.admin"
)

// allKeys is the complete, stable catalog key set (English is authoritative).
var allKeys = []string{
	KeyErrorUnauthorized,
	KeyErrorForbidden,
	KeyErrorNotFound,
	KeyErrorInvalidReq,
	KeyErrorConflict,
	KeyErrorRateLimited,
	KeyErrorUnavailable,
	KeyErrorInternal,
	KeyErrorIPNotAllowed,
	KeyErrorSetupRequired,
	KeyErrorSetupConflict,
	KeyErrorUnknown,

	KeySetupHintLoopbackOnly,
	KeySetupHintRemoteIP,
	KeySetupHintWhitelistRequired,
	KeySetupHintWhitelistEmpty,
	KeySetupHintTokenOnce,
	KeySetupHintRestartRequired,
	KeySetupHintAdminRequired,
	KeySetupHintSetupComplete,
	KeySetupHintLanguageInvalid,
	KeySetupHintCIDRInvalid,
	KeySetupValidationRequired,

	KeySetupStepLanguage,
	KeySetupStepSite,
	KeySetupStepWhitelist,
	KeySetupStepAdmin,
	KeySetupStepCollectors,
	KeySetupStepSummary,

	KeyLabelRoleViewer,
	KeyLabelRoleOperator,
	KeyLabelRoleAdmin,
}

// AllKeys returns the complete key set in stable order.
func AllKeys() []string {
	out := make([]string, len(allKeys))
	copy(out, allKeys)
	return out
}

// errorCodes is the stable machine-readable API error code set. The order is the
// contract order used by the API documentation and QA reports.
var errorCodes = []string{
	"unauthorized",
	"forbidden",
	"not_found",
	"invalid_request",
	"conflict",
	"rate_limited",
	"unavailable",
	"internal",
	"ip_not_allowed",
	"setup_required",
	"setup_conflict",
}

// ErrorCodes returns the stable error codes covered by the catalogs.
func ErrorCodes() []string {
	out := make([]string, len(errorCodes))
	copy(out, errorCodes)
	return out
}

// IsKnownErrorCode reports whether the code has a dedicated message key.
func IsKnownErrorCode(code string) bool {
	for _, known := range errorCodes {
		if known == code {
			return true
		}
	}
	return false
}

// ErrorKey maps a stable API error.code onto its catalog key. Unknown codes use
// the generic "error.unknown" message instead of leaking an internal string.
func ErrorKey(code string) string {
	if IsKnownErrorCode(code) {
		return "error." + code
	}
	return KeyErrorUnknown
}
