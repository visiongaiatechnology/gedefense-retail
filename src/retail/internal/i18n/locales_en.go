package i18n

// localeEn is the authoritative English catalog (also the fallback language).
var localeEn = map[string]string{
	"error.unauthorized":    "Authentication required.",
	"error.forbidden":       "Access denied.",
	"error.not_found":       "Resource not found.",
	"error.invalid_request": "Invalid request.",
	"error.conflict":        "The request conflicts with the current state.",
	"error.rate_limited":    "Too many requests. Please try again later.",
	"error.unavailable":     "Service temporarily unavailable.",
	"error.internal":        "Internal server error.",
	"error.ip_not_allowed":  "Access from this network address is not allowed.",
	"error.setup_required":  "Setup is not completed yet.",
	"error.setup_conflict":  "Setup cannot be changed in its current state.",
	"error.unknown":         "Request failed.",

	"setup.hint.loopback_only":      "Setup is only reachable from the local machine.",
	"setup.hint.remote_ip":          "Detected request address: %s",
	"setup.hint.whitelist_required": "Without an access whitelist every request is denied.",
	"setup.hint.whitelist_empty":    "The whitelist is empty. Add at least one address.",
	"setup.hint.token_once":         "The admin token is shown only once. Store it securely.",
	"setup.hint.restart_required":   "Restart the service to apply the configuration.",
	"setup.hint.admin_required":     "Create an administrator account before completing setup.",
	"setup.hint.setup_complete":     "Setup is already completed.",
	"setup.hint.language_invalid":   "Unsupported language: %s",
	"setup.hint.cidr_invalid":       "Invalid IP address or CIDR.",
	"setup.validation.required":     "This field is required.",

	"setup.step.language":   "Language",
	"setup.step.site":       "Store",
	"setup.step.whitelist":  "Access whitelist",
	"setup.step.admin":      "Administrator",
	"setup.step.collectors": "Collectors",
	"setup.step.summary":    "Summary",

	"label.role.viewer":   "Viewer",
	"label.role.operator": "Operator",
	"label.role.admin":    "Administrator",
}
