package i18n

// localeDe is the German catalog (German is the secondary fallback language).
var localeDe = map[string]string{
	"error.unauthorized":    "Authentifizierung erforderlich.",
	"error.forbidden":       "Zugriff verweigert.",
	"error.not_found":       "Ressource nicht gefunden.",
	"error.invalid_request": "Ungültige Anfrage.",
	"error.conflict":        "Die Anfrage steht im Konflikt mit dem aktuellen Zustand.",
	"error.rate_limited":    "Zu viele Anfragen. Bitte versuchen Sie es später erneut.",
	"error.unavailable":     "Dienst vorübergehend nicht verfügbar.",
	"error.internal":        "Interner Serverfehler.",
	"error.ip_not_allowed":  "Der Zugriff von dieser Netzwerkadresse ist nicht erlaubt.",
	"error.setup_required":  "Die Einrichtung ist noch nicht abgeschlossen.",
	"error.setup_conflict":  "Die Einrichtung kann im aktuellen Zustand nicht geändert werden.",
	"error.unknown":         "Anfrage fehlgeschlagen.",

	"setup.hint.loopback_only":      "Die Einrichtung ist nur vom lokalen Rechner aus erreichbar.",
	"setup.hint.remote_ip":          "Erkannte Anfrageadresse: %s",
	"setup.hint.whitelist_required": "Ohne Zugriffs-Whitelist wird jede Anfrage abgelehnt.",
	"setup.hint.whitelist_empty":    "Die Whitelist ist leer. Fügen Sie mindestens eine Adresse hinzu.",
	"setup.hint.token_once":         "Das Administrator-Token wird nur einmal angezeigt. Bewahren Sie es sicher auf.",
	"setup.hint.restart_required":   "Starten Sie den Dienst neu, um die Konfiguration anzuwenden.",
	"setup.hint.admin_required":     "Legen Sie vor dem Abschluss der Einrichtung ein Administratorkonto an.",
	"setup.hint.setup_complete":     "Die Einrichtung ist bereits abgeschlossen.",
	"setup.hint.language_invalid":   "Nicht unterstützte Sprache: %s",
	"setup.hint.cidr_invalid":       "Ungültige IP-Adresse oder CIDR.",
	"setup.validation.required":     "Dieses Feld ist erforderlich.",

	"setup.step.language":   "Sprache",
	"setup.step.site":       "Filiale",
	"setup.step.whitelist":  "Zugriffs-Whitelist",
	"setup.step.admin":      "Administrator",
	"setup.step.collectors": "Collectors",
	"setup.step.summary":    "Zusammenfassung",

	"label.role.viewer":   "Betrachter",
	"label.role.operator": "Bediener",
	"label.role.admin":    "Administrator",
}
