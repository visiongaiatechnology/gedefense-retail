package i18n

// localeIt is the Italian catalog.
var localeIt = map[string]string{
	"error.unauthorized":    "Autenticazione richiesta.",
	"error.forbidden":       "Accesso negato.",
	"error.not_found":       "Risorsa non trovata.",
	"error.invalid_request": "Richiesta non valida.",
	"error.conflict":        "La richiesta è in conflitto con lo stato attuale.",
	"error.rate_limited":    "Troppe richieste. Riprova più tardi.",
	"error.unavailable":     "Servizio temporaneamente non disponibile.",
	"error.internal":        "Errore interno del server.",
	"error.ip_not_allowed":  "L'accesso da questo indirizzo di rete non è consentito.",
	"error.setup_required":  "La configurazione non è ancora completata.",
	"error.setup_conflict":  "La configurazione non può essere modificata nello stato attuale.",
	"error.unknown":         "Richiesta non riuscita.",

	"setup.hint.loopback_only":      "La configurazione è raggiungibile solo dalla macchina locale.",
	"setup.hint.remote_ip":          "Indirizzo della richiesta rilevato: %s",
	"setup.hint.whitelist_required": "Senza una whitelist di accesso ogni richiesta viene rifiutata.",
	"setup.hint.whitelist_empty":    "La whitelist è vuota. Aggiungi almeno un indirizzo.",
	"setup.hint.token_once":         "Il token amministratore viene mostrato una sola volta. Conservalo in modo sicuro.",
	"setup.hint.restart_required":   "Riavvia il servizio per applicare la configurazione.",
	"setup.hint.admin_required":     "Crea un account amministratore prima di completare la configurazione.",
	"setup.hint.setup_complete":     "La configurazione è già completata.",
	"setup.hint.language_invalid":   "Lingua non supportata: %s",
	"setup.hint.cidr_invalid":       "Indirizzo IP o CIDR non valido.",
	"setup.validation.required":     "Questo campo è obbligatorio.",

	"setup.step.language":   "Lingua",
	"setup.step.site":       "Filiale",
	"setup.step.whitelist":  "Whitelist di accesso",
	"setup.step.admin":      "Amministratore",
	"setup.step.collectors": "Collector",
	"setup.step.summary":    "Riepilogo",

	"label.role.viewer":   "Visualizzatore",
	"label.role.operator": "Operatore",
	"label.role.admin":    "Amministratore",
}
