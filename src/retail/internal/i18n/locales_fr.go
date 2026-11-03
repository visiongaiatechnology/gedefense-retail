package i18n

// localeFr is the French catalog.
var localeFr = map[string]string{
	"error.unauthorized":    "Authentification requise.",
	"error.forbidden":       "Accès refusé.",
	"error.not_found":       "Ressource introuvable.",
	"error.invalid_request": "Requête invalide.",
	"error.conflict":        "La requête est en conflit avec l'état actuel.",
	"error.rate_limited":    "Trop de requêtes. Veuillez réessayer plus tard.",
	"error.unavailable":     "Service temporairement indisponible.",
	"error.internal":        "Erreur interne du serveur.",
	"error.ip_not_allowed":  "L'accès depuis cette adresse réseau n'est pas autorisé.",
	"error.setup_required":  "La configuration n'est pas encore terminée.",
	"error.setup_conflict":  "La configuration ne peut pas être modifiée dans son état actuel.",
	"error.unknown":         "Requête échouée.",

	"setup.hint.loopback_only":      "La configuration n'est accessible que depuis la machine locale.",
	"setup.hint.remote_ip":          "Adresse de requête détectée : %s",
	"setup.hint.whitelist_required": "Sans liste blanche d'accès, toute requête est refusée.",
	"setup.hint.whitelist_empty":    "La liste blanche est vide. Ajoutez au moins une adresse.",
	"setup.hint.token_once":         "Le jeton administrateur n'est affiché qu'une seule fois. Conservez-le en lieu sûr.",
	"setup.hint.restart_required":   "Redémarrez le service pour appliquer la configuration.",
	"setup.hint.admin_required":     "Créez un compte administrateur avant de terminer la configuration.",
	"setup.hint.setup_complete":     "La configuration est déjà terminée.",
	"setup.hint.language_invalid":   "Langue non prise en charge : %s",
	"setup.hint.cidr_invalid":       "Adresse IP ou CIDR invalide.",
	"setup.validation.required":     "Ce champ est obligatoire.",

	"setup.step.language":   "Langue",
	"setup.step.site":       "Magasin",
	"setup.step.whitelist":  "Liste blanche d'accès",
	"setup.step.admin":      "Administrateur",
	"setup.step.collectors": "Collecteurs",
	"setup.step.summary":    "Résumé",

	"label.role.viewer":   "Lecteur",
	"label.role.operator": "Opérateur",
	"label.role.admin":    "Administrateur",
}
