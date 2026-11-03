package i18n

// localeEs is the Spanish catalog.
var localeEs = map[string]string{
	"error.unauthorized":    "Se requiere autenticación.",
	"error.forbidden":       "Acceso denegado.",
	"error.not_found":       "Recurso no encontrado.",
	"error.invalid_request": "Solicitud no válida.",
	"error.conflict":        "La solicitud entra en conflicto con el estado actual.",
	"error.rate_limited":    "Demasiadas solicitudes. Inténtelo de nuevo más tarde.",
	"error.unavailable":     "Servicio temporalmente no disponible.",
	"error.internal":        "Error interno del servidor.",
	"error.ip_not_allowed":  "No se permite el acceso desde esta dirección de red.",
	"error.setup_required":  "La configuración aún no se ha completado.",
	"error.setup_conflict":  "La configuración no se puede modificar en su estado actual.",
	"error.unknown":         "Solicitud fallida.",

	"setup.hint.loopback_only":      "La configuración solo es accesible desde la máquina local.",
	"setup.hint.remote_ip":          "Dirección de solicitud detectada: %s",
	"setup.hint.whitelist_required": "Sin una lista blanca de acceso se deniega toda solicitud.",
	"setup.hint.whitelist_empty":    "La lista blanca está vacía. Añada al menos una dirección.",
	"setup.hint.token_once":         "El token de administrador solo se muestra una vez. Guárdelo de forma segura.",
	"setup.hint.restart_required":   "Reinicie el servicio para aplicar la configuración.",
	"setup.hint.admin_required":     "Cree una cuenta de administrador antes de completar la configuración.",
	"setup.hint.setup_complete":     "La configuración ya está completada.",
	"setup.hint.language_invalid":   "Idioma no admitido: %s",
	"setup.hint.cidr_invalid":       "Dirección IP o CIDR no válida.",
	"setup.validation.required":     "Este campo es obligatorio.",

	"setup.step.language":   "Idioma",
	"setup.step.site":       "Tienda",
	"setup.step.whitelist":  "Lista blanca de acceso",
	"setup.step.admin":      "Administrador",
	"setup.step.collectors": "Colectores",
	"setup.step.summary":    "Resumen",

	"label.role.viewer":   "Visualizador",
	"label.role.operator": "Operador",
	"label.role.admin":    "Administrador",
}
