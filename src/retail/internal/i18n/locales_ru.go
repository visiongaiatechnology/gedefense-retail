package i18n

// localeRu is the Russian catalog (formal address, вы).
var localeRu = map[string]string{
	"error.unauthorized":    "Требуется аутентификация.",
	"error.forbidden":       "Доступ запрещён.",
	"error.not_found":       "Ресурс не найден.",
	"error.invalid_request": "Некорректный запрос.",
	"error.conflict":        "Запрос конфликтует с текущим состоянием.",
	"error.rate_limited":    "Слишком много запросов. Повторите попытку позже.",
	"error.unavailable":     "Сервис временно недоступен.",
	"error.internal":        "Внутренняя ошибка сервера.",
	"error.ip_not_allowed":  "Доступ с этого сетевого адреса запрещён.",
	"error.setup_required":  "Настройка ещё не завершена.",
	"error.setup_conflict":  "Настройку нельзя изменить в текущем состоянии.",
	"error.unknown":         "Запрос не выполнен.",

	"setup.hint.loopback_only":      "Настройка доступна только с локального компьютера.",
	"setup.hint.remote_ip":          "Обнаруженный адрес запроса: %s",
	"setup.hint.whitelist_required": "Без списка разрешённых адресов отклоняется каждый запрос.",
	"setup.hint.whitelist_empty":    "Список разрешённых адресов пуст. Добавьте хотя бы один адрес.",
	"setup.hint.token_once":         "Токен администратора отображается только один раз. Сохраните его в надёжном месте.",
	"setup.hint.restart_required":   "Перезапустите службу, чтобы применить конфигурацию.",
	"setup.hint.admin_required":     "Создайте учётную запись администратора до завершения настройки.",
	"setup.hint.setup_complete":     "Настройка уже завершена.",
	"setup.hint.language_invalid":   "Неподдерживаемый язык: %s",
	"setup.hint.cidr_invalid":       "Некорректный IP-адрес или CIDR.",
	"setup.validation.required":     "Это поле обязательно.",

	"setup.step.language":   "Язык",
	"setup.step.site":       "Магазин",
	"setup.step.whitelist":  "Список доступа",
	"setup.step.admin":      "Администратор",
	"setup.step.collectors": "Коллекторы",
	"setup.step.summary":    "Сводка",

	"label.role.viewer":   "Наблюдатель",
	"label.role.operator": "Оператор",
	"label.role.admin":    "Администратор",
}
