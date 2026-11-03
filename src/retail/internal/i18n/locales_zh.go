package i18n

// localeZh is the Simplified Chinese catalog (formal simplified characters).
var localeZh = map[string]string{
	"error.unauthorized":    "需要身份验证。",
	"error.forbidden":       "访问被拒绝。",
	"error.not_found":       "未找到资源。",
	"error.invalid_request": "请求无效。",
	"error.conflict":        "请求与当前状态冲突。",
	"error.rate_limited":    "请求过于频繁，请稍后重试。",
	"error.unavailable":     "服务暂时不可用。",
	"error.internal":        "服务器内部错误。",
	"error.ip_not_allowed":  "不允许从此网络地址访问。",
	"error.setup_required":  "初始化尚未完成。",
	"error.setup_conflict":  "当前状态下无法更改初始化配置。",
	"error.unknown":         "请求失败。",

	"setup.hint.loopback_only":      "初始化只能从本地计算机访问。",
	"setup.hint.remote_ip":          "检测到的请求地址：%s",
	"setup.hint.whitelist_required": "没有访问白名单时，所有请求都会被拒绝。",
	"setup.hint.whitelist_empty":    "白名单为空。请至少添加一个地址。",
	"setup.hint.token_once":         "管理员令牌仅显示一次，请安全保存。",
	"setup.hint.restart_required":   "请重启服务以应用配置。",
	"setup.hint.admin_required":     "完成初始化前请创建管理员账户。",
	"setup.hint.setup_complete":     "初始化已完成。",
	"setup.hint.language_invalid":   "不支持的语言：%s",
	"setup.hint.cidr_invalid":       "IP 地址或 CIDR 无效。",
	"setup.validation.required":     "此字段为必填项。",

	"setup.step.language":   "语言",
	"setup.step.site":       "门店",
	"setup.step.whitelist":  "访问白名单",
	"setup.step.admin":      "管理员",
	"setup.step.collectors": "采集器",
	"setup.step.summary":    "摘要",

	"label.role.viewer":   "查看者",
	"label.role.operator": "操作员",
	"label.role.admin":    "管理员",
}
