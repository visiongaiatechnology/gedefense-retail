package i18n

// localeJa is the Japanese catalog (polite です/ます form).
var localeJa = map[string]string{
	"error.unauthorized":    "認証が必要です。",
	"error.forbidden":       "アクセスが拒否されました。",
	"error.not_found":       "リソースが見つかりません。",
	"error.invalid_request": "リクエストが無効です。",
	"error.conflict":        "リクエストは現在の状態と競合しています。",
	"error.rate_limited":    "リクエストが多すぎます。しばらくしてから再度お試しください。",
	"error.unavailable":     "サービスは一時的に利用できません。",
	"error.internal":        "サーバー内部エラーです。",
	"error.ip_not_allowed":  "このネットワークアドレスからのアクセスは許可されていません。",
	"error.setup_required":  "セットアップがまだ完了していません。",
	"error.setup_conflict":  "現在の状態ではセットアップを変更できません。",
	"error.unknown":         "リクエストに失敗しました。",

	"setup.hint.loopback_only":      "セットアップはローカルマシンからのみアクセスできます。",
	"setup.hint.remote_ip":          "検出されたリクエストアドレス: %s",
	"setup.hint.whitelist_required": "アクセス許可リストがない場合、すべてのリクエストが拒否されます。",
	"setup.hint.whitelist_empty":    "許可リストが空です。少なくとも1つのアドレスを追加してください。",
	"setup.hint.token_once":         "管理者トークンは一度だけ表示されます。安全な場所に保管してください。",
	"setup.hint.restart_required":   "設定を適用するにはサービスを再起動してください。",
	"setup.hint.admin_required":     "セットアップを完了する前に管理者アカウントを作成してください。",
	"setup.hint.setup_complete":     "セットアップはすでに完了しています。",
	"setup.hint.language_invalid":   "サポートされていない言語です: %s",
	"setup.hint.cidr_invalid":       "IPアドレスまたはCIDRが無効です。",
	"setup.validation.required":     "この項目は必須です。",

	"setup.step.language":   "言語",
	"setup.step.site":       "店舗",
	"setup.step.whitelist":  "アクセス許可リスト",
	"setup.step.admin":      "管理者",
	"setup.step.collectors": "コレクター",
	"setup.step.summary":    "概要",

	"label.role.viewer":   "閲覧者",
	"label.role.operator": "オペレーター",
	"label.role.admin":    "管理者",
}
