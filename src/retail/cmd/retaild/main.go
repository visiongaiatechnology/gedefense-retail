// Command retaild is the GeDefense Retail edge gateway.
//
// Subcommands:
//
//	retaild serve      --config <path> [--demo]   start the detection gateway
//	retaild check      --config <path>            validate configuration and runtime
//	retaild gen-token  --user <id> --role <role>  create a bearer token + SHA-256 digest
//	retaild version                               print build identity
//
// The binary is passive by design: it never writes to OT devices (see
// internal/guard and docs/retail/safety-boundaries.md).
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/visiongaiatechnology/gedefense/retail/internal/app"
	"github.com/visiongaiatechnology/gedefense/retail/internal/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 2
	}
	switch args[0] {
	case "version":
		return cmdVersion()
	case "gen-token":
		return cmdGenToken(args[1:])
	case "check":
		return cmdCheck(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "retaild: unknown subcommand %q\n\n", args[0])
		printUsage()
		return 2
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `retaild — GeDefense Retail edge gateway %s

Usage:
  retaild serve      --config <path> [--demo]
  retaild check      --config <path>
  retaild gen-token  --user <id> --role viewer|operator|admin
  retaild version
`, version.Version)
}

func cmdVersion() int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(version.Current()); err != nil {
		fmt.Fprintf(os.Stderr, "retaild: encode version: %v\n", err)
		return 1
	}
	return 0
}

// tokenOutput is the JSON printed by gen-token. The plaintext token is printed
// exactly once and never stored by the gateway.
type tokenOutput struct {
	UserID      string `json:"user_id"`
	Role        string `json:"role"`
	Token       string `json:"token"`
	TokenSHA256 string `json:"token_sha256"`
}

func cmdGenToken(args []string) int {
	fs := flag.NewFlagSet("gen-token", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	user := fs.String("user", "", "user id (for example admin)")
	role := fs.String("role", "admin", "role: viewer, operator or admin")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	roleValue := config.Role(strings.TrimSpace(*role))
	if !roleValue.Valid() {
		fmt.Fprintf(os.Stderr, "retaild: invalid role %q (viewer, operator, admin)\n", *role)
		return 2
	}
	uid := domain.UserID(strings.TrimSpace(*user))
	if err := uid.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "retaild: invalid user id: %v\n", err)
		return 2
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		fmt.Fprintf(os.Stderr, "retaild: crypto/rand unavailable: %v\n", err)
		return 1
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(tokenOutput{
		UserID:      string(uid),
		Role:        string(roleValue),
		Token:       token,
		TokenSHA256: hex.EncodeToString(sum[:]),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "retaild: encode token: %v\n", err)
		return 1
	}
	return 0
}

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", "", "path to retail.json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "retaild check: %v\n", err)
		return 1
	}
	report, err := app.Check(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "retaild check: %v\n", err)
		return 1
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "retaild check: encode report: %v\n", err)
		return 1
	}
	if !report.OK {
		return 1
	}
	return 0
}

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", "", "path to retail.json")
	demoMode := fs.Bool("demo", false, "seed the fictional demo store (requires simulation.enabled)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "retaild serve: %v\n", err)
		return 1
	}

	logger := newLogger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, cfg, app.Options{Demo: *demoMode, Logger: logger, ConfigPath: *cfgPath}); err != nil {
		logger.Error("gateway failed", "error", err.Error())
		return 1
	}
	return 0
}

func loadConfig(path string) (config.Config, error) {
	if strings.TrimSpace(path) == "" {
		return config.Config{}, errors.New("--config is required")
	}
	return config.Load(path)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
