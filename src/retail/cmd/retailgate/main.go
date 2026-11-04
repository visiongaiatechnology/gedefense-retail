// Command retailgate is the GeDefense Retail Access Gate: the enforcement point
// for the management/configuration path of store OT devices.
//
// It has NO autonomous control path: every write must be requested, approved
// (four eyes where required), bound to an exact target/address/value and
// authorised by a one-time token. Without a valid approval the gate denies the
// write and records evidence. The refrigeration plant itself is never touched.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	gateconfig "github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/identity"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gateapp"
	"github.com/visiongaiatechnology/gedefense/retail/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "check":
		return cmdCheck(args[1:])
	case "hash-password":
		return cmdHashPassword(args[1:])
	case "gen-totp":
		return cmdGenTOTP()
	case "netpolicy":
		return cmdNetPolicy(args[1:])
	case "version":
		return cmdVersion()
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "retailgate: unknown subcommand %q\n\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `retailgate - GeDefense Retail Access Gate %s

Usage:
  retailgate serve         --config <gate.json>
  retailgate check         --config <gate.json>
  retailgate hash-password [--password <plain>]   (stdin if omitted)
  retailgate gen-totp
  retailgate netpolicy  --config <gate.json> --format nftables|iptables \
                        --gate-source <CIDR> [--gate-source ...] [--out <file>]
                        [--apply] [--rollback] [--check] [--print-topology]
  retailgate version
`, version.Version)
}

func cmdVersion() int {
	return printJSON(version.Current())
}

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", "", "path to gate.json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "retailgate serve: %v\n", err)
		return 1
	}
	logger := newLogger()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := gateapp.Run(ctx, cfg, gateapp.Options{ConfigPath: *cfgPath, Logger: logger}); err != nil {
		logger.Error("access gate failed", "error", err.Error())
		return 1
	}
	return 0
}

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", "", "path to gate.json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "retailgate check: %v\n", err)
		return 1
	}
	report, err := gateapp.Check(cfg, *cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "retailgate check: %v\n", err)
		return 1
	}
	if code := printJSON(report); code != 0 {
		return code
	}
	if !report.OK {
		return 1
	}
	return 0
}

func cmdHashPassword(args []string) int {
	fs := flag.NewFlagSet("hash-password", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	password := fs.String("password", "", "password to hash (stdin if omitted)")
	iterations := fs.Int("iterations", 210000, "PBKDF2 iterations (>= 100000)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	plain := *password
	if plain == "" {
		raw, err := readAllStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "retailgate hash-password: %v\n", err)
			return 1
		}
		plain = strings.TrimRight(raw, "\r\n")
	}
	if len(plain) < 12 {
		fmt.Fprintln(os.Stderr, "retailgate hash-password: password must have at least 12 characters")
		return 2
	}
	if *iterations < 100000 {
		fmt.Fprintln(os.Stderr, "retailgate hash-password: iterations must be >= 100000")
		return 2
	}
	hash, err := identity.HashPasswordWithIterations(plain, *iterations)
	if err != nil {
		fmt.Fprintf(os.Stderr, "retailgate hash-password: %v\n", err)
		return 1
	}
	return printJSON(map[string]string{"password_hash": hash, "note": "store only in gate.json (0600); never log the password"})
}

func cmdGenTOTP() int {
	secret, err := identity.NewTOTPSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "retailgate gen-totp: %v\n", err)
		return 1
	}
	return printJSON(map[string]string{"totp_secret": secret, "note": "store in gate.json (0600); enroll the same secret in the authenticator app"})
}

func loadConfig(path string) (gateconfig.Config, error) {
	if strings.TrimSpace(path) == "" {
		return gateconfig.Config{}, errors.New("--config is required")
	}
	return gateconfig.Load(path)
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func printJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "retailgate: encode output: %v\n", err)
		return 1
	}
	return 0
}

func readAllStdin() (string, error) {
	info, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return "", errors.New("no --password and stdin is a terminal")
	}
	var buf strings.Builder
	chunk := make([]byte, 4096)
	for {
		n, rerr := os.Stdin.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			if buf.Len() > 4096 {
				return "", errors.New("password input too long")
			}
		}
		if rerr != nil {
			break
		}
	}
	return buf.String(), nil
}
