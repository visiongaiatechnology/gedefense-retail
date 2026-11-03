// Process-level helpers kept separate so the command logic stays testable.
package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func versionArgs() []string { return os.Args[1:] }

func stdoutWriter() io.Writer { return os.Stdout }

func stderrWriter() io.Writer { return os.Stderr }

func exit(code int) { os.Exit(code) }

// signalContext is cancelled on SIGINT/SIGTERM.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
