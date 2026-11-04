package netpolicy

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Runner abstracts the host firewall commands so the package is testable without
// root privileges and without the real nft/iptables binaries.
type Runner interface {
	// LookPath reports whether a tool is installed.
	LookPath(name string) (string, error)
	// Run executes one command and returns an error on a non-zero exit.
	Run(name string, args ...string) error
	// Root reports whether the process may change the host firewall.
	Root() bool
}

// ExecRunner is the production Runner backed by os/exec and the effective UID.
type ExecRunner struct{}

// LookPath reports the resolved tool path.
func (ExecRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

// Run executes the command, capturing bounded stderr for a useful error message.
func (ExecRunner) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...) // #nosec G204 -- fixed tool names, arguments are generated locally
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 400 {
			message = message[:400]
		}
		return fmt.Errorf("%s: %w: %s", name, err, message)
	}
	return nil
}

// Root reports whether the process runs with root privileges. On Windows the
// command is unsupported and therefore never applies host firewall rules.
func (ExecRunner) Root() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return os.Geteuid() == 0
}

// WriteFileAtomic writes data through a 0600 temporary file and an atomic rename
// in the target directory (same filesystem), creating the directory if needed.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: output path is empty", ErrApply)
	}
	dir := dirOf(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("%w: create directory %s: %v", ErrApply, dir, err)
	}
	temp, err := os.CreateTemp(dir, ".gedefense-netpolicy-*")
	if err != nil {
		return fmt.Errorf("%w: create temporary file: %v", ErrApply, err)
	}
	name := temp.Name()
	cleanup := func() { _ = os.Remove(name) }
	defer cleanup()
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return fmt.Errorf("%w: chmod temporary file: %v", ErrApply, err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("%w: write temporary file: %v", ErrApply, err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("%w: sync temporary file: %v", ErrApply, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("%w: close temporary file: %v", ErrApply, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("%w: replace %s: %v", ErrApply, path, err)
	}
	return nil
}

// dirOf returns the directory part of a path.
func dirOf(path string) string {
	index := strings.LastIndexAny(path, `/\`)
	if index < 0 {
		return "."
	}
	if index == 0 {
		return string(path[0])
	}
	return path[:index]
}
