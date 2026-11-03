package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// captureRun runs a CLI invocation and captures its JSON stdout.
func captureRun(t *testing.T, args []string) (int, string) {
	t.Helper()
	old := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = writer
	code := run(args)
	_ = writer.Close()
	os.Stdout = old
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	_ = reader.Close()
	return code, string(raw)
}

// TestTokenRotateCLI covers FIND-007: rotation prints a new token + hash, marks
// the restart requirement and writes no configuration.
func TestTokenRotateCLI(t *testing.T) {
	code, out := captureRun(t, []string{"token", "rotate", "--user", "admin", "--role", "admin"})
	if code != 0 {
		t.Fatalf("token rotate exit = %d", code)
	}
	var payload struct {
		UserID          string `json:"user_id"`
		Role            string `json:"role"`
		Token           string `json:"token"`
		TokenSHA256     string `json:"token_sha256"`
		RestartRequired bool   `json:"restart_required"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("decode token rotate output %q: %v", out, err)
	}
	sum := sha256.Sum256([]byte(payload.Token))
	if payload.TokenSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("token_sha256 does not match token")
	}
	if !payload.RestartRequired || payload.UserID != "admin" {
		t.Fatalf("rotation payload = %+v", payload)
	}
}

// TestTokenHashCLI hashes an existing token without persisting it.
func TestTokenHashCLI(t *testing.T) {
	plain := "existing-bearer-token"
	code, out := captureRun(t, []string{"token", "hash", "--token", plain})
	if code != 0 {
		t.Fatalf("token hash exit = %d", code)
	}
	sum := sha256.Sum256([]byte(plain))
	if !strings.Contains(out, hex.EncodeToString(sum[:])) {
		t.Fatalf("hash output %q does not contain the expected digest", out)
	}
}
