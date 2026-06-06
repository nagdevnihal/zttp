// internal/vault/vault_test.go
// Integration tests for the Vault client.
// Requires the running dev Vault container from docker-compose.
//
// Run:
//
//	VAULT_ADDR=http://localhost:8201 VAULT_TOKEN=dev-root-token-zttp \
//	  go test -v -race ./internal/vault/
package vault

import (
	"context"
	"os"
	"testing"

	"github.com/nagdevnihal/zttp/internal/config"
	"go.uber.org/zap"
)

// testClient creates a Vault client in dev mode using env vars.
// Skips if VAULT_ADDR is not reachable.
func testClient(t *testing.T) *Client {
	t.Helper()

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = "http://localhost:8201"
	}
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		token = "dev-root-token-zttp"
	}

	cfg := &config.Config{
		VaultAddr:    addr,
		VaultToken:   token,
		VaultDevMode: true,
	}

	client, err := New(cfg, zap.NewNop())
	if err != nil {
		t.Skipf("Vault not reachable at %s (%v) — skipping integration test", addr, err)
	}
	return client
}

// ── Client Authentication Tests ───────────────────────────────────────────────

func TestNew_DevMode(t *testing.T) {
	// Should succeed with a valid dev token
	client := testClient(t)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.token == "" {
		t.Error("expected non-empty token")
	}
}

// ── FetchPrivateKey Tests ─────────────────────────────────────────────────────

func TestFetchPrivateKey_ExistingPath(t *testing.T) {
	client := testClient(t)

	// Path seeded by vault-seed.sh
	signer, err := client.FetchPrivateKey(context.Background(), "secret/data/ssh/dev-app-01")
	if err != nil {
		t.Fatalf("FetchPrivateKey failed: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil EphemeralSigner")
	}
	if signer.Signer() == nil {
		t.Fatal("expected non-nil ssh.Signer inside EphemeralSigner")
	}
	if len(signer.rawBytes) == 0 {
		t.Error("expected non-empty rawBytes before zeroing")
	}
	signer.Zero()
}

func TestFetchPrivateKey_AllSeededPaths(t *testing.T) {
	client := testClient(t)

	paths := []string{
		"secret/data/ssh/dev-app-01",
		"secret/data/ssh/dev-db-01",
		"secret/data/ssh/stage-web-01",
		"secret/data/ssh/stage-db-01",
		"secret/data/ssh/prod-app-01",
		"secret/data/ssh/prod-db-01",
	}

	for _, path := range paths {
		path := path // capture range var
		t.Run(path, func(t *testing.T) {
			signer, err := client.FetchPrivateKey(context.Background(), path)
			if err != nil {
				t.Fatalf("FetchPrivateKey(%s) failed: %v", path, err)
			}
			defer signer.Zero()
			if signer.Signer() == nil {
				t.Errorf("expected non-nil signer for path %s", path)
			}
		})
	}
}

func TestFetchPrivateKey_NonExistentPath(t *testing.T) {
	client := testClient(t)

	_, err := client.FetchPrivateKey(context.Background(), "secret/data/ssh/does-not-exist-99")
	if err == nil {
		t.Error("expected error for non-existent vault path")
	}
}

// ── Zero() Tests ──────────────────────────────────────────────────────────────

func TestEphemeralSigner_ZeroWipesBytes(t *testing.T) {
	client := testClient(t)

	signer, err := client.FetchPrivateKey(context.Background(), "secret/data/ssh/dev-app-01")
	if err != nil {
		t.Fatalf("FetchPrivateKey failed: %v", err)
	}

	// Keep a reference to rawBytes BEFORE Zero() to check they've been wiped
	rawRef := signer.rawBytes
	originalLen := len(rawRef)
	if originalLen == 0 {
		t.Fatal("expected non-empty rawBytes")
	}

	signer.Zero()

	// After Zero(), every byte should be 0x00
	for i, b := range rawRef {
		if b != 0x00 {
			t.Errorf("rawBytes[%d] = %02x after Zero(), expected 0x00", i, b)
			break // report first non-zero byte
		}
	}

	// signer reference should be nil
	if signer.signer != nil {
		t.Error("expected signer.signer to be nil after Zero()")
	}
	if signer.rawBytes != nil {
		t.Error("expected signer.rawBytes to be nil after Zero()")
	}
}

func TestEphemeralSigner_ZeroIdempotent(t *testing.T) {
	client := testClient(t)

	signer, err := client.FetchPrivateKey(context.Background(), "secret/data/ssh/dev-db-01")
	if err != nil {
		t.Fatalf("FetchPrivateKey failed: %v", err)
	}

	// Should not panic when called multiple times
	signer.Zero()
	signer.Zero()
	signer.Zero()
}

func TestEphemeralSigner_ZeroOnNil(t *testing.T) {
	// Should not panic on nil receiver
	var e *EphemeralSigner
	e.Zero() // must not panic
}

// ── stripKVPrefix Tests (pure unit tests) ──────────────────────────────────────

func TestStripKVPrefix_WithPrefix(t *testing.T) {
	got := stripKVPrefix("secret/data/ssh/prod-db-01")
	want := "ssh/prod-db-01"
	if got != want {
		t.Errorf("stripKVPrefix: got %q, want %q", got, want)
	}
}

func TestStripKVPrefix_WithoutPrefix(t *testing.T) {
	got := stripKVPrefix("ssh/dev-app-01")
	want := "ssh/dev-app-01"
	if got != want {
		t.Errorf("stripKVPrefix no-op: got %q, want %q", got, want)
	}
}

func TestStripKVPrefix_EmptyString(t *testing.T) {
	got := stripKVPrefix("")
	if got != "" {
		t.Errorf("stripKVPrefix empty: expected empty, got %q", got)
	}
}

// ── Fingerprint Tests ─────────────────────────────────────────────────────────

func TestComputeFingerprint_Format(t *testing.T) {
	// Generate a test RSA key to verify fingerprint format
	// We use the host key from a live server fetch instead of generating one,
	// as crypto/rsa key generation is slow in tests.
	client := testClient(t)

	signer, err := client.FetchPrivateKey(context.Background(), "secret/data/ssh/dev-app-01")
	if err != nil {
		t.Fatalf("FetchPrivateKey failed: %v", err)
	}
	defer signer.Zero()

	// computeFingerprint operates on a public key
	pubKey := signer.Signer().PublicKey()
	fp := computeFingerprint(pubKey)

	if len(fp) == 0 {
		t.Error("expected non-empty fingerprint")
	}
	if fp[:7] != "SHA256:" {
		t.Errorf("expected fingerprint to start with SHA256:, got: %s", fp[:7])
	}
}

func TestStrictHostKeyCallback_SkipVerify(t *testing.T) {
	// In dev mode, skipVerify=true should return InsecureIgnoreHostKey
	cb := StrictHostKeyCallback("SHA256:whatever", true)
	if cb == nil {
		t.Error("expected non-nil callback")
	}
}

func TestFetchHostFingerprint_ExistingPath(t *testing.T) {
	client := testClient(t)

	fp, err := client.FetchHostFingerprint(context.Background(), "secret/data/ssh/dev-app-01")
	if err != nil {
		t.Fatalf("FetchHostFingerprint failed: %v", err)
	}
	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}
}
