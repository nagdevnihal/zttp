// internal/vault/keyfetch.go
// Ephemeral key lifecycle — fetch, use, zero.
//
// The entire point of ZTTP's security model is here:
//   - The private key never touches disk, /tmp, or any file descriptor
//   - It lives only in Go heap memory as a []byte
//   - After the SSH handshake succeeds, Zero() is called via defer
//   - Zero() overwrites every byte to 0x00 and nils the references
//   - runtime.GC() is called to trigger immediate collection of the now-nil signer
//
// Callers MUST follow this pattern:
//
//	ephemeral, err := vaultClient.FetchPrivateKey(ctx, path)
//	if err != nil { ... }
//	defer ephemeral.Zero()  // ← ALWAYS defer before using the signer
//	sshClient, err := ssh.Dial(..., &ssh.ClientConfig{Auth: []ssh.AuthMethod{ssh.PublicKeys(ephemeral.Signer())}}, ...)
package vault

import (
	"context"
	"fmt"
	"runtime"

	"golang.org/x/crypto/ssh"
	"go.uber.org/zap"
)

// EphemeralSigner wraps ssh.Signer with the raw key bytes tracked for secure zeroing.
// Once Zero() is called, neither Signer() nor the raw bytes are safe to use.
type EphemeralSigner struct {
	signer   ssh.Signer
	rawBytes []byte // kept for explicit overwrite; not copied anywhere
}

// Signer returns the ssh.Signer for use in SSH dial configuration.
// Do NOT call after Zero() has been called.
func (e *EphemeralSigner) Signer() ssh.Signer {
	return e.signer
}

// Zero explicitly wipes the private key bytes from memory.
//
// It must be called immediately after the backend SSH handshake completes
// (whether it succeeds or fails). Use via defer:
//
//	ephemeral, _ := client.FetchPrivateKey(ctx, path)
//	defer ephemeral.Zero()
//
// Implementation notes:
//   - Explicit byte-by-byte loop: the compiler cannot optimize away a loop that
//     writes to memory that escapes the current function scope (rawBytes is heap-allocated).
//   - runtime.KeepAlive: prevents the GC from collecting rawBytes before the loop runs.
//   - runtime.GC(): requests immediate collection of the now-nil signer — this is a hint,
//     not a guarantee, but it reduces the window during which a memory dump could expose
//     the key material.
func (e *EphemeralSigner) Zero() {
	if e == nil || e.rawBytes == nil {
		return
	}
	// Overwrite every byte
	for i := range e.rawBytes {
		e.rawBytes[i] = 0x00
	}
	// Keep rawBytes alive through the loop — prevents the compiler from
	// reordering or eliding the zeroing loop as a dead-store optimization.
	runtime.KeepAlive(e.rawBytes)

	// Nil the references so GC can reclaim the backing array
	e.rawBytes = nil
	e.signer = nil

	// Request GC to reduce the window in which a memory dump could find key material.
	// This is advisory — production deployments should also consider disabling core dumps.
	runtime.GC()
}

// FetchPrivateKey fetches a private SSH key from Vault KV v2 and returns an
// EphemeralSigner backed only by in-RAM bytes.
//
// The caller MUST call .Zero() on the returned signer after the SSH handshake.
// If parsing fails, rawBytes are zeroed before the error is returned.
func (c *Client) FetchPrivateKey(ctx context.Context, vaultPath string) (*EphemeralSigner, error) {
	// Ensure the current token is set on the API client before the request
	c.mu.RLock()
	c.api.SetToken(c.token)
	c.mu.RUnlock()

	// KVv2 Get: path format is "secret/data/<name>" but KVv2() handles the prefix
	keyName := stripKVPrefix(vaultPath)
	secret, err := c.api.KVv2("secret").Get(ctx, keyName)
	if err != nil {
		return nil, fmt.Errorf("vault kv get [%s]: %w", vaultPath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault secret empty at path [%s]", vaultPath)
	}

	rawKeyVal, ok := secret.Data["private_key"]
	if !ok {
		return nil, fmt.Errorf("vault secret at [%s] missing 'private_key' field", vaultPath)
	}
	rawKeyStr, ok := rawKeyVal.(string)
	if !ok {
		return nil, fmt.Errorf("vault 'private_key' at [%s] is not a string", vaultPath)
	}

	// Convert string → []byte. This allocation stays on the Go heap.
	// No file descriptor, no /tmp, no os.WriteFile.
	rawBytes := []byte(rawKeyStr)

	signer, err := ssh.ParsePrivateKey(rawBytes)
	if err != nil {
		// Key parsing failed — zero the bytes before returning so we don't
		// leave PEM data in RAM attached to a returned error.
		zeroBytes(rawBytes)
		return nil, fmt.Errorf("parse private key from vault [%s]: %w", vaultPath, err)
	}

	c.logger.Info("Private key materialized from Vault (RAM only)",
		zap.String("path", vaultPath),
	)

	return &EphemeralSigner{
		signer:   signer,
		rawBytes: rawBytes,
	}, nil
}

// zeroBytes overwrites a byte slice with zeros.
// Used on error paths before returning, so key material never outlives an error.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0x00
	}
	runtime.KeepAlive(b)
}

// stripKVPrefix removes the "secret/data/" prefix that appears in vault_secret_path
// DB column values. The KVv2 API adds this prefix itself, so we strip it first.
//
//	"secret/data/ssh/prod-db-01" → "ssh/prod-db-01"
//	"ssh/prod-db-01"             → "ssh/prod-db-01"  (no-op)
func stripKVPrefix(path string) string {
	const prefix = "secret/data/"
	if len(path) > len(prefix) && path[:len(prefix)] == prefix {
		return path[len(prefix):]
	}
	return path
}

// PutSecret stores a private key and its fingerprint into Vault KV v2.
func (c *Client) PutSecret(ctx context.Context, vaultPath string, privateKey string, fingerprint string) error {
	c.mu.RLock()
	c.api.SetToken(c.token)
	c.mu.RUnlock()

	keyName := stripKVPrefix(vaultPath)
	data := map[string]interface{}{
		"private_key": privateKey,
		"fingerprint": fingerprint,
	}

	_, err := c.api.KVv2("secret").Put(ctx, keyName, data)
	if err != nil {
		return fmt.Errorf("vault kv put [%s]: %w", vaultPath, err)
	}

	c.logger.Info("Provisioned new key in Vault", zap.String("path", vaultPath))
	return nil
}
