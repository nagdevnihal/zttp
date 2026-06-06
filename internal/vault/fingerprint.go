// internal/vault/fingerprint.go
// SSH host key fingerprint verification.
//
// The proxy verifies the backend server's host key against the fingerprint stored
// in Vault before completing the SSH handshake. This prevents:
//   - DNS spoofing: attacker changes DNS to point hostname at their server
//   - ARP poisoning: attacker intercepts traffic on the internal network
//   - MITM by rogue server: attacker spins up a server at the target IP
//
// All three attacks are neutralized because the expected fingerprint comes from
// Vault (a trusted, authenticated source), not from the OS known_hosts file or
// from the connecting client.
package vault

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
)

// FetchHostFingerprint retrieves the expected SSH host key fingerprint from Vault.
// It reads the "fingerprint" field from the same KV path as the private key.
//
// If the fingerprint field is empty or missing, an error is returned and
// the connection must be refused. We never fall back to an insecure verification.
func (c *Client) FetchHostFingerprint(ctx context.Context, vaultPath string) (string, error) {
	c.mu.RLock()
	c.api.SetToken(c.token)
	c.mu.RUnlock()

	keyName := stripKVPrefix(vaultPath)
	secret, err := c.api.KVv2("secret").Get(ctx, keyName)
	if err != nil {
		return "", fmt.Errorf("vault kv get fingerprint [%s]: %w", vaultPath, err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault secret empty at [%s]", vaultPath)
	}

	fp, ok := secret.Data["fingerprint"].(string)
	if !ok || fp == "" {
		// Missing fingerprint → fail closed. We cannot connect without verification.
		return "", fmt.Errorf("no 'fingerprint' field at vault path [%s] — connection refused", vaultPath)
	}

	return fp, nil
}

// StrictHostKeyCallback returns an ssh.HostKeyCallback that verifies the backend
// server's presented public key matches the Vault-stored fingerprint.
//
// If the fingerprint does not match, the error message explicitly says MITM DETECTED
// so it shows clearly in logs. The SSH library will abort the handshake.
//
// For dev mode where Vault seeds placeholder fingerprints, pass skipVerify=true.
// NEVER set skipVerify=true in production.
func StrictHostKeyCallback(expectedFingerprint string, skipVerify bool) ssh.HostKeyCallback {
	if skipVerify {
		// Dev-only: accept any host key (Vault has placeholder fingerprints)
		return ssh.InsecureIgnoreHostKey() //nolint:gosec
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		actual := computeFingerprint(key)
		if actual != expectedFingerprint {
			return fmt.Errorf(
				"MITM DETECTED: host key fingerprint mismatch for %s — "+
					"expected %s, got %s — connection aborted",
				hostname, expectedFingerprint, actual,
			)
		}
		return nil
	}
}

// computeFingerprint computes a SHA-256 fingerprint of an SSH public key,
// in the standard OpenSSH format: "SHA256:<base64-encoded-hash>".
// This matches the format returned by: ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub
func computeFingerprint(key ssh.PublicKey) string {
	digest := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(digest[:])
}
