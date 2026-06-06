// internal/vault/vault.go
// Vault client — handles authentication and token lifecycle.
//
// Two auth modes:
//   - Dev mode (VAULT_DEV_MODE=true): uses VAULT_TOKEN directly (local dev only)
//   - Prod mode: AppRole login → short-lived token → auto-renewed every 30 min
//
// Thread safety: all token reads/writes are protected by a RWMutex.
// The background renewToken goroutine re-authenticates (not just renews) to
// handle the case where the SecretID has been rotated by the security team.
package vault

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/nagdevnihal/zttp/internal/config"
	"go.uber.org/zap"
)

// Client wraps the HashiCorp Vault API client with token lifecycle management.
type Client struct {
	api    *vaultapi.Client
	cfg    *config.Config
	logger *zap.Logger
	mu     sync.RWMutex
	token  string
}

// New creates a Vault client and authenticates immediately.
// It starts a background token renewal goroutine before returning.
//
// Dev mode: VAULT_DEV_MODE=true skips AppRole and uses VAULT_TOKEN directly.
// Prod mode: requires VAULT_ROLE_ID + VAULT_SECRET_ID.
func New(cfg *config.Config, logger *zap.Logger) (*Client, error) {
	vaultCfg := vaultapi.DefaultConfig()
	vaultCfg.Address = cfg.VaultAddr

	// Use a custom HTTP client with an explicit timeout.
	// NOTE: In dev mode we allow HTTP (Vault dev server doesn't have TLS).
	// In production, Vault runs behind TLS and the transport will use system CAs.
	vaultCfg.HttpClient = &http.Client{
		Timeout: 10 * time.Second,
	}

	api, err := vaultapi.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("vault client init: %w", err)
	}

	c := &Client{api: api, cfg: cfg, logger: logger}

	if cfg.VaultDevMode || cfg.VaultToken != "" {
		// ── Dev mode: static token ────────────────────────────────────────────
		// Used when VAULT_TOKEN is set (local Docker Compose dev environment).
		// Token renewal is a no-op in this path.
		c.mu.Lock()
		c.token = cfg.VaultToken
		c.api.SetToken(cfg.VaultToken)
		c.mu.Unlock()
		logger.Info("Vault authenticated (dev mode — static token)", zap.String("token", c.token))
	} else {
		// ── Prod mode: AppRole authentication ────────────────────────────────
		if cfg.VaultRoleID == "" || cfg.VaultSecretID == "" {
			return nil, fmt.Errorf("VAULT_ROLE_ID and VAULT_SECRET_ID are required when VAULT_DEV_MODE is false")
		}
		if err := c.loginAppRole(context.Background()); err != nil {
			return nil, fmt.Errorf("vault approle login: %w", err)
		}
		// Start background token renewal — re-authenticates every 30 minutes.
		// Using full re-auth (not just renew) handles SecretID rotation transparently.
		go c.renewLoop()
		logger.Info("Vault authenticated (AppRole)",
			zap.String("addr", cfg.VaultAddr),
		)
	}

	return c, nil
}

// loginAppRole authenticates with Vault using AppRole credentials and stores the token.
func (c *Client) loginAppRole(ctx context.Context) error {
	data := map[string]interface{}{
		"role_id":   c.cfg.VaultRoleID,
		"secret_id": c.cfg.VaultSecretID,
	}

	secret, err := c.api.Logical().WriteWithContext(ctx, "auth/approle/login", data)
	if err != nil {
		return fmt.Errorf("approle login request: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("approle login returned empty auth response")
	}

	c.mu.Lock()
	c.token = secret.Auth.ClientToken
	c.api.SetToken(secret.Auth.ClientToken)
	c.mu.Unlock()

	c.logger.Info("Vault AppRole login successful",
		zap.Int("lease_duration_sec", secret.Auth.LeaseDuration),
		zap.Bool("renewable", secret.Auth.Renewable),
	)
	return nil
}

// renewLoop re-authenticates with Vault every 30 minutes.
// This runs as a background goroutine for the lifetime of the process.
// It uses a full re-login (not just token renewal) to be resilient to
// SecretID rotation without requiring a proxy restart.
func (c *Client) renewLoop() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if err := c.loginAppRole(context.Background()); err != nil {
			c.logger.Error("Vault token renewal failed — will retry next cycle",
				zap.Error(err),
			)
			// Token remains set from the previous successful login.
			// FetchPrivateKey calls will fail if the old token has expired,
			// which triggers fail-closed behavior as designed.
		}
	}
}

// setToken safely updates the active token (used by loginAppRole).
// The API client token is also updated so subsequent requests use it.
func (c *Client) setToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
	c.api.SetToken(token)
}
