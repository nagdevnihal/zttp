package config

// internal/config/config.go
// Central configuration system using environment variables with sane defaults.
// Uses Viper for env var binding. All sensitive values (passwords, tokens) come
// ONLY from env vars — never from config files committed to version control.

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config holds all runtime configuration for the ZTTP proxy.
type Config struct {
	// ── Proxy Server ─────────────────────────────────────────────────────────
	ProxyListenAddr string `mapstructure:"PROXY_LISTEN_ADDR"` // e.g. "0.0.0.0:2222"
	HTTPListenAddr  string `mapstructure:"HTTP_LISTEN_ADDR"`  // e.g. "0.0.0.0:8080" for /healthz
	GRPCListenAddr  string `mapstructure:"GRPC_LISTEN_ADDR"`  // e.g. "0.0.0.0:9090" for kill switch
	ProxyNodeIP     string `mapstructure:"PROXY_NODE_IP"`     // This node's internal IP (for session tracking)

	// ── TLS ──────────────────────────────────────────────────────────────────
	TLSCertFile string `mapstructure:"TLS_CERT_FILE"` // Path to TLS certificate (PEM)
	TLSKeyFile  string `mapstructure:"TLS_KEY_FILE"`  // Path to TLS private key (PEM)

	// ── PostgreSQL ───────────────────────────────────────────────────────────
	DatabaseURL    string `mapstructure:"DATABASE_URL"`     // Full DSN: postgres://user:pass@host:5432/db?sslmode=...
	DBMaxOpenConns int    `mapstructure:"DB_MAX_OPEN_CONNS"` // Max open connections — caps at 50 to prevent PG starvation
	DBMaxIdleConns int    `mapstructure:"DB_MAX_IDLE_CONNS"` // Max idle connections in pool

	// ── HashiCorp Vault ──────────────────────────────────────────────────────
	VaultAddr     string `mapstructure:"VAULT_ADDR"`      // e.g. "https://vault.internal:8200"
	VaultToken    string `mapstructure:"VAULT_TOKEN"`     // Dev only — overrides AppRole in local dev
	VaultRoleID   string `mapstructure:"VAULT_ROLE_ID"`   // AppRole RoleID (not a secret itself)
	VaultSecretID string `mapstructure:"VAULT_SECRET_ID"` // AppRole SecretID (treat as secret)
	// VaultDevMode: when true, use VAULT_TOKEN directly; skip AppRole (local dev only)
	VaultDevMode bool `mapstructure:"VAULT_DEV_MODE"`

	// ── Authentication Security ───────────────────────────────────────────────
	MaxFailedAttempts int           `mapstructure:"MAX_FAILED_ATTEMPTS"` // Lockout after N failures (default: 5)
	LockoutDuration   time.Duration `mapstructure:"LOCKOUT_DURATION"`    // Lockout period (default: 15m)
	RateLimitPerMin   int           `mapstructure:"RATE_LIMIT_PER_MIN"`  // Max auth attempts/min per IP (default: 10)

	// ── Audit Logging ────────────────────────────────────────────────────────
	AuditLogDir     string `mapstructure:"AUDIT_LOG_DIR"`      // Must be on dedicated partition
	AuditDiskMaxPct int    `mapstructure:"AUDIT_DISK_MAX_PCT"` // Reject new sessions above this % (default: 95)

	// ── TCP Keepalive (Zombie PTY detection) ────────────────────────────────
	KeepaliveInterval time.Duration `mapstructure:"KEEPALIVE_INTERVAL"` // Ping frequency (default: 30s)
	KeepaliveMaxMiss  int           `mapstructure:"KEEPALIVE_MAX_MISS"` // Missed pings before declaring dead (default: 3)

	// ── Integrations ─────────────────────────────────────────────────────────
	SOCWebhookURL string `mapstructure:"SOC_WEBHOOK_URL"` // Security Operations Center alert webhook
}

// Load reads configuration from environment variables, falling back to defaults.
// An optional .env file is read if present (for local development convenience).
func Load() (*Config, error) {
	v := viper.New()
	v.AutomaticEnv()

	// Load .env file if present (local dev only — not for production)
	v.SetConfigFile(".env")
	v.SetConfigType("env")
	_ = v.ReadInConfig() // silently ignore if file doesn't exist

	// ── Defaults ─────────────────────────────────────────────────────────────
	v.SetDefault("PROXY_LISTEN_ADDR", "0.0.0.0:2222")
	v.SetDefault("HTTP_LISTEN_ADDR", "0.0.0.0:8080")
	v.SetDefault("GRPC_LISTEN_ADDR", "0.0.0.0:9090")
	v.SetDefault("PROXY_NODE_IP", "127.0.0.1")
	v.SetDefault("TLS_CERT_FILE", "deploy/certs/server.pem")
	v.SetDefault("TLS_KEY_FILE", "deploy/certs/server.key")
	v.SetDefault("DATABASE_URL", "postgres://zttp:zttpsecret@localhost:5432/zttp?sslmode=disable")
	v.SetDefault("DB_MAX_OPEN_CONNS", 50)
	v.SetDefault("DB_MAX_IDLE_CONNS", 10)
	v.SetDefault("VAULT_ADDR", "http://localhost:8200")
	v.SetDefault("VAULT_TOKEN", "")
	v.SetDefault("VAULT_ROLE_ID", "")
	v.SetDefault("VAULT_SECRET_ID", "")
	v.SetDefault("VAULT_DEV_MODE", false)
	v.SetDefault("MAX_FAILED_ATTEMPTS", 5)
	v.SetDefault("LOCKOUT_DURATION", "15m")
	v.SetDefault("RATE_LIMIT_PER_MIN", 10)
	v.SetDefault("AUDIT_LOG_DIR", "/var/log/zttp/audit")
	v.SetDefault("AUDIT_DISK_MAX_PCT", 95)
	v.SetDefault("KEEPALIVE_INTERVAL", "30s")
	v.SetDefault("KEEPALIVE_MAX_MISS", 3)

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config unmarshal: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return &cfg, nil
}

// validate checks required fields and sane values.
func validate(cfg *Config) error {
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.VaultAddr == "" {
		return fmt.Errorf("VAULT_ADDR is required")
	}
	if cfg.MaxFailedAttempts < 1 {
		return fmt.Errorf("MAX_FAILED_ATTEMPTS must be >= 1")
	}
	if cfg.DBMaxOpenConns < 1 || cfg.DBMaxOpenConns > 200 {
		return fmt.Errorf("DB_MAX_OPEN_CONNS must be between 1 and 200")
	}
	return nil
}
