package main

// cmd/proxy/main.go
// ZTTP Proxy Server — the central gateway for all infrastructure SSH access.
//
// Startup sequence:
//   1. Load configuration from environment variables
//   2. Connect to PostgreSQL (bounded pool)
//   3. Start HTTP server (/healthz, /readyz) for NLB probing
//   4. [Phase 4] Initialize Vault client
//   5. [Phase 2] Start authentication engine
//   6. [Phase 5] Start SSH proxy listener (TLS 1.3)
//   7. [Phase 7] Start gRPC Kill Switch server
//   8. Block on OS signal (SIGTERM/SIGINT for graceful shutdown)

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/nagdevnihal/zttp/internal/auth"
	"github.com/nagdevnihal/zttp/internal/audit"
	"github.com/nagdevnihal/zttp/internal/config"
	"github.com/nagdevnihal/zttp/internal/db"
	"github.com/nagdevnihal/zttp/internal/health"
	"github.com/nagdevnihal/zttp/internal/killswitch"
	"github.com/nagdevnihal/zttp/internal/proxy"
	"github.com/nagdevnihal/zttp/internal/ratelimit"
	"github.com/nagdevnihal/zttp/internal/rbac"
	"github.com/nagdevnihal/zttp/internal/session"
	"github.com/nagdevnihal/zttp/internal/vault"
)

// Build-time variables — injected via ldflags:
// go build -ldflags="-X main.Version=1.0.0 -X main.GitCommit=abc123"
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	// ── Logger ────────────────────────────────────────────────────────────────
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("ZTTP Proxy starting",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("git_commit", GitCommit),
	)

	// ── Configuration ─────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("Configuration load failed", zap.Error(err))
	}
	logger.Info("Configuration loaded",
		zap.String("proxy_addr", cfg.ProxyListenAddr),
		zap.String("http_addr", cfg.HTTPListenAddr),
		zap.String("grpc_addr", cfg.GRPCListenAddr),
		zap.String("proxy_node_ip", cfg.ProxyNodeIP),
		zap.Int("db_max_open_conns", cfg.DBMaxOpenConns),
	)

	// ── PostgreSQL ────────────────────────────────────────────────────────────
	database, err := db.Connect(cfg)
	if err != nil {
		logger.Fatal("PostgreSQL connection failed", zap.Error(err))
	}
	defer database.Close()
	logger.Info("PostgreSQL connected",
		zap.Int("max_open_conns", cfg.DBMaxOpenConns),
		zap.Int("max_idle_conns", cfg.DBMaxIdleConns),
	)

	// ── HTTP Server (/healthz + /readyz for NLB + /api) ────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", health.Handler(database))
	mux.HandleFunc("/readyz", health.ReadyHandler())

	// Initialize a KillSwitchClient that uses the proxy's TLS CA (in dev, same as cert)
	// In production, we'd load a dedicated internal CA for service-to-service gRPC.
	ksClient := killswitch.NewKillSwitchClient(cfg.TLSCertFile)
	mux.HandleFunc("POST /api/sessions/{id}/terminate", killSwitchHandler(database, ksClient))

	httpServer := &http.Server{
		Addr:         cfg.HTTPListenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		logger.Info("HTTP health server listening", zap.String("addr", cfg.HTTPListenAddr))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	// ── Phase 4: Vault Client ────────────────────────────────────────────────
	vaultClient, err := vault.New(cfg, logger)
	if err != nil {
		logger.Fatal("Vault client initialization failed", zap.Error(err))
	}
	logger.Info("Vault client ready",
		zap.String("addr", cfg.VaultAddr),
		zap.Bool("dev_mode", cfg.VaultDevMode || cfg.VaultToken != ""),
	)

	// ── Phase 2: Authentication Engine ──────────────────────────────────────
	authenticator := auth.New(database, cfg, logger)
	logger.Info("Authentication engine ready",
		zap.Int("max_failed_attempts", cfg.MaxFailedAttempts),
		zap.Duration("lockout_duration", cfg.LockoutDuration),
	)

	// ── Phase 2: IP Rate Limiter (pre-TLS, pre-bcrypt) ───────────────────────
	rateLimiter := ratelimit.New(cfg.RateLimitPerMin)
	go rateLimiter.Cleanup() // background goroutine to evict stale IP entries
	logger.Info("IP rate limiter active",
		zap.Int("requests_per_min_per_ip", cfg.RateLimitPerMin),
	)

	// ── Phase 3: RBAC Policy Engine ────────────────────────────────────────
	policyEngine := rbac.New(database, logger)
	logger.Info("RBAC policy engine ready")

	// ── Phase 6: Session Management & Audit Logging ──────────────────────
	if err := os.MkdirAll(cfg.AuditLogDir, 0755); err != nil {
		logger.Fatal("Failed to create audit log directory", zap.Error(err))
	}
	diskGuard := audit.NewDiskGuard(cfg.AuditLogDir, cfg.AuditDiskMaxPct, logger)
	sessionStore := session.NewStore(database, logger)
	logger.Info("Audit disk guard active", zap.String("dir", cfg.AuditLogDir), zap.Int("max_pct", cfg.AuditDiskMaxPct))

	// Clean up orphaned sessions from a previous crash/restart of this node
	if err := sessionStore.CleanupOrphanedSessions(context.Background(), cfg.ProxyNodeIP); err != nil {
		logger.Warn("Failed to clean up orphaned sessions", zap.Error(err))
	}

	// Suppress until Phase 8 consumes all these
	_ = authenticator
	_ = rateLimiter
	_ = policyEngine
	_ = vaultClient
	_ = diskGuard
	_ = sessionStore

	// ── Phase 7: Start gRPC Kill Switch server ───────────────────────────
	connManager := killswitch.NewConnectionManager(logger)
	ksServer := killswitch.NewKillSwitchServer(connManager, sessionStore, logger)
	go func() {
		// Use TLS certs configured for the proxy (can be separated for production)
		if err := killswitch.StartGRPCServer(cfg.GRPCListenAddr, ksServer, cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
			logger.Fatal("Failed to start gRPC Kill Switch server", zap.Error(err))
		}
	}()
	logger.Info("Kill Switch gRPC server active", zap.String("addr", cfg.GRPCListenAddr))

	// ── Phase 5+8: Start SSH proxy listener and Accept Loop ────────────────
	tlsListener, err := proxy.NewTLSListener(cfg.ProxyListenAddr, cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		logger.Fatal("Failed to start proxy listener", zap.Error(err))
	}
	defer tlsListener.Close()
	logger.Info("SSH proxy listener active (TLS 1.3)", zap.String("addr", cfg.ProxyListenAddr))

	proxyServer := &proxy.Server{
		Auth:         authenticator,
		RateLimiter:  rateLimiter,
		Policy:       policyEngine,
		Vault:        vaultClient,
		SessionStore: sessionStore,
		ConnManager:  connManager,
		DiskGuard:    diskGuard,
		Logger:       logger,
		DB:           database,
		ProxyNodeIP:  cfg.ProxyNodeIP,
		AuditLogDir:  cfg.AuditLogDir,
		VaultDevMode: cfg.VaultDevMode || cfg.VaultToken != "",
	}

	go proxyServer.AcceptLoop(context.Background(), tlsListener)

	// ── Graceful Shutdown ─────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	logger.Info("Shutdown signal received", zap.String("signal", sig.String()))

	// Give in-flight requests 15 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("HTTP server shutdown error", zap.Error(err))
	}

	logger.Info("ZTTP Proxy shut down cleanly")
}
