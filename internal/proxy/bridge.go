// internal/proxy/bridge.go
// SSH Proxy Bridge — the core dumb pipe connecting the CLI to the target server.
//
// Responsibilities:
//   - Request target PTY with proper dimensions
//   - Spawn io.CopyBuffer goroutines for stdin and stdout/stderr
//   - Enforce TCP backpressure rate limiting (Cat Bomb mitigation)
//   - Intercept and block multiplexer commands on stdin
//   - Handle zombie PTY cleanup via keepalives
//   - Fork all I/O to the audit recorder (Phase 6)
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nagdevnihal/zttp/internal/audit"
	"github.com/nagdevnihal/zttp/internal/killswitch"
	"github.com/nagdevnihal/zttp/internal/session"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	// Fixed 32 KB buffer per stream — prevents Cat Bomb OOM (Scenario 1)
	streamBufSize = 32 * 1024

	// Per-stream throughput cap: 15 MB/s (tokens per second)
	streamRateLimit = 15 * 1024 * 1024 // 15 MB/s
	streamBurst     = 32 * 1024        // 32 KB burst
)

// BridgeConfig holds all parameters needed to establish a PTY bridge.
type BridgeConfig struct {
	SessionID    uuid.UUID
	UserID       uuid.UUID
	ServerID     uuid.UUID
	ProxyNodeIP  net.IP
	ClientConn   net.Conn    // TLS connection from developer CLI
	SSHClient    *ssh.Client // Backend connection to target server
	TermWidth    int
	TermHeight   int
	AllowedCmds  []string // from RBAC policy (nil = full shell)
	AuditWriter  *audit.Writer
	SessionStore *session.Store
	ConnManager  *killswitch.ConnectionManager
	Logger       *zap.Logger
}

// Bridge establishes the bidirectional PTY proxy bridge.
// This function blocks until the session terminates.
func Bridge(ctx context.Context, cfg *BridgeConfig) error {
	// Step 1: Open an SSH session channel on the backend connection
	sshSess, err := cfg.SSHClient.NewSession()
	if err != nil {
		return fmt.Errorf("new ssh session: %w", err)
	}
	defer sshSess.Close()

	// Step 2: Request PTY from target server
	if err := sshSess.RequestPty("xterm-256color", cfg.TermHeight, cfg.TermWidth,
		ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}); err != nil {
		return fmt.Errorf("request pty: %w", err)
	}

	// Step 3: Start an interactive shell on the target
	backendStdin, err := sshSess.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	backendStdout, err := sshSess.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	// We want to merge stdout and stderr to the single ClientConn
	backendStderr, err := sshSess.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	backendMergedOut := io.MultiReader(backendStdout, backendStderr)

	if err := sshSess.Shell(); err != nil {
		return fmt.Errorf("start shell: %w", err)
	}

	// Step 4: Register session in Active_Sessions (Phase 6)
	if err := cfg.SessionStore.Register(ctx, cfg.SessionID, cfg.UserID, cfg.ServerID, cfg.ProxyNodeIP); err != nil {
		return fmt.Errorf("session register: %w", err)
	}
	defer cfg.SessionStore.Terminate(context.Background(), cfg.SessionID, "terminated")

	// ── Kill Switch Registration (Phase 7) ───────────────────────────────
	ctx, cancel := context.WithCancel(ctx)
	handle := &killswitch.SessionHandle{
		Cancel: cancel,
		CloseConns: func() {
			// Only close the backend SSH connection.
			// Do NOT close ClientConn, so the user can be seamlessly returned to the Gateway menu!
			cfg.SSHClient.Close()
		},
	}
	if cfg.ConnManager != nil {
		cfg.ConnManager.Register(cfg.SessionID, handle)
		defer cfg.ConnManager.Deregister(cfg.SessionID)
	}
	// ─────────────────────────────────────────────────────────────────────

	// Step 5: Spawn isolated goroutine pair for bidirectional copy
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// Stdin forwarder: client → backend (with rate limiter and cmd filter)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer backendStdin.Close()

		// 1. Rate limiter on raw client read
		limitedReader := newRateLimitedReader(cfg.ClientConn, streamRateLimit, streamBurst)

		// 2. Do not log stdin to prevent duplicated keystrokes and plain-text password logging
		// Audit log only records stdout (what the user actually sees)
		
		// 3. Filter for multiplexers / whitelist before writing to backend
		filterWriter := newCommandFilterWriter(backendStdin, cfg.ClientConn, cfg.AllowedCmds)

		_, err := io.CopyBuffer(filterWriter, limitedReader, make([]byte, streamBufSize))
		errCh <- err
	}()

	// Stdout forwarder: backend → client (with rate limiter)
	wg.Add(1)
	go func() {
		defer wg.Done()

		// 1. Rate limiter on raw client write
		limitedWriter := newRateLimitedWriter(cfg.ClientConn, streamRateLimit, streamBurst)

		// 2. Fork to audit log
		teeWriter := io.MultiWriter(limitedWriter, cfg.AuditWriter)

		_, err := io.CopyBuffer(teeWriter, backendMergedOut, make([]byte, streamBufSize))
		errCh <- err
	}()

	// Step 6: Keepalive loop — detects Zombie PTY (Scenario 4)
	go runKeepalive(ctx, cfg.SSHClient, cfg.SessionID, cfg.SessionStore, cfg.Logger)

	// Block until the FIRST goroutine exits (usually stdout, when the server drops connection)
	<-errCh

	// Force the stdin goroutine to unblock from reading ClientConn by setting an immediate deadline.
	// This prevents the "Enter key required to exit" bug.
	cfg.ClientConn.SetReadDeadline(time.Now())

	// Now wait for both goroutines to fully exit
	wg.Wait()

	// Reset the read deadline so the connection can be cleanly reused by the Gateway menu loop!
	cfg.ClientConn.SetReadDeadline(time.Time{})
	
	close(errCh)

	// Finalize audit log (Phase 6)
	if err := cfg.AuditWriter.Finalize(cfg.SessionID); err != nil {
		cfg.Logger.Error("Audit finalization failed", zap.Error(err), zap.String("session", cfg.SessionID.String()))
	}

	if ctx.Err() != nil {
		return fmt.Errorf("Access revoked by administrator")
	}

	return nil
}
