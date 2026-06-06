// internal/proxy/accept.go
package proxy

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/nagdevnihal/zttp/internal/audit"
	"github.com/nagdevnihal/zttp/internal/auth"
	"github.com/nagdevnihal/zttp/internal/killswitch"
	"github.com/nagdevnihal/zttp/internal/ratelimit"
	"github.com/nagdevnihal/zttp/internal/rbac"
	"github.com/nagdevnihal/zttp/internal/session"
	"github.com/nagdevnihal/zttp/internal/vault"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// ConnectRequest matches the CLI's struct
type ConnectRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Target     string `json:"target"`
	TermWidth  int    `json:"term_width"`
	TermHeight int    `json:"term_height"`
}

// Server holds all dependencies needed to accept and bridge connections.
type Server struct {
	Auth         *auth.Authenticator
	RateLimiter  *ratelimit.IPRateLimiter
	Policy       *rbac.PolicyEngine
	Vault        *vault.Client
	SessionStore *session.Store
	ConnManager  *killswitch.ConnectionManager
	DiskGuard    *audit.DiskGuard
	Logger       *zap.Logger
	DB           *sql.DB

	ProxyNodeIP  string
	AuditLogDir  string
	VaultDevMode bool
}

// AcceptLoop runs the main server accept loop. Blocks until listener is closed.
func (s *Server) AcceptLoop(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.Logger.Error("TLS accept failed", zap.Error(err))
				continue
			}
		}

		go s.handleConnection(ctx, conn)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close() // Ensure connection is closed when this goroutine returns

	// Step 1: Enforce IP rate limiting early
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if !s.RateLimiter.Allow(ip) {
		s.deny(conn, "rate limit exceeded — back off", false)
		return
	}

	// Step 2: Enforce disk capacity guard
	if s.DiskGuard.ShouldRejectNewConnections() {
		s.deny(conn, "system under heavy load — connection rejected", false)
		return
	}

	// Step 3: Parse ConnectRequest
	req, err := s.readConnectRequest(conn)
	if err != nil {
		s.deny(conn, fmt.Sprintf("invalid protocol: %v", err), false)
		return
	}

	s.Logger.Info("Connection request received", zap.String("user", req.Username), zap.String("target", req.Target))

	// Step 4: Authenticate (Phase 2)
	authCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	user, err := s.Auth.Authenticate(authCtx, req.Username, req.Password)
	if err != nil {
		s.Logger.Warn("Authentication failed", zap.String("user", req.Username), zap.Error(err))
		s.deny(conn, "authentication failed", false)
		return
	}

	// Step 4.5: Intercept Admin Console
	if req.Target == "zttp-admin" {
		if user.Role == "security-admin" {
			s.Logger.Info("Admin console session started", zap.String("user", user.Username))
			s.ackReady(conn, false)
			s.handleAdminConsole(ctx, conn, user.Username)
			return
		}
		s.Logger.Warn("Unauthorized access to admin console", zap.String("user", user.Username))
		s.deny(conn, "access denied by RBAC policy", false)
		return
	}

	// Step 4.5: Gateway Menu (Dynamic Server Selection)
	if req.Target == "zttp-gateway" {
		s.Logger.Info("Gateway menu session started", zap.String("user", user.Username))
		s.ackReady(conn, false)
		
		for {
			target, err := s.handleGatewayMenu(ctx, conn, user.ID, user.Role)
			if err != nil {
				s.Logger.Info("Gateway menu exited", zap.Error(err))
				return
			}
			req.Target = target // Overwrite target with user's selection
			
			// If they selected the admin console from the gateway, route them directly there
			if req.Target == "zttp-admin" {
				s.Logger.Info("Admin console session started from gateway", zap.String("user", user.Username))
				s.handleAdminConsole(ctx, conn, user.Username)
				continue // Loop back to the gateway menu!
			}

			// Perform connection
			s.connectToTarget(ctx, conn, req, user, true)
		}
	} else {
		// Normal direct connection
		s.connectToTarget(ctx, conn, req, user, false)
	}
}

func (s *Server) connectToTarget(ctx context.Context, conn net.Conn, req *ConnectRequest, user *auth.User, isInteractiveHandoff bool) error {
	opCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Step 5: Authorize against target server (Phase 3)
	target, err := s.Policy.Authorize(opCtx, user.ID, user.Role, req.Target)
	if err != nil {
		s.Logger.Warn("Authorization failed", zap.String("user", user.Username), zap.String("target", req.Target))
		s.deny(conn, "access denied by RBAC policy", isInteractiveHandoff)
		return err
	}

	// Step 6: Fetch Secrets
	signer, err := s.Vault.FetchPrivateKey(opCtx, target.VaultPath)
	if err != nil {
		s.Logger.Error("Failed to get Vault ephemeral key", zap.Error(err))
		s.deny(conn, "internal proxy error", isInteractiveHandoff)
		return err
	}
	defer signer.Zero() // Guarantee memory wiping when function exits

	fp, err := s.Vault.FetchHostFingerprint(opCtx, target.VaultPath)
	if err != nil {
		s.Logger.Error("Failed to fetch host fingerprint", zap.Error(err))
		s.deny(conn, "internal proxy error", isInteractiveHandoff)
		return err
	}

	hostKeyCb := vault.StrictHostKeyCallback(fp, s.VaultDevMode)

	// Step 7: Dial Backend via SSH
	sshConfig := &ssh.ClientConfig{
		User:            target.SSHUser, // using the target server's specific SSH username (e.g. root/ubuntu)
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer.Signer())},
		HostKeyCallback: hostKeyCb,
		Timeout:         5 * time.Second,
	}

	targetAddr := fmt.Sprintf("%s:22", target.PrivateIP.String())
	sshClient, err := ssh.Dial("tcp", targetAddr, sshConfig)
	if err != nil {
		s.Logger.Error("SSH dial failed", zap.Error(err))
		s.deny(conn, "failed to connect to target server", isInteractiveHandoff)
		return err
	}

	// Step 8: Acknowledge Ready
	s.ackReady(conn, isInteractiveHandoff)

	// Step 9: Initialize Audit Writer (Phase 6)
	sessionID := uuid.New()
	auditWriter, err := audit.NewWriter(s.AuditLogDir, sessionID, user.ID, s.Logger)
	if err != nil {
		s.Logger.Error("Failed to initialize audit log", zap.Error(err))
		// We can't safely deny here because we already sent Ready. So we just close.
		sshClient.Close()
		if !isInteractiveHandoff {
			conn.Close()
		}
		return err
	}
	defer auditWriter.Finalize(sessionID)

	// Step 10: Launch Bridge (Phase 5)
	bcfg := &BridgeConfig{
		SessionID:    sessionID,
		UserID:       user.ID,
		ServerID:     target.ServerID,
		ProxyNodeIP:  net.ParseIP(s.ProxyNodeIP),
		ClientConn:   conn,
		SSHClient:    sshClient,
		TermWidth:    req.TermWidth,
		TermHeight:   req.TermHeight,
		AllowedCmds:  target.AllowedCmds,
		AuditWriter:  auditWriter,
		SessionStore: s.SessionStore,
		ConnManager:  s.ConnManager,
		Logger:       s.Logger,
	}

	if err := Bridge(ctx, bcfg); err != nil {
		s.Logger.Error("Session bridge error", zap.String("session", sessionID.String()), zap.Error(err))
		if isInteractiveHandoff {
			s.clearScreen(conn)
			msg := fmt.Sprintf("\r\n\033[31mSession Error:\033[0m %v\r\n\r\nPress any key to continue...", err)
			conn.Write([]byte(msg))
			s.readKey(conn)
		} else {
			conn.Close()
		}
		return err
	}

	if !isInteractiveHandoff {
		conn.Close()
	}

	return nil
}

// readConnectRequest reads the 4-byte length header and the JSON payload.
func (s *Server) readConnectRequest(conn net.Conn) (*ConnectRequest, error) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	msgLen := binary.BigEndian.Uint32(lenBuf)
	if msgLen > 4096 { // Sanity check
		return nil, fmt.Errorf("request payload too large: %d bytes", msgLen)
	}

	data := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Time{}) // Clear deadline

	var req ConnectRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// deny sends the 0x01 status byte and the error message to the CLI, then closes the connection.
func (s *Server) deny(conn net.Conn, reason string, isInteractiveHandoff bool) {
	if isInteractiveHandoff {
		s.clearScreen(conn)
		msg := fmt.Sprintf("\r\n\033[31mError:\033[0m %s\r\n\r\nPress any key to continue...", reason)
		conn.Write([]byte(msg))
		s.readKey(conn)
		return // Do not close the connection so we can loop back to the gateway!
	} else {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte{0x01})
		msg := []byte(reason)
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(msg)))
		conn.Write(lenBuf)
		conn.Write(msg)
	}
	conn.Close()
}

// ackReady sends the 0x00 success byte to the CLI.
func (s *Server) ackReady(conn net.Conn, isInteractiveHandoff bool) {
	if isInteractiveHandoff {
		// The CLI is already in raw mode doing PTY passthrough. We don't send the protocol byte.
		// Just clear the screen for a clean terminal prompt!
		s.clearScreen(conn)
		return
	}
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.Write([]byte{0x00})
	conn.SetWriteDeadline(time.Time{})
}
