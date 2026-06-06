// internal/session/store.go
package session

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Status values for the active_sessions.status column
const (
	StatusActive            = "active"
	StatusTerminated        = "terminated"
	StatusTerminatedTimeout = "terminated-timeout"
	StatusTerminatedKill    = "terminated-kill"
)

// SessionRecord mirrors the active_sessions row.
type SessionRecord struct {
	SessionID   uuid.UUID
	UserID      uuid.UUID
	ServerID    uuid.UUID
	ProxyNodeIP net.IP
	StartTime   time.Time
	Status      string
	// Joined fields
	Username string
	Hostname string
}

// Store manages Active_Sessions CRUD operations.
type Store struct {
	db     *sql.DB
	logger *zap.Logger
}

func NewStore(db *sql.DB, logger *zap.Logger) *Store {
	return &Store{db: db, logger: logger}
}

// Register inserts a new active session row at PTY establishment.
func (s *Store) Register(ctx context.Context, sessionID, userID, serverID uuid.UUID, proxyNodeIP net.IP) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO active_sessions (session_id, user_id, server_id, proxy_node_ip, start_time, status)
        VALUES ($1, $2, $3, $4::inet, NOW(), 'active')
    `, sessionID, userID, serverID, proxyNodeIP.String())
	if err != nil {
		return fmt.Errorf("register session: %w", err)
	}
	s.logger.Info("Session registered",
		zap.String("session_id", sessionID.String()),
		zap.String("user_id", userID.String()),
		zap.String("server_id", serverID.String()),
	)
	return nil
}

// Terminate marks a session as ended. Called on normal exit, keepalive timeout, or kill switch.
func (s *Store) Terminate(ctx context.Context, sessionID uuid.UUID, status string) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE active_sessions
        SET status = $1
        WHERE session_id = $2
    `, status, sessionID)
	if err != nil {
		return fmt.Errorf("terminate session [%s]: %w", sessionID, err)
	}
	s.logger.Info("Session terminated",
		zap.String("session_id", sessionID.String()),
		zap.String("status", status),
	)
	return nil
}

// GetActiveByProxyNode returns all active sessions on a specific proxy node.
// Used by the Kill Switch gRPC server (Phase 7) to route termination signals.
func (s *Store) GetActiveByProxyNode(ctx context.Context, proxyIP string) ([]SessionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT session_id, user_id, server_id, proxy_node_ip::text, start_time, status
        FROM active_sessions
        WHERE status = 'active'
          AND proxy_node_ip = $1::inet
    `, proxyIP)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []SessionRecord
	for rows.Next() {
		var r SessionRecord
		var ipStr string
		if err := rows.Scan(&r.SessionID, &r.UserID, &r.ServerID, &ipStr, &r.StartTime, &r.Status); err != nil {
			return nil, err
		}
		r.ProxyNodeIP = net.ParseIP(ipStr)
		sessions = append(sessions, r)
	}
	return sessions, rows.Err()
}

// ListAllActive returns all currently active sessions (for security dashboard).
func (s *Store) ListAllActive(ctx context.Context) ([]SessionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT
            a.session_id, a.user_id, a.server_id,
            a.proxy_node_ip::text, a.start_time, a.status,
            u.username, s.hostname
        FROM active_sessions a
        JOIN users u ON u.id = a.user_id
        JOIN servers s ON s.id = a.server_id
        WHERE a.status = 'active'
        ORDER BY a.start_time DESC
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []SessionRecord
	for rows.Next() {
		var r SessionRecord
		var ipStr string
		if err := rows.Scan(&r.SessionID, &r.UserID, &r.ServerID, &ipStr, &r.StartTime, &r.Status, &r.Username, &r.Hostname); err != nil {
			return nil, err
		}
		r.ProxyNodeIP = net.ParseIP(ipStr)
		sessions = append(sessions, r)
	}
	return sessions, rows.Err()
}
