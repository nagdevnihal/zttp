// internal/killswitch/manager.go
package killswitch

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SessionHandle holds the cancellation and close functions for an active session.
type SessionHandle struct {
	Cancel     func() // cancels the context passed to Bridge()
	CloseConns func() // closes client + backend TCP sockets
}

// ConnectionManager is the in-memory registry of active session handles.
// It is the single source of truth for session→socket mapping on this node.
type ConnectionManager struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID]*SessionHandle
	logger   *zap.Logger
}

func NewConnectionManager(logger *zap.Logger) *ConnectionManager {
	return &ConnectionManager{
		sessions: make(map[uuid.UUID]*SessionHandle),
		logger:   logger,
	}
}

// Register adds a session handle when PTY bridge is established.
func (cm *ConnectionManager) Register(sessionID uuid.UUID, handle *SessionHandle) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.sessions[sessionID] = handle
	cm.logger.Info("Session registered in connection manager",
		zap.String("session_id", sessionID.String()),
	)
}

// Deregister removes a session handle on clean exit.
func (cm *ConnectionManager) Deregister(sessionID uuid.UUID) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.sessions, sessionID)
}

// Terminate forcefully ends the session with the given ID.
// Returns elapsed milliseconds from call to socket close.
func (cm *ConnectionManager) Terminate(sessionID uuid.UUID, reason string) (int64, error) {
	start := time.Now()

	cm.mu.RLock()
	handle, exists := cm.sessions[sessionID]
	cm.mu.RUnlock()

	if !exists {
		return 0, fmt.Errorf("session %s not found on this node", sessionID)
	}

	cm.logger.Warn("Kill Switch activated",
		zap.String("session_id", sessionID.String()),
		zap.String("reason", reason),
	)

	// Cancel context first → goroutines begin unwinding
	handle.Cancel()

	// Forcefully close both sockets simultaneously
	handle.CloseConns()

	elapsed := time.Since(start).Milliseconds()
	cm.logger.Info("Session terminated by Kill Switch",
		zap.String("session_id", sessionID.String()),
		zap.Int64("elapsed_ms", elapsed),
	)

	cm.Deregister(sessionID)
	return elapsed, nil
}
