// internal/killswitch/manager_test.go
package killswitch

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestConnectionManager_RegisterAndDeregister(t *testing.T) {
	logger := zap.NewNop()
	cm := NewConnectionManager(logger)
	sessionID := uuid.New()

	handle := &SessionHandle{
		Cancel:     func() {},
		CloseConns: func() {},
	}

	cm.Register(sessionID, handle)

	cm.mu.RLock()
	_, exists := cm.sessions[sessionID]
	cm.mu.RUnlock()
	if !exists {
		t.Errorf("session not found after Register")
	}

	cm.Deregister(sessionID)

	cm.mu.RLock()
	_, exists = cm.sessions[sessionID]
	cm.mu.RUnlock()
	if exists {
		t.Errorf("session still found after Deregister")
	}
}

func TestConnectionManager_Terminate(t *testing.T) {
	logger := zap.NewNop()
	cm := NewConnectionManager(logger)
	sessionID := uuid.New()

	cancelCalled := false
	closeCalled := false

	handle := &SessionHandle{
		Cancel:     func() { cancelCalled = true },
		CloseConns: func() { closeCalled = true },
	}

	cm.Register(sessionID, handle)

	elapsed, err := cm.Terminate(sessionID, "admin-kill")
	if err != nil {
		t.Fatalf("Terminate failed: %v", err)
	}

	if !cancelCalled {
		t.Errorf("Cancel func was not called")
	}
	if !closeCalled {
		t.Errorf("CloseConns func was not called")
	}
	if elapsed < 0 {
		t.Errorf("elapsed time should be >= 0")
	}

	// Session should be deregistered automatically
	cm.mu.RLock()
	_, exists := cm.sessions[sessionID]
	cm.mu.RUnlock()
	if exists {
		t.Errorf("session still exists after Terminate")
	}
}

func TestConnectionManager_TerminateUnknownSession(t *testing.T) {
	logger := zap.NewNop()
	cm := NewConnectionManager(logger)
	sessionID := uuid.New()

	_, err := cm.Terminate(sessionID, "admin-kill")
	if err == nil {
		t.Errorf("expected error when terminating unknown session, got nil")
	}
}

func TestConnectionManager_Sub500ms(t *testing.T) {
	logger := zap.NewNop()
	cm := NewConnectionManager(logger)
	sessionID := uuid.New()

	ctx, cancel := context.WithCancel(context.Background())
	handle := &SessionHandle{
		Cancel: cancel,
		CloseConns: func() {
			// Simulate rapid socket teardown
			time.Sleep(10 * time.Millisecond)
		},
	}
	cm.Register(sessionID, handle)

	elapsed, err := cm.Terminate(sessionID, "admin-kill")
	if err != nil {
		t.Fatalf("Terminate failed: %v", err)
	}
	if ctx.Err() == nil {
		t.Errorf("context was not cancelled")
	}
	if elapsed > 500 {
		t.Errorf("expected termination to take < 500ms, took %d ms", elapsed)
	}
}
