// internal/session/session_test.go
package session

import (
	"context"
	"database/sql"
	"net"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

// testDB opens a real DB connection for integration tests.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://zttp:zttpsecret@localhost:5432/zttp?sslmode=disable"
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("PostgreSQL not reachable (%v) — skipping integration test", err)
	}
	return db
}

// getTestUserAndServer grabs the UUIDs of an existing user and server from the seed data.
func getTestUserAndServer(t *testing.T, db *sql.DB) (uuid.UUID, uuid.UUID) {
	t.Helper()
	var userID, serverID uuid.UUID
	err := db.QueryRow("SELECT id FROM users WHERE username = 'jdoe'").Scan(&userID)
	if err != nil {
		t.Fatalf("failed to find jdoe: %v", err)
	}
	err = db.QueryRow("SELECT id FROM servers WHERE hostname = 'prod-db-01'").Scan(&serverID)
	if err != nil {
		t.Fatalf("failed to find prod-db-01: %v", err)
	}
	return userID, serverID
}

func TestStoreLifecycle(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	logger := zap.NewNop()
	store := NewStore(db, logger)
	ctx := context.Background()

	userID, serverID := getTestUserAndServer(t, db)
	sessionID := uuid.New()
	proxyIP := net.ParseIP("192.168.1.100")

	// 1. Register
	err := store.Register(ctx, sessionID, userID, serverID, proxyIP)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// 2. GetActiveByProxyNode
	sessions, err := store.GetActiveByProxyNode(ctx, proxyIP.String())
	if err != nil {
		t.Fatalf("GetActiveByProxyNode failed: %v", err)
	}
	found := false
	for _, s := range sessions {
		if s.SessionID == sessionID {
			found = true
			if s.Status != StatusActive {
				t.Errorf("expected status 'active', got %s", s.Status)
			}
		}
	}
	if !found {
		t.Errorf("session %s not found in GetActiveByProxyNode", sessionID)
	}

	// 3. ListAllActive
	allActive, err := store.ListAllActive(ctx)
	if err != nil {
		t.Fatalf("ListAllActive failed: %v", err)
	}
	found = false
	for _, s := range allActive {
		if s.SessionID == sessionID {
			found = true
			if s.Username != "jdoe" || s.Hostname != "prod-db-01" {
				t.Errorf("expected jdoe and prod-db-01, got %s and %s", s.Username, s.Hostname)
			}
		}
	}
	if !found {
		t.Errorf("session %s not found in ListAllActive", sessionID)
	}

	// 4. Terminate
	err = store.Terminate(ctx, sessionID, StatusTerminated)
	if err != nil {
		t.Fatalf("Terminate failed: %v", err)
	}

	// 5. Verify it's no longer active
	sessionsAfter, _ := store.GetActiveByProxyNode(ctx, proxyIP.String())
	for _, s := range sessionsAfter {
		if s.SessionID == sessionID {
			t.Errorf("session %s should not be active", sessionID)
		}
	}
}

func TestCleanupOrphanedSessions(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	logger := zap.NewNop()
	store := NewStore(db, logger)
	ctx := context.Background()

	userID, serverID := getTestUserAndServer(t, db)
	sessionID := uuid.New()
	proxyIP := net.ParseIP("192.168.1.101")

	_ = store.Register(ctx, sessionID, userID, serverID, proxyIP)

	err := store.CleanupOrphanedSessions(ctx, proxyIP.String())
	if err != nil {
		t.Fatalf("CleanupOrphanedSessions failed: %v", err)
	}

	// Verify the session is now terminated
	sessions, _ := store.GetActiveByProxyNode(ctx, proxyIP.String())
	for _, s := range sessions {
		if s.SessionID == sessionID {
			t.Errorf("session %s should have been cleaned up", sessionID)
		}
	}
}
