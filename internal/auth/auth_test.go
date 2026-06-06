// internal/auth/auth_test.go
// Unit tests for the authentication engine.
// These tests run against a real (dockerized) PostgreSQL database.
// To run: DATABASE_URL="postgres://zttp:zttpsecret@localhost:5432/zttp?sslmode=disable" go test -v -race ./internal/auth/
package auth

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/nagdevnihal/zttp/internal/config"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

// testDB opens a real DB connection for integration tests.
// Skips the test if DATABASE_URL is not set.
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

// testConfig returns a minimal config for tests.
func testConfig() *config.Config {
	return &config.Config{
		MaxFailedAttempts: 5,
		LockoutDuration:   15 * time.Minute,
		SOCWebhookURL:     "", // disabled in tests
	}
}

// resetUser resets the failed_attempts and locked_until for a test user.
func resetUser(t *testing.T, db *sql.DB, username string) {
	t.Helper()
	_, err := db.Exec(`UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = $1`, username)
	if err != nil {
		t.Fatalf("resetUser: %v", err)
	}
}

// ── Hash Tests (pure unit tests — no DB needed) ──────────────────────────────

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("mysecretpassword")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if len(hash) == 0 {
		t.Fatal("expected non-empty hash")
	}
	// bcrypt hashes always start with $2a$12$ at cost=12
	if hash[:7] != "$2a$12$" {
		t.Errorf("expected bcrypt hash starting with $2a$12$, got: %s", hash[:7])
	}
}

func TestVerifyPassword_Match(t *testing.T) {
	hash, _ := HashPassword("correctpassword")
	if !VerifyPassword("correctpassword", hash) {
		t.Error("expected VerifyPassword to return true for matching password")
	}
}

func TestVerifyPassword_Mismatch(t *testing.T) {
	hash, _ := HashPassword("correctpassword")
	if VerifyPassword("wrongpassword", hash) {
		t.Error("expected VerifyPassword to return false for wrong password")
	}
}

// ── Integration Tests (require running PostgreSQL) ────────────────────────────

func TestAuthenticate_Success(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	resetUser(t, db, "jdoe")

	auth := New(db, testConfig(), zap.NewNop())
	user, err := auth.Authenticate(context.Background(), "jdoe", "devpassword123")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if user.Username != "jdoe" {
		t.Errorf("expected username 'jdoe', got '%s'", user.Username)
	}
	if user.Role != "sre-tier1" {
		t.Errorf("expected role 'sre-tier1', got '%s'", user.Role)
	}
}

func TestAuthenticate_WrongPassword(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	resetUser(t, db, "alice")

	auth := New(db, testConfig(), zap.NewNop())
	_, err := auth.Authenticate(context.Background(), "alice", "thewrongpassword")
	if err != ErrAuthentication {
		t.Errorf("expected ErrAuthentication, got: %v", err)
	}
}

func TestAuthenticate_UnknownUser(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	auth := New(db, testConfig(), zap.NewNop())
	_, err := auth.Authenticate(context.Background(), "doesnotexist", "anypassword")
	if err != ErrAuthentication {
		t.Errorf("expected ErrAuthentication for unknown user, got: %v", err)
	}
}

func TestAuthenticate_AccountLockout(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	resetUser(t, db, "bob")

	cfg := testConfig()
	cfg.MaxFailedAttempts = 3 // lower threshold for test speed
	auth := New(db, cfg, zap.NewNop())

	// Fail 3 times to trigger lockout
	for i := 0; i < 3; i++ {
		_, err := auth.Authenticate(context.Background(), "bob", "wrongpassword")
		if err != ErrAuthentication {
			t.Fatalf("attempt %d: expected ErrAuthentication, got: %v", i+1, err)
		}
	}

	// Lockout is written synchronously on the threshold-crossing attempt,
	// so no sleep needed — next request immediately hits ErrAccountLocked.

	// 4th attempt should hit lockout
	_, err := auth.Authenticate(context.Background(), "bob", "wrongpassword")
	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked after threshold, got: %v", err)
	}

	// Correct password should also be rejected while locked
	_, err = auth.Authenticate(context.Background(), "bob", "devpassword123")
	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked even with correct password, got: %v", err)
	}

	// Reset for other tests
	resetUser(t, db, "bob")
}

func TestAuthenticate_SuccessResetsCounter(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	resetUser(t, db, "jdoe")

	cfg := testConfig()
	cfg.MaxFailedAttempts = 5
	auth := New(db, cfg, zap.NewNop())

	// Fail twice
	for i := 0; i < 2; i++ {
		auth.Authenticate(context.Background(), "jdoe", "wrong") //nolint:errcheck
	}
	// No sleep needed — counter increment is synchronous (atomic DB update).

	// Verify counter incremented
	var attempts int
	db.QueryRow(`SELECT failed_attempts FROM users WHERE username = 'jdoe'`).Scan(&attempts) //nolint:errcheck
	if attempts != 2 {
		t.Errorf("expected failed_attempts=2, got %d", attempts)
	}

	// Now succeed
	_, err := auth.Authenticate(context.Background(), "jdoe", "devpassword123")
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}

	// Counter should be reset to 0
	db.QueryRow(`SELECT failed_attempts FROM users WHERE username = 'jdoe'`).Scan(&attempts) //nolint:errcheck
	if attempts != 0 {
		t.Errorf("expected failed_attempts=0 after success, got %d", attempts)
	}

	resetUser(t, db, "jdoe")
}
