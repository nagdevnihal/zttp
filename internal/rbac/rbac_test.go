// internal/rbac/rbac_test.go
// Integration tests for the RBAC policy engine.
// Requires a running PostgreSQL with seed data from Phase 1.
//
// Run: DATABASE_URL="postgres://zttp:zttpsecret@localhost:5432/zttp?sslmode=disable" \
//      go test -v -race ./internal/rbac/
package rbac

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

// testDB opens a DB connection, skipping if Postgres is unreachable.
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

// ── Authorization Tests ───────────────────────────────────────────────────────

// sre-tier1 can access all environments including production
func TestAuthorize_SRECanAccessProduction(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	engine := New(db, zap.NewNop())
	access, err := engine.Authorize(context.Background(), "sre-tier1", "prod-db-01")
	if err != nil {
		t.Fatalf("expected authorization, got error: %v", err)
	}
	if access.Hostname != "prod-db-01" {
		t.Errorf("expected hostname prod-db-01, got %s", access.Hostname)
	}
	if access.Environment != "production" {
		t.Errorf("expected environment 'production', got '%s'", access.Environment)
	}
	if access.PrivateIP == nil {
		t.Error("expected non-nil PrivateIP")
	}
	if access.VaultPath == "" {
		t.Error("expected non-empty VaultPath")
	}
	if access.VaultPath != "secret/data/ssh/prod-db-01" {
		t.Errorf("expected vault path 'secret/data/ssh/prod-db-01', got '%s'", access.VaultPath)
	}
}

// backend-dev cannot access production — this is the core RBAC denial scenario
func TestAuthorize_BackendDevDeniedProduction(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	engine := New(db, zap.NewNop())
	_, err := engine.Authorize(context.Background(), "backend-dev", "prod-db-01")
	if err != ErrPermissionDenied {
		t.Errorf("expected ErrPermissionDenied, got: %v", err)
	}
}

// backend-dev CAN access staging
func TestAuthorize_BackendDevCanAccessStaging(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	engine := New(db, zap.NewNop())
	access, err := engine.Authorize(context.Background(), "backend-dev", "stage-web-01")
	if err != nil {
		t.Fatalf("expected staging access for backend-dev, got: %v", err)
	}
	if access.Environment != "staging" {
		t.Errorf("expected environment 'staging', got '%s'", access.Environment)
	}
}

// auditor role is restricted to dev only
func TestAuthorize_AuditorDeniedStaging(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	engine := New(db, zap.NewNop())
	_, err := engine.Authorize(context.Background(), "auditor", "stage-web-01")
	if err != ErrPermissionDenied {
		t.Errorf("expected ErrPermissionDenied for auditor on staging, got: %v", err)
	}
}

// auditor CAN access dev
func TestAuthorize_AuditorCanAccessDev(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	engine := New(db, zap.NewNop())
	access, err := engine.Authorize(context.Background(), "auditor", "dev-app-01")
	if err != nil {
		t.Fatalf("expected dev access for auditor, got: %v", err)
	}
	// auditor has a command whitelist — AllowedCmds must be non-nil
	if len(access.AllowedCmds) == 0 {
		t.Error("expected non-empty AllowedCmds for auditor role")
	}
}

// Unknown hostname must return ErrUnknownHost
func TestAuthorize_UnknownHost(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	engine := New(db, zap.NewNop())
	_, err := engine.Authorize(context.Background(), "sre-tier1", "nonexistent-host-99")
	if err != ErrUnknownHost {
		t.Errorf("expected ErrUnknownHost, got: %v", err)
	}
}

// A role with no policy row must be denied
func TestAuthorize_RoleWithNoPolicy(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	engine := New(db, zap.NewNop())
	_, err := engine.Authorize(context.Background(), "nonexistent-role", "dev-app-01")
	if err != ErrPermissionDenied {
		t.Errorf("expected ErrPermissionDenied for undefined role, got: %v", err)
	}
}

// sre-tier1 must get nil AllowedCmds (full shell, no whitelist)
func TestAuthorize_SREHasFullShell(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	engine := New(db, zap.NewNop())
	access, err := engine.Authorize(context.Background(), "sre-tier1", "dev-app-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(access.AllowedCmds) != 0 {
		t.Errorf("expected nil/empty AllowedCmds for sre-tier1 (full shell), got: %v", access.AllowedCmds)
	}
}

// Verify the returned PrivateIP is a valid IP address
func TestAuthorize_ValidPrivateIP(t *testing.T) {
	db := testDB(t)
	defer db.Close()

	engine := New(db, zap.NewNop())
	access, err := engine.Authorize(context.Background(), "sre-tier1", "dev-app-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if access.PrivateIP == nil {
		t.Fatal("expected non-nil PrivateIP")
	}
	if access.PrivateIP.String() != "10.0.1.10" {
		t.Errorf("expected PrivateIP 10.0.1.10, got %s", access.PrivateIP.String())
	}
}
