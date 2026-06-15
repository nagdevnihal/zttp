// internal/rbac/rbac.go
// RBAC Policy Engine — the second gate every connection passes through.
//
// After Phase 2 verifies *who* you are, Phase 3 determines *what* you can access.
//
// Design:
//   - Single optimized JOIN query: server lookup + policy check in one round-trip.
//   - The DB does the environment membership check via PostgreSQL's ANY() operator,
//     which uses the GIN index on the allowed_environments array column.
//   - Error responses are deliberately vague — the client always sees "Permission denied"
//     regardless of whether the denial was caused by an unknown host, missing policy,
//     or environment mismatch. This prevents infrastructure topology enumeration.
package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

// ── Sentinel Errors ───────────────────────────────────────────────────────────

// ErrPermissionDenied is the single external error for all RBAC denials.
// Callers must map ALL internal denial reasons to this before responding to clients.
var ErrPermissionDenied = errors.New("permission denied")

// ErrUnknownHost is returned when the hostname is not in the Servers table.
// NOTE: externally this must still map to "Permission denied" — see Error Response Policy.
var ErrUnknownHost = errors.New("unknown host")

// ── Authorization Result ──────────────────────────────────────────────────────

// AuthorizedAccess is the result of a successful RBAC check.
// It contains everything needed for Phase 4 (Vault key fetch) and Phase 5 (SSH dial).
type AuthorizedAccess struct {
	ServerID    uuid.UUID
	Hostname    string
	PrivateIP   net.IP
	Environment string
	SSHUser     string
	VaultPath   string        // e.g. "secret/data/ssh/prod-db-01"
	AllowedCmds []string      // nil = full interactive shell; non-nil = command whitelist
}

// ── Policy Engine ─────────────────────────────────────────────────────────────

// PolicyEngine evaluates RBAC rules using a single optimized JOIN query.
type PolicyEngine struct {
	db     *sql.DB
	logger *zap.Logger
}

// New creates a PolicyEngine backed by the given database pool.
func New(db *sql.DB, logger *zap.Logger) *PolicyEngine {
	return &PolicyEngine{db: db, logger: logger}
}

// Authorize checks whether a role can access the given target hostname.
//
// It executes a single JOIN query across servers and policies tables.
// PostgreSQL evaluates the environment membership check (ANY operator) server-side,
// using the indexed columns, keeping total authorization latency under 5ms.
//
// Returns:
//   - *AuthorizedAccess on success (carry this into Phase 4)
//   - ErrUnknownHost if hostname not found in servers table
//   - ErrPermissionDenied if role has no policy or environment is not allowed
//   - wrapped error on DB failure
func (e *PolicyEngine) Authorize(ctx context.Context, userID uuid.UUID, role, targetHostname string) (*AuthorizedAccess, error) {
	var (
		serverID     uuid.UUID
		hostname     string
		privateIPStr string
		environment  string
		sshUser      string
		vaultPath    string
		allowedCmds  pq.StringArray
		isAuthorized bool
		policyFound  bool
	)

	// Single JOIN query: resolve server + check policy in one DB round-trip.
	// The LEFT JOIN ensures we can distinguish "server not found" from "no policy".
	// is_authorized uses PostgreSQL's ANY() which leverages the GIN index on
	// allowed_environments for sub-millisecond array membership testing.
	err := e.db.QueryRowContext(ctx, `
		SELECT
			s.id,
			s.hostname,
			host(s.private_ip),
			s.environment,
			s.ssh_user,
			s.vault_secret_path,
			p.allowed_commands,
			(p.role IS NOT NULL)                        AS policy_found,
			COALESCE(
				EXISTS (SELECT 1 FROM user_server_grants g WHERE g.user_id = $3 AND g.server_id = s.id) OR
				(u.override_role_access = false AND s.environment = ANY(p.allowed_environments)),
				false
			)                                           AS is_authorized
		FROM servers s
		CROSS JOIN users u
		LEFT JOIN policies p ON p.role = $1
		WHERE s.hostname = $2 AND u.id = $3
	`, role, targetHostname, userID).Scan(
		&serverID, &hostname, &privateIPStr, &environment,
		&sshUser, &vaultPath, &allowedCmds, &policyFound, &isAuthorized,
	)

	// ── Case 1: Server hostname not in inventory ──────────────────────────────
	if err == sql.ErrNoRows {
		e.logger.Warn("RBAC: connection attempt to unknown host",
			zap.String("hostname", targetHostname),
			zap.String("role", role),
		)
		return nil, ErrUnknownHost
	}
	if err != nil {
		return nil, fmt.Errorf("rbac query: %w", err)
	}

	// ── Case 2: No policy row exists AND no direct grant ──────────────────────
	if !policyFound && !isAuthorized {
		e.logger.Warn("RBAC: no policy defined for role and no direct grant",
			zap.String("role", role),
			zap.String("hostname", targetHostname),
		)
		return nil, ErrPermissionDenied
	}

	// ── Case 3: Environment not in allowed_environments ───────────────────────
	if !isAuthorized {
		e.logger.Warn("RBAC: environment not permitted for role",
			zap.String("role", role),
			zap.String("hostname", targetHostname),
			zap.String("environment", environment),
		)
		return nil, ErrPermissionDenied
	}

	// ── Authorized ────────────────────────────────────────────────────────────
	e.logger.Info("RBAC: authorized",
		zap.String("role", role),
		zap.String("hostname", targetHostname),
		zap.String("environment", environment),
		zap.Bool("command_whitelist_active", len(allowedCmds) > 0),
	)

	return &AuthorizedAccess{
		ServerID:    serverID,
		Hostname:    hostname,
		PrivateIP:   net.ParseIP(privateIPStr),
		Environment: environment,
		SSHUser:     sshUser,
		VaultPath:   vaultPath,
		AllowedCmds: []string(allowedCmds), // nil if DB value was NULL
	}, nil
}
