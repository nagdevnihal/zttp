// internal/auth/auth.go
// Authentication engine — the first gate every connection passes through.
//
// Security properties maintained by this package:
//   - Fail-closed: DB outage → all new auth denied (no cached credentials)
//   - Timing-safe: unknown username takes same time as wrong password
//   - Error-masked: all failures return the same generic message
//   - Fail2ban-style: 5 failures → 15-minute lockout written to DB
//   - Async SOC: lockout events fire a webhook without blocking the auth path
package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nagdevnihal/zttp/internal/config"
	"go.uber.org/zap"
)

// ── Sentinel Errors ──────────────────────────────────────────────────────────

// ErrAuthentication means credentials were wrong. Generic — covers both
// "user not found" and "wrong password" so neither is distinguishable.
var ErrAuthentication = errors.New("authentication failed")

// ErrAccountLocked means too many failed attempts; lockout is active.
var ErrAccountLocked = errors.New("account temporarily locked")

// ── Authenticated Identity ───────────────────────────────────────────────────

// User is the verified identity returned on successful authentication.
// Passed to the RBAC engine (Phase 3) for authorization decisions.
type User struct {
	ID       uuid.UUID
	Username string
	Role     string
}

// ── Authenticator ────────────────────────────────────────────────────────────

// Authenticator verifies credentials against the PostgreSQL users table.
type Authenticator struct {
	db     *sql.DB
	cfg    *config.Config
	logger *zap.Logger
	http   *http.Client
}

// New creates an Authenticator. Inject a *sql.DB with a bounded pool (Phase 1).
func New(db *sql.DB, cfg *config.Config, logger *zap.Logger) *Authenticator {
	return &Authenticator{
		db:     db,
		cfg:    cfg,
		logger: logger,
		http:   &http.Client{Timeout: 5 * time.Second},
	}
}

// Authenticate verifies credentials and returns the verified identity or an error.
// CRITICAL: callers must never expose the specific error type to the client —
// always return the same generic message regardless of which sentinel error occurred.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*User, error) {
	var (
		id          uuid.UUID
		storedHash  string
		role        string
		lockedUntil sql.NullTime
	)

	// ── Step 1: Fetch user record ─────────────────────────────────────────────
	err := a.db.QueryRowContext(ctx, `
		SELECT id, password_hash, role, locked_until
		FROM users
		WHERE username = $1
	`, username).Scan(&id, &storedHash, &role, &lockedUntil)

	if err == sql.ErrNoRows {
		// User not found — run dummy bcrypt to equalize timing and prevent
		// timing-based username enumeration.
		_ = VerifyPassword(password, dummyHash)
		a.logger.Warn("Authentication attempt for unknown username",
			zap.String("username", username),
		)
		return nil, ErrAuthentication
	}
	if err != nil {
		return nil, fmt.Errorf("auth db query: %w", err)
	}

	// ── Step 2: Check lockout BEFORE bcrypt (fast-path rejection) ─────────────
	if lockedUntil.Valid && time.Now().UTC().Before(lockedUntil.Time) {
		remaining := time.Until(lockedUntil.Time).Round(time.Minute)
		a.logger.Warn("Attempt on locked account",
			zap.String("username", username),
			zap.Duration("remaining_lockout", remaining),
		)
		return nil, ErrAccountLocked
	}

	// ── Step 3: Verify password — expensive bcrypt operation ──────────────────
	if !VerifyPassword(password, storedHash) {
		// Use a DB-side atomic increment (failed_attempts = failed_attempts + 1)
		// to avoid read-then-write races when multiple requests come in concurrently.
		// The RETURNING clause gives us the new value to decide if lockout is needed.
		lockUntil, locked, incErr := a.atomicIncrementAndMaybeLock(ctx, id, username)
		if incErr != nil {
			a.logger.Error("Failed to record failed attempt", zap.Error(incErr))
		}
		if locked {
			go a.fireSOCAlert(username, a.cfg.MaxFailedAttempts, lockUntil)
		}
		return nil, ErrAuthentication
	}

	// ── Step 4: Success — reset failure counter ───────────────────────────────
	_, err = a.db.ExecContext(ctx, `
		UPDATE users
		SET failed_attempts = 0, locked_until = NULL
		WHERE id = $1
	`, id)
	if err != nil {
		a.logger.Error("Failed to reset failed_attempts after successful auth",
			zap.String("username", username), zap.Error(err))
	}

	a.logger.Info("Authentication successful", zap.String("username", username))
	return &User{ID: id, Username: username, Role: role}, nil
}

// ── Internal Helpers ──────────────────────────────────────────────────────────

// atomicIncrementAndMaybeLock atomically increments failed_attempts in the DB
// and, if the new count hits the threshold, sets locked_until in the same query.
// This single-statement approach eliminates read-write races under concurrency.
// Returns the lockUntil time, whether an account was locked, and any error.
func (a *Authenticator) atomicIncrementAndMaybeLock(ctx context.Context, userID uuid.UUID, username string) (time.Time, bool, error) {
	lockDuration := a.cfg.LockoutDuration
	threshold := a.cfg.MaxFailedAttempts

	var newCount int
	var lockedUntil sql.NullTime

	// Single atomic UPDATE: increment the counter and conditionally set locked_until
	// when the threshold is first crossed. The CASE expression ensures locked_until
	// is only set on the exact crossing attempt, not on every subsequent failure.
	err := a.db.QueryRowContext(ctx, `
		UPDATE users
		SET
			failed_attempts = failed_attempts + 1,
			locked_until = CASE
				WHEN failed_attempts + 1 >= $1 AND locked_until IS NULL
				THEN NOW() + ($2 * INTERVAL '1 second')
				ELSE locked_until
			END
		WHERE id = $3
		RETURNING failed_attempts, locked_until
	`, threshold, int(lockDuration.Seconds()), userID).Scan(&newCount, &lockedUntil)

	if err != nil {
		return time.Time{}, false, fmt.Errorf("atomic increment: %w", err)
	}

	locked := lockedUntil.Valid && time.Now().UTC().Before(lockedUntil.Time)

	if locked {
		a.logger.Warn("Account locked — threshold exceeded",
			zap.String("username", username),
			zap.Int("failed_attempts", newCount),
			zap.Time("locked_until", lockedUntil.Time),
		)
		return lockedUntil.Time, true, nil
	}

	a.logger.Warn("Failed authentication attempt",
		zap.String("username", username),
		zap.Int("failed_attempts", newCount),
		zap.Int("threshold", threshold),
	)
	return time.Time{}, false, nil
}

// fireSOCAlert posts a JSON alert to the SOC webhook.
// No-ops if SOCWebhookURL is empty (local dev mode).
func (a *Authenticator) fireSOCAlert(username string, attempts int, lockedUntil time.Time) {
	if a.cfg.SOCWebhookURL == "" {
		return
	}
	payload := map[string]interface{}{
		"event":        "account_locked",
		"severity":     "high",
		"username":     username,
		"attempts":     attempts,
		"locked_until": lockedUntil.Format(time.RFC3339),
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		a.logger.Error("SOC alert marshal failed", zap.Error(err))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.SOCWebhookURL, bytes.NewReader(body))
	if err != nil {
		a.logger.Error("SOC alert request creation failed", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		a.logger.Error("SOC webhook delivery failed", zap.Error(err))
		return
	}
	defer resp.Body.Close()
	a.logger.Info("SOC alert fired",
		zap.String("username", username),
		zap.Int("status_code", resp.StatusCode),
	)
}
