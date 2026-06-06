package db

// internal/db/db.go
// PostgreSQL connection pool management.
//
// CRITICAL: The pool is strictly bounded at DB_MAX_OPEN_CONNS (default: 50).
// Without this, a burst of 500 concurrent authentications would open 500 raw
// connections, exceeding PostgreSQL's max_connections limit and causing a
// cascading "too many clients" failure (PRD Scenario 6 — The 9 AM Spike).

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"github.com/nagdevnihal/zttp/internal/config"
)

// Connect opens a PostgreSQL connection pool with bounds enforced.
// It also verifies the connection with a Ping() before returning.
func Connect(cfg *config.Config) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	// ── Bounded pool — prevents PostgreSQL starvation ──────────────────────
	db.SetMaxOpenConns(cfg.DBMaxOpenConns)
	db.SetMaxIdleConns(cfg.DBMaxIdleConns)
	db.SetConnMaxLifetime(30 * time.Minute) // recycle stale connections
	db.SetConnMaxIdleTime(5 * time.Minute)  // release idle connections faster

	// Verify connection is live before returning
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping postgres: %w\n  Is Postgres running? Try: docker compose up -d postgres", err)
	}

	return db, nil
}
