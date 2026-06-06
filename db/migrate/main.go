package main

// db/migrate/main.go
// Run with: go run ./db/migrate/
// Applies all SQL migration files in db/migrations/ in sorted order.
// Safe to re-run — uses IF NOT EXISTS throughout.

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	_ "github.com/lib/pq"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://zttp:zttpsecret@localhost:5432/zttp?sslmode=disable"
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("❌ open db: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("❌ ping db: %v\n   Is Postgres running? Check: docker compose up -d postgres", err)
	}
	fmt.Println("✓ Connected to PostgreSQL")

	// Discover migration files
	files, err := filepath.Glob("db/migrations/*.sql")
	if err != nil || len(files) == 0 {
		log.Fatal("❌ No migration files found in db/migrations/")
	}
	sort.Strings(files) // ensures 001 → 002 → 003 → 004 order

	// Apply each migration in a separate transaction
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("❌ read %s: %v", f, err)
		}

		tx, err := db.Begin()
		if err != nil {
			log.Fatalf("❌ begin tx for %s: %v", f, err)
		}

		if _, err := tx.Exec(string(content)); err != nil {
			tx.Rollback()
			log.Fatalf("❌ Migration failed [%s]: %v", f, err)
		}

		if err := tx.Commit(); err != nil {
			log.Fatalf("❌ commit %s: %v", f, err)
		}

		fmt.Printf("✓ Applied: %s\n", f)
	}

	fmt.Println("\n✅ All migrations applied successfully.")
}
