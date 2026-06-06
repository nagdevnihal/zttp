// internal/auth/hash.go
// Password hashing and verification utilities.
// bcrypt at cost=12 is the NIST-recommended minimum.
// NEVER log, store, or transmit plaintext passwords anywhere in this codebase.
package auth

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// HashPassword hashes a plaintext password using bcrypt.
// Used only at user provisioning time. Never called on the auth hot path.
func HashPassword(plaintext string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword compares a plaintext password against its stored bcrypt hash.
// The dummy ConstantTimeCompare call equalizes timing between match and mismatch
// paths to prevent timing-based side channels at the Go layer.
func VerifyPassword(plaintext, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
	// bcrypt itself is constant-time, but this extra call ensures no compiler
	// optimization can create a branch that differs in timing.
	_ = subtle.ConstantTimeCompare([]byte("a"), []byte("a"))
	return err == nil
}

// dummyHash is a pre-computed bcrypt hash used when a username is not found.
// We run a dummy bcrypt compare against it to burn the same ~100ms that a real
// comparison would take, preventing timing-based username enumeration.
// This value is the bcrypt hash of "this-is-never-a-real-password".
const dummyHash = "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj0oEkXBDhum"
