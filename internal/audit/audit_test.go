// internal/audit/audit_test.go
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestWriterLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	sessionID := uuid.New()
	userID := uuid.New()
	logger := zap.NewNop()

	writer, err := NewWriter(tempDir, sessionID, userID, logger)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Write some dummy data
	dummyData := []byte("hello terminal")
	n, err := writer.Write(dummyData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(dummyData) {
		t.Fatalf("expected %d bytes written, got %d", len(dummyData), n)
	}

	err = writer.Finalize(sessionID)
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	// Verify files exist
	ttyrecPath := filepath.Join(tempDir, sessionID.String()+".ttyrec")
	sha256Path := filepath.Join(tempDir, sessionID.String()+".ttyrec.sha256")

	if _, err := os.Stat(ttyrecPath); os.IsNotExist(err) {
		t.Errorf("expected ttyrec file to exist at %s", ttyrecPath)
	}

	shaBytes, err := os.ReadFile(sha256Path)
	if err != nil {
		t.Fatalf("expected sha256 file to exist: %v", err)
	}

	// Compute hash manually to verify
	f, _ := os.Open(ttyrecPath)
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	expectedHash := hex.EncodeToString(h.Sum(nil))

	gotHash := strings.TrimSpace(string(shaBytes))
	if expectedHash != gotHash {
		t.Errorf("SHA-256 mismatch: expected %s, got %s", expectedHash, gotHash)
	}
}

func TestDiskGuard_UsagePercent(t *testing.T) {
	// A bit tricky to test real disk usage, but we can call it to ensure it doesn't panic
	// and returns a value between 0 and 100.
	logger := zap.NewNop()
	guard := NewDiskGuard(t.TempDir(), 95, logger)

	pct, err := guard.usagePercent()
	if err != nil {
		t.Fatalf("usagePercent failed: %v", err)
	}
	if pct < 0 || pct > 100 {
		t.Errorf("expected percentage between 0 and 100, got %d", pct)
	}
}
