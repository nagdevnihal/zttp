// internal/audit/writer.go
package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Writer streams a .ttyrec audit log with identity attribution and SHA-256 integrity.
type Writer struct {
	mu        sync.Mutex
	file      *os.File
	hasher    hash.Hash
	logger    *zap.Logger
	sessionID uuid.UUID
	userID    uuid.UUID
}

// ttyrec header: 4+4+4 = 12 bytes per frame
type ttyrecHeader struct {
	Sec  uint32
	USec uint32
	Len  uint32
}

// NewWriter creates a new audit .ttyrec file for the given session.
// logDir must be on a dedicated partition (not the OS partition).
func NewWriter(logDir string, sessionID, userID uuid.UUID, logger *zap.Logger) (*Writer, error) {
	filename := filepath.Join(logDir, fmt.Sprintf("%s.ttyrec", sessionID.String()))
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("create audit file: %w", err)
	}

	w := &Writer{
		file:      file,
		logger:    logger,
		sessionID: sessionID,
		userID:    userID,
	}

	// Write identity attribution header as a special first frame
	w.writeAttributionHeader(sessionID, userID)

	return w, nil
}

// writeAttributionHeader writes a JSON attribution block as the first ttyrec frame.
// Security teams can read this to confirm session_id → user_id mapping without a DB query.
func (w *Writer) writeAttributionHeader(sessionID, userID uuid.UUID) {
	header := map[string]string{
		"zttp_session_id": sessionID.String(),
		"zttp_user_id":    userID.String(),
		"created_at":      time.Now().UTC().Format(time.RFC3339Nano),
		"format":          "ttyrec+zttp-v1",
	}
	data, _ := json.Marshal(header)
	w.writeFrame(data)
}

// Write implements io.Writer — called by TeeReader in Phase 5's stdin/stdout goroutines.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writeFrame(p)
	return len(p), nil
}

// writeFrame writes a single ttyrec-format frame.
func (w *Writer) writeFrame(data []byte) {
	now := time.Now()
	hdr := ttyrecHeader{
		Sec:  uint32(now.Unix()),
		USec: uint32(now.Nanosecond() / 1000),
		Len:  uint32(len(data)),
	}
	_ = binary.Write(w.file, binary.LittleEndian, hdr)
	_, _ = w.file.Write(data)
}

// Finalize flushes, computes SHA-256, writes the checksum sidecar, and closes the file.
// Called by Phase 5's Bridge function on session teardown.
func (w *Writer) Finalize(sessionID uuid.UUID) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.file.Sync(); err != nil {
		w.file.Close()
		return fmt.Errorf("audit sync: %w", err)
	}

	// Close before hashing since we open it again for reading
	fileName := w.file.Name()
	w.file.Close()

	// Compute SHA-256 of the complete .ttyrec file
	f, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("open for hash: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash compute: %w", err)
	}
	checksum := hex.EncodeToString(h.Sum(nil))

	// Write checksum as a sidecar .sha256 file
	checksumFile := fileName + ".sha256"
	return os.WriteFile(checksumFile, []byte(checksum+"\n"), 0600)
}
