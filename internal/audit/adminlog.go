// internal/audit/adminlog.go
package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AdminLogger appends plain-text audit lines to admin-actions.log inside the
// audit log directory. It is safe for concurrent use.
type AdminLogger struct {
	mu       sync.Mutex
	file     *os.File
	adminUser string
}

// NewAdminLogger opens (or creates) admin-actions.log for appending.
func NewAdminLogger(logDir, adminUsername string) (*AdminLogger, error) {
	path := filepath.Join(logDir, "admin-actions.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open admin log: %w", err)
	}
	return &AdminLogger{file: f, adminUser: adminUsername}, nil
}

// Log writes a single timestamped event line to the admin log file.
// event should be one of the defined event tags (e.g. "[LOGIN]").
// detail is a human-readable description of the action.
func (l *AdminLogger) Log(event, detail string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().UTC().Format(time.RFC3339)
	line := fmt.Sprintf("%-24s  %-18s  %s logged in as admin: %s\n", ts, event, l.adminUser, detail)
	// For LOGIN/LOGOUT, the detail already includes the right description so we
	// build a slightly different line for those to avoid "logged in as admin: logged in".
	line = fmt.Sprintf("%-24s  %-18s  %s\n", ts, event, detail)
	_, _ = l.file.WriteString(line)
	_ = l.file.Sync()
}

// Close flushes and closes the log file. Should be deferred by the caller.
func (l *AdminLogger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.file.Sync()
	_ = l.file.Close()
}
