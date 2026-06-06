// internal/audit/diskguard.go
package audit

import (
	"fmt"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// DiskGuard monitors audit log partition usage and signals when the proxy
// should reject new connections (at maxUsagePct % capacity).
type DiskGuard struct {
	logDir      string
	maxUsagePct uint64
	reject      atomic.Bool
	logger      *zap.Logger
}

func NewDiskGuard(logDir string, maxUsagePct int, logger *zap.Logger) *DiskGuard {
	g := &DiskGuard{
		logDir:      logDir,
		maxUsagePct: uint64(maxUsagePct),
		logger:      logger,
	}
	go g.monitor()
	return g
}

// ShouldRejectNewConnections returns true if the disk is too full for new sessions.
func (g *DiskGuard) ShouldRejectNewConnections() bool {
	return g.reject.Load()
}

func (g *DiskGuard) monitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		pct, err := g.usagePercent()
		if err != nil {
			g.logger.Error("Disk usage check failed", zap.Error(err))
			continue
		}
		if pct >= g.maxUsagePct {
			if !g.reject.Load() {
				g.logger.Error("AUDIT DISK CRITICAL — rejecting new connections",
					zap.Uint64("usage_pct", pct),
				)
			}
			g.reject.Store(true)
		} else {
			if g.reject.Load() {
				g.logger.Info("Audit disk recovered — accepting connections", zap.Uint64("usage_pct", pct))
			}
			g.reject.Store(false)
		}
	}
}

func (g *DiskGuard) usagePercent() (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(g.logDir, &stat); err != nil {
		return 0, fmt.Errorf("statfs: %w", err)
	}
	total := stat.Blocks * uint64(stat.Bsize)
	avail := stat.Bavail * uint64(stat.Bsize)
	used := total - avail
	if total == 0 {
		return 0, nil
	}
	return (used * 100) / total, nil
}
