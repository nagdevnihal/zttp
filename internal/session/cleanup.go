// internal/session/cleanup.go
package session

import (
	"context"

	"go.uber.org/zap"
)

// CleanupOrphanedSessions marks any active sessions belonging to this proxy node
// as terminated. This is called on proxy startup to clean up sessions that were
// interrupted by an ungraceful shutdown or crash.
func (s *Store) CleanupOrphanedSessions(ctx context.Context, proxyNodeIP string) error {
	result, err := s.db.ExecContext(ctx, `
        UPDATE active_sessions
        SET status = 'terminated'
        WHERE proxy_node_ip = $1::inet
          AND status = 'active'
    `, proxyNodeIP)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows > 0 {
		s.logger.Warn("Cleaned up orphaned sessions from previous proxy instance",
			zap.Int64("count", rows),
			zap.String("proxy_ip", proxyNodeIP),
		)
	}
	return nil
}
