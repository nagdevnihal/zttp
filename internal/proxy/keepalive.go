// internal/proxy/keepalive.go
// TCP Keepalive / Zombie PTY Detection
package proxy

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/nagdevnihal/zttp/internal/session"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// runKeepalive sends SSH keepalive pings and declares the client dead if
// consecutive pings are missed. Closes the backend SSH client.
func runKeepalive(ctx context.Context, client *ssh.Client, sessionID uuid.UUID,
	store *session.Store, logger *zap.Logger) {

	// Hardcoded values based on PRD §6.5
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	missedPings := 0
	maxMiss := 3

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Send SSH ignore-message keepalive (does not require server support)
			_, _, err := client.SendRequest("keepalive@zttp", true, nil)
			if err != nil {
				missedPings++
				logger.Warn("Keepalive missed",
					zap.String("session_id", sessionID.String()),
					zap.Int("missed", missedPings),
				)
				if missedPings >= maxMiss {
					logger.Warn("Client declared dead — closing zombie PTY",
						zap.String("session_id", sessionID.String()),
					)
					// Mark as timeout-terminated in DB, close backend
					_ = store.Terminate(context.Background(), sessionID, "terminated-timeout")
					client.Close()
					return
				}
			} else {
				missedPings = 0 // Reset on successful pong
			}
		}
	}
}
