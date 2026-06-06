// cmd/proxy/handlers.go
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nagdevnihal/zttp/internal/killswitch"
)

// killSwitchHandler handles POST /api/sessions/{id}/terminate
func killSwitchHandler(db *sql.DB, ksClient *killswitch.KillSwitchClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("id")
		if sessionID == "" {
			http.Error(w, "missing session ID", http.StatusBadRequest)
			return
		}

		// Step 1: Look up which proxy node holds this session
		var proxyNodeIP string
		err := db.QueryRowContext(r.Context(), `
            SELECT proxy_node_ip::text FROM active_sessions
            WHERE session_id = $1 AND status = 'active'
        `, sessionID).Scan(&proxyNodeIP)
		if err == sql.ErrNoRows {
			http.Error(w, "Session not found or already terminated", http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		// Step 2: Route kill signal to the correct proxy node via gRPC
		if err := ksClient.TerminateSession(proxyNodeIP, sessionID, "admin-kill"); err != nil {
			http.Error(w, fmt.Sprintf("Kill switch failed: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "terminated", "session_id": sessionID})
	}
}
