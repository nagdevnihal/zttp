package health

// internal/health/health.go
// Health check HTTP handler for the NLB to probe.
// The NLB polls GET /healthz every 5 seconds.
// A non-200 response causes the node to be drained from the load balancer.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

// Status is the JSON response body returned by /healthz.
type Status struct {
	Status    string `json:"status"`              // "ok" | "degraded"
	Database  string `json:"database"`            // "ok" | "unreachable"
	Timestamp string `json:"timestamp"`           // RFC3339 UTC
	Uptime    string `json:"uptime,omitempty"`    // seconds since start
}

var startTime = time.Now()

// Handler returns an HTTP handler that reports system health.
// Used by the NLB to detect and drain failed proxy nodes.
func Handler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := Status{
			Status:    "ok",
			Database:  "ok",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Uptime:    time.Since(startTime).Round(time.Second).String(),
		}
		code := http.StatusOK

		// Check DB connectivity with a short timeout
		pingCtx := r.Context()
		if err := db.PingContext(pingCtx); err != nil {
			status.Status = "degraded"
			status.Database = "unreachable"
			code = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(status) //nolint:errcheck
	}
}

// ReadyHandler is a simpler liveness probe — just returns 200 if the process is alive.
func ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready")) //nolint:errcheck
	}
}
