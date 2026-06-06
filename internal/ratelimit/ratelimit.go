// internal/ratelimit/ratelimit.go
// IP-level rate limiter for the authentication endpoint.
//
// This operates at the TCP layer BEFORE TLS handshake and BEFORE bcrypt.
// Purpose: prevent credential stuffing and bcrypt CPU exhaustion.
// If an IP exceeds the rate limit, the TCP connection is dropped silently —
// no error message, no TLS, no bcrypt. The attacker learns nothing.
//
// Memory leak prevention: a background Cleanup() goroutine expires stale IP
// entries every 5 minutes so an attacker hitting from many IPs doesn't grow
// the map indefinitely.
package ratelimit

import (
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPRateLimiter enforces a per-source-IP token-bucket rate limit.
type IPRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	expiry   map[string]time.Time
	rps      rate.Limit    // tokens per second (fractional)
	burst    int           // maximum burst tokens
	ttl      time.Duration // how long to keep an idle IP entry
}

// New creates an IPRateLimiter allowing requestsPerMinute attempts per IP.
// Example: requestsPerMinute=10 → limiter allows ~0.167 req/sec with burst=10.
func New(requestsPerMinute int) *IPRateLimiter {
	rps := rate.Limit(float64(requestsPerMinute) / 60.0)
	return &IPRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		expiry:   make(map[string]time.Time),
		rps:      rps,
		burst:    requestsPerMinute, // allow a full minute's quota as initial burst
		ttl:      10 * time.Minute,
	}
}

// Allow returns true if the request from remoteAddr is within rate limits.
// Returns false if the IP has exceeded its quota — caller should drop the conn.
func (l *IPRateLimiter) Allow(remoteAddr string) bool {
	// Strip port — we rate-limit by IP, not by IP+port
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If parsing fails (e.g., unix socket), use the raw address
		ip = remoteAddr
	}

	l.mu.Lock()
	limiter, exists := l.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(l.rps, l.burst)
		l.limiters[ip] = limiter
	}
	l.expiry[ip] = time.Now().Add(l.ttl) // refresh TTL on each access
	l.mu.Unlock()

	return limiter.Allow()
}

// Cleanup removes stale IP entries to prevent unbounded memory growth.
// Start as a background goroutine on proxy startup:
//
//	go rateLimiter.Cleanup()
func (l *IPRateLimiter) Cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		l.mu.Lock()
		for ip, exp := range l.expiry {
			if now.After(exp) {
				delete(l.limiters, ip)
				delete(l.expiry, ip)
			}
		}
		l.mu.Unlock()
	}
}
