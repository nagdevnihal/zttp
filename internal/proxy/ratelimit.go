// internal/proxy/ratelimit.go
// TCP Backpressure / Cat Bomb Mitigation
//
// These wrappers enforce per-stream throughput limits on the SSH bridge.
// By using golang.org/x/time/rate.Limiter, we apply TCP backpressure up
// the stack to the sender, rather than buffering unbounded amounts of data
// in memory, which would cause an OOM (Scenario 1: The Cat Bomb).
package proxy

import (
	"context"
	"io"

	"golang.org/x/time/rate"
)

// rateLimitedReader wraps an io.Reader with a token-bucket rate limiter.
type rateLimitedReader struct {
	r       io.Reader
	limiter *rate.Limiter
}

// newRateLimitedReader creates a rate-limited io.Reader.
func newRateLimitedReader(r io.Reader, bytesPerSec float64, burst int) io.Reader {
	return &rateLimitedReader{
		r:       r,
		limiter: rate.NewLimiter(rate.Limit(bytesPerSec), burst),
	}
}

// Read reads from the underlying reader and blocks until the rate limiter allows it.
func (rl *rateLimitedReader) Read(p []byte) (int, error) {
	n, err := rl.r.Read(p)
	if n > 0 {
		if waitErr := rl.limiter.WaitN(context.Background(), n); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

// rateLimitedWriter wraps an io.Writer with a token-bucket rate limiter.
type rateLimitedWriter struct {
	w       io.Writer
	limiter *rate.Limiter
}

// newRateLimitedWriter creates a rate-limited io.Writer.
func newRateLimitedWriter(w io.Writer, bytesPerSec float64, burst int) io.Writer {
	return &rateLimitedWriter{
		w:       w,
		limiter: rate.NewLimiter(rate.Limit(bytesPerSec), burst),
	}
}

// Write blocks until the rate limiter allows it, then writes to the underlying writer.
func (rl *rateLimitedWriter) Write(p []byte) (int, error) {
	if err := rl.limiter.WaitN(context.Background(), len(p)); err != nil {
		return 0, err
	}
	return rl.w.Write(p)
}
