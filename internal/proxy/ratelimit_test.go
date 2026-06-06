// internal/proxy/ratelimit_test.go
package proxy

import (
	"bytes"
	"testing"
	"time"
)

func TestRateLimitedReader(t *testing.T) {
	data := bytes.Repeat([]byte("a"), 1024)
	buf := bytes.NewReader(data)

	// Rate limit: 100 bytes/sec, burst 100
	rl := newRateLimitedReader(buf, 100, 100)

	start := time.Now()
	// We read 200 bytes. The first 100 should be immediate (burst).
	// We must read in chunks <= burst, otherwise WaitN fails.
	p := make([]byte, 100)
	n1, err := rl.Read(p)
	if err != nil {
		t.Fatalf("unexpected error on read 1: %v", err)
	}
	n2, err := rl.Read(p)
	if err != nil {
		t.Fatalf("unexpected error on read 2: %v", err)
	}
	if n1+n2 != 200 {
		t.Fatalf("expected 200 bytes, got %d", n1+n2)
	}
	elapsed := time.Since(start)

	// Expected time is ~1.0s, allow small variation (0.9 to 1.5s)
	if elapsed < 900*time.Millisecond {
		t.Errorf("rate limiter did not throttle: took only %v", elapsed)
	}
}

func TestRateLimitedWriter(t *testing.T) {
	var buf bytes.Buffer
	// Rate limit: 100 bytes/sec, burst 100
	rl := newRateLimitedWriter(&buf, 100, 100)

	data := bytes.Repeat([]byte("a"), 200)

	start := time.Now()
	// Write in chunks <= burst
	n1, err := rl.Write(data[:100])
	if err != nil {
		t.Fatalf("unexpected error on write 1: %v", err)
	}
	n2, err := rl.Write(data[100:])
	if err != nil {
		t.Fatalf("unexpected error on write 2: %v", err)
	}
	if n1+n2 != 200 {
		t.Fatalf("expected 200 bytes written, got %d", n1+n2)
	}
	elapsed := time.Since(start)

	if elapsed < 900*time.Millisecond {
		t.Errorf("rate limiter did not throttle: took only %v", elapsed)
	}
}
