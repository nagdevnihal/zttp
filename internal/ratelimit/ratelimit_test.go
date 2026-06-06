// internal/ratelimit/ratelimit_test.go
// Unit tests for the IP rate limiter. Pure unit tests — no external deps.
package ratelimit

import (
	"fmt"
	"testing"
)

func TestAllow_UnderLimit(t *testing.T) {
	limiter := New(10) // 10 requests per minute

	// First 10 requests from same IP should all be allowed (burst)
	for i := 0; i < 10; i++ {
		if !limiter.Allow("192.168.1.1:54321") {
			t.Errorf("request %d should have been allowed", i+1)
		}
	}
}

func TestAllow_ExceedsLimit(t *testing.T) {
	limiter := New(5) // 5 requests per minute burst

	// Exhaust the burst
	for i := 0; i < 5; i++ {
		limiter.Allow("10.0.0.1:12345") //nolint:errcheck
	}

	// 6th request should be denied
	if limiter.Allow("10.0.0.1:12345") {
		t.Error("expected 6th request to be denied after burst exhausted")
	}
}

func TestAllow_IsolatedPerIP(t *testing.T) {
	limiter := New(2) // very low burst for test

	// Exhaust IP A
	limiter.Allow("1.1.1.1:100") //nolint:errcheck
	limiter.Allow("1.1.1.1:100") //nolint:errcheck
	limiter.Allow("1.1.1.1:100") // should be denied

	// IP B should still have its own full quota
	if !limiter.Allow("2.2.2.2:200") {
		t.Error("IP B should not be affected by IP A's exhaustion")
	}
}

func TestAllow_ManyIPs(t *testing.T) {
	limiter := New(10)

	// 1000 distinct IPs should all get their own limiter
	for i := 0; i < 1000; i++ {
		ip := fmt.Sprintf("10.0.%d.%d:1234", i/256, i%256)
		if !limiter.Allow(ip) {
			t.Errorf("new IP %s should have been allowed on first request", ip)
		}
	}
}

func TestAllow_InvalidAddr(t *testing.T) {
	limiter := New(10)
	// Should not panic on malformed addresses
	result := limiter.Allow("not-an-ip")
	if !result {
		t.Error("malformed addr should be allowed (treated as its own key)")
	}
}
