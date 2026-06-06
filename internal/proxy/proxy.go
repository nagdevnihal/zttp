// Package proxy implements the SSH proxy core — PTY bridge, io.CopyBuffer, goroutine pairs.
// Phase 5 implements: backend SSH dial, PTY alloc, dumb pipe, rate limiting, keepalive, SIGWINCH.
package proxy
