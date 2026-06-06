// internal/proxy/resize.go
// Terminal resize handling.
// Called from CLI client (Phase 8) when it detects SIGWINCH.
package proxy

import "golang.org/x/crypto/ssh"

// WindowSize represents a terminal dimension update from the client CLI.
type WindowSize struct {
	Width  int
	Height int
}

// ApplyWindowChange sends a PTY window resize to the backend SSH session.
// Called when the proxy receives a SIGWINCH message from the client connection.
func ApplyWindowChange(sshSess *ssh.Session, ws WindowSize) error {
	return sshSess.WindowChange(ws.Height, ws.Width)
}
