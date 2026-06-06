// internal/proxy/listener.go
// TLS 1.3 Proxy Listener
//
// Accepts incoming TLS connections from the ZTTP CLI client.
// Enforces TLS 1.3 only — downgrade attacks to TLS 1.2 are rejected outright.
package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
)

// NewTLSListener creates a TCP listener that only accepts TLS 1.3 connections.
// Downgrade to TLS 1.2 is rejected — no fallback allowed (PRD §11.3).
func NewTLSListener(addr, certFile, keyFile string) (net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls cert: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // Hard floor — no TLS 1.2 fallback
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("tls listen on %s: %w", addr, err)
	}
	return ln, nil
}
