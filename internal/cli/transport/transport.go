// internal/cli/transport/transport.go
package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// ConnectRequest is sent from CLI to proxy after TLS handshake.
type ConnectRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Target     string `json:"target"`
	TermWidth  int    `json:"term_width"`
	TermHeight int    `json:"term_height"`
}

// ConnectTLS establishes a TLS 1.3 connection to the ZTTP proxy.
// Downgrade to TLS 1.2 is actively rejected.
func ConnectTLS(proxyAddr string) (net.Conn, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		// In production: ServerName and RootCAs populated from compiled-in CA cert.
		// For development, we skip verify since it's a self-signed dev cert.
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		proxyAddr,
		cfg,
	)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", proxyAddr, err)
	}
	return conn, nil
}

// SendConnectRequest encodes and sends the auth + target request.
// Protocol: 4-byte length prefix + JSON payload.
func SendConnectRequest(conn net.Conn, req *ConnectRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}

// WaitReady blocks until the proxy sends a READY signal or an error.
// Protocol: 1-byte status (0x00 = ready, 0x01 = error) + optional error string.
func WaitReady(conn net.Conn) error {
	statusByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, statusByte); err != nil {
		return fmt.Errorf("read proxy response: %w", err)
	}
	if statusByte[0] == 0x00 {
		return nil // READY
	}
	// Read error message (4-byte len prefix + string)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return fmt.Errorf("proxy denied connection")
	}
	msgLen := binary.BigEndian.Uint32(lenBuf)
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return fmt.Errorf("read proxy error message: %w", err)
	}
	return fmt.Errorf("%s", string(msg))
}

// SendWindowChange sends a terminal resize event to the proxy.
// Protocol: 1-byte type (0x02 = resize) + 2-byte width + 2-byte height.
func SendWindowChange(conn net.Conn, width, height int) error {
	buf := []byte{
		0x02,
		byte(width >> 8), byte(width),
		byte(height >> 8), byte(height),
	}
	_, err := conn.Write(buf)
	return err
}

// RunPipe runs bidirectional copy between stdin/stdout and the proxy connection.
// This function blocks until the session ends.
func RunPipe(ctx context.Context, conn net.Conn) error {
	done := make(chan struct{}, 2)
	// stdin → proxy
	go func() {
		io.Copy(conn, os.Stdin)
		done <- struct{}{}
	}()
	// proxy → stdout
	go func() {
		io.Copy(os.Stdout, conn)
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
		conn.Close()
	}
	return nil
}
