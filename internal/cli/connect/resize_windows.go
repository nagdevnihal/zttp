//go:build windows
// +build windows

package connect

import (
	"net"
)

// watchTerminalResize is a no-op on Windows since it does not support SIGWINCH natively.
func watchTerminalResize(conn net.Conn) func() {
	return func() {}
}
