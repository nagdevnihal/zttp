//go:build !windows
// +build !windows

package connect

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/nagdevnihal/zttp/internal/cli/terminal"
	"github.com/nagdevnihal/zttp/internal/cli/transport"
)

// watchTerminalResize listens for SIGWINCH and forwards the new dimensions to the proxy.
func watchTerminalResize(conn net.Conn) func() {
	sigwinchCh := make(chan os.Signal, 1)
	signal.Notify(sigwinchCh, syscall.SIGWINCH)
	
	go func() {
		for range sigwinchCh {
			w, h, err := terminal.GetSize()
			if err == nil {
				_ = transport.SendWindowChange(conn, w, h)
			}
		}
	}()
	
	return func() {
		signal.Stop(sigwinchCh)
	}
}
