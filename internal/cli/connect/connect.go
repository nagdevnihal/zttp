// internal/cli/connect/connect.go
package connect

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/nagdevnihal/zttp/internal/cli/terminal"
	"github.com/nagdevnihal/zttp/internal/cli/transport"
)

func Command(defaultProxyAddr string) *cli.Command {
	return &cli.Command{
		Name:      "connect",
		Usage:     "Connect to a target server: zttp connect <hostname>",
		ArgsUsage: "<hostname>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "proxy",
				Aliases: []string{"p"},
				EnvVars: []string{"ZTTP_PROXY_ADDR"},
				Value:   defaultProxyAddr, // points to our local proxy's TLS listener
				Usage:   "Address of the ZTTP proxy node",
			},
			&cli.StringFlag{
				Name:    "user",
				Aliases: []string{"u"},
				EnvVars: []string{"ZTTP_USER"},
				Usage:   "Username (will prompt for password)",
			},
		},
		Action: func(c *cli.Context) error {
			if c.NArg() < 1 {
				return fmt.Errorf("hostname required — usage: zttp connect <hostname>")
			}
			hostname := c.Args().First()
			proxyAddr := c.String("proxy")
			username := c.String("user")

			return RunConnect(c.Context, proxyAddr, hostname, username)
		},
	}
}

func RunConnect(ctx context.Context, proxyAddr, hostname, username string) error {
	var password string
	// Step 1: Collect credentials securely
	if username == "" {
		var err error
		username, password, err = drawLoginTUI()
		if err != nil {
			return fmt.Errorf("login failed: %w", err)
		}
		if username == "exit" || username == "quit" {
			os.Exit(0)
		}
	} else {
		var err error
		password, err = terminal.Prompt("Password: ", true) // hidden input
		if err != nil {
			return fmt.Errorf("password prompt: %w", err)
		}
	}

	// Step 2: Get current terminal dimensions
	width, height, err := terminal.GetSize()
	if err != nil {
		width, height = 80, 24 // sane fallback
	}

	isInternalTUI := (hostname == "zttp-gateway" || hostname == "zttp-admin")
	if !isInternalTUI {
		fmt.Printf("\033[32mConnecting to %s via ZTTP...\033[0m\n", hostname)
	}
	start := time.Now()

	// Step 3: Establish TLS 1.3 connection to proxy
	conn, err := transport.ConnectTLS(proxyAddr)
	if err != nil {
		return fmt.Errorf("proxy connection failed: %w", err)
	}
	defer conn.Close()

	// Step 4: Send authentication + target in a single framed request
	req := &transport.ConnectRequest{
		Username:   username,
		Password:   password,
		Target:     hostname,
		TermWidth:  width,
		TermHeight: height,
	}
	if err := transport.SendConnectRequest(conn, req); err != nil {
		return fmt.Errorf("send connect request: %w", err)
	}

	// Step 5: Wait for proxy's READY signal
	if err := transport.WaitReady(conn); err != nil {
		return err // contains human-readable denial reason
	}

	if !isInternalTUI {
		elapsed := time.Since(start)
		fmt.Printf("\033[32mConnected\033[0m (%dms)\n", elapsed.Milliseconds())
		fmt.Println("─────────────────────────────────────────")
		fmt.Println("Audit logging active")
		fmt.Println("─────────────────────────────────────────")
	}

	// Step 6: Switch terminal to raw mode for PTY passthrough
	oldState, err := terminal.MakeRaw()
	if err != nil {
		return fmt.Errorf("raw terminal: %w", err)
	}
	defer terminal.Restore(oldState)

	// Step 7: Start terminal resize propagation listener (platform-specific)
	stopWatching := watchTerminalResize(conn)
	defer stopWatching()

	// Step 8: Bidirectional copy — stdin to proxy, proxy to stdout
	return transport.RunPipe(ctx, conn)
}
