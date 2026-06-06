// internal/cli/app.go
package cli

import (
	"fmt"
	"os"
	"syscall"

	"github.com/urfave/cli/v2"
	"github.com/nagdevnihal/zttp/internal/cli/connect"
)

// NewApp returns the initialized urfave/cli application.
func NewApp(defaultProxyAddr string) *cli.App {
	return &cli.App{
		Name:  "zttp",
		Usage: "Zero-Trust Terminal Proxy Client",
		Flags: []cli.Flag{},
		Commands: []*cli.Command{
			connect.Command(defaultProxyAddr),
		},
		Action: func(c *cli.Context) error {
			if c.NArg() == 0 {
				fmt.Println("=== ZTTP Interactive Shell ===")
				
				// Default to standard local proxy addr if not specified in env
				proxyAddr := os.Getenv("ZTTP_PROXY_ADDR")
				if proxyAddr == "" {
					proxyAddr = defaultProxyAddr
				}
				
				for {
					fmt.Println("=== ZTTP Interactive Shell ===")
					// Automatically route to the gateway menu
					err := connect.RunConnect(c.Context, proxyAddr, "zttp-gateway", "")
					if err != nil {
						fmt.Printf("Connection closed: %v\n", err)
					}
					fmt.Println() // Add a newline before looping back
					
					// Restart the process entirely to avoid leaking os.Stdin readers
					syscall.Exec(os.Args[0], os.Args, os.Environ())
				}
				return nil
			}
			return cli.ShowAppHelp(c)
		},
	}
}
