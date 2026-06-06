// cmd/zttp/main.go
package main

import (
	"fmt"
	"os"

	"github.com/nagdevnihal/zttp/internal/cli"
)

var DefaultProxyAddr = "127.0.0.1:2224"

func main() {
	app := cli.NewApp(DefaultProxyAddr)
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "\033[31mError: %v\033[0m\n", err)
		os.Exit(1)
	}
}
