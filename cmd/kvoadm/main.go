// Command kvoadm is the Kevaso operator CLI (see internal/cli/kvoadm).
package main

import (
	"context"
	"os"
	"os/signal"

	"kevaso.com/core/internal/cli/kvoadm"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := kvoadm.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
