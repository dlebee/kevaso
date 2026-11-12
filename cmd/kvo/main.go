// Command kvo is the Kevaso user CLI (see internal/cli/kvo).
package main

import (
	"context"
	"os"
	"os/signal"

	"kevaso.com/core/internal/cli/kvo"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := kvo.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
