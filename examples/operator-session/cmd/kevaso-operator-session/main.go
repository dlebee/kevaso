// Command kevaso-operator-session is the example plugin operator's controller program, as
// kvoadm plugin install runs it on a control-plane host (a systemd unit, as the plugin's own
// service account; its credentials come through systemd, see sdk/operator).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"kevaso.com/core/examples/operator-session/session"
	"kevaso.com/core/sdk/operator"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kevaso-operator-session:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	creds, err := operator.FromEnv()
	if err != nil {
		return err
	}
	return session.Main(ctx, creds)
}
