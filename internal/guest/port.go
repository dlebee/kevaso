package guest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"kevaso.com/core/api/client"
)

// portCommand is kvo-guest port open NAME [--for D] [--wait D] | port close NAME (design §7.2d):
// the silo asks to open one of its leased ports to the outside for a while, waiting for a person's
// yes when its lease needs one, or closes it early.
func portCommand(ctx context.Context, dial Dialer, args []string, stdout, stderr io.Writer) error {
	usage := errors.New("usage: kvo-guest port open NAME [--for D] [--wait D] | port close NAME")
	if len(args) < 2 {
		return usage
	}
	switch args[0] {
	case "open":
		req := client.BrokerRequest{Op: client.OpPortOpen, Name: args[1]}
		if err := approvalFlags(&req, args[2:]); err != nil {
			return err
		}
		resp, err := Ask(ctx, dial, req, PollEvery, waiting(stderr))
		if err != nil {
			return err
		}
		if resp.Until == nil {
			return fmt.Errorf("port %s: no end time in the answer", args[1])
		}
		if resp.Clamped {
			_, _ = fmt.Fprintf(stderr, "kvo-guest: port %s: that's more than its lease's max: open for the max instead\n", args[1])
		}
		_, err = fmt.Fprintf(stdout, "port %s open until %s\n", args[1], resp.Until.Local().Format(time.RFC3339))
		return err
	case "close":
		if len(args) != 2 {
			return usage
		}
		if _, err := Call(ctx, dial, client.BrokerRequest{Op: client.OpPortClose, Name: args[1]}); err != nil {
			return err
		}
		_, err := fmt.Fprintf(stdout, "port %s closed\n", args[1])
		return err
	}
	return usage
}
