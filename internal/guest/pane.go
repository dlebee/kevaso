package guest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

// paneCommand reports a pane (design §10.1). Nothing comes back but "ok": panes are one way.
//
//	pane report NAME [--state S] [--progress P] [--title T] [--message M] [--field LABEL=VALUE]… [--ttl D]
//	pane html NAME --bundle FILE [--data JSON | --data -] [--ttl D]
func paneCommand(ctx context.Context, dial Dialer, args []string, stdin io.Reader, stdout io.Writer) error {
	usage := errors.New("usage: kvo-guest pane report NAME [--state S] [--progress P] [--title T] [--message M] [--field L=V]… [--ttl D] | pane html NAME --bundle FILE [--data JSON|-] [--ttl D]")
	if len(args) < 2 || (args[0] != "report" && args[0] != "html") {
		return usage
	}
	r := v1.PaneReport{Pane: args[1], Kind: v1.PaneStatus}
	if args[0] == "html" {
		r.Kind = v1.PaneHTML
	}
	var bundle string
	rest := args[2:]
	for len(rest) > 0 {
		if len(rest) < 2 {
			return fmt.Errorf("%s needs a value", rest[0])
		}
		flag, val := rest[0], rest[1]
		rest = rest[2:]
		switch {
		case flag == "--state" && r.Kind == v1.PaneStatus:
			r.State = val
		case flag == "--progress" && r.Kind == v1.PaneStatus:
			p, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return fmt.Errorf("--progress %q: %v", val, err)
			}
			r.Progress = &p
		case flag == "--title":
			r.Title = val
		case flag == "--message" && r.Kind == v1.PaneStatus:
			r.Message = val
		case flag == "--field" && r.Kind == v1.PaneStatus:
			l, v, ok := strings.Cut(val, "=")
			if !ok {
				return fmt.Errorf("--field %q: want LABEL=VALUE", val)
			}
			r.Fields = append(r.Fields, v1.PaneField{Label: l, Value: v})
		case flag == "--ttl":
			r.TTL = val
		case flag == "--bundle" && r.Kind == v1.PaneHTML:
			bundle = val
		case flag == "--data" && r.Kind == v1.PaneHTML:
			data := []byte(val)
			if val == "-" {
				b, err := io.ReadAll(io.LimitReader(stdin, 256<<10))
				if err != nil {
					return err
				}
				data = b
			}
			if !json.Valid(data) {
				return errors.New("--data must be JSON")
			}
			r.Data = json.RawMessage(data)
		default:
			return fmt.Errorf("unknown flag %s for pane %s", flag, args[0])
		}
	}
	if r.Kind == v1.PaneHTML {
		if bundle == "" {
			return errors.New("pane html needs --bundle FILE (the pane's HTML, or an archive the client unpacks)")
		}
		b, err := os.ReadFile(bundle)
		if err != nil {
			return err
		}
		resp, err := Call(ctx, dial, client.BrokerRequest{Op: client.OpPaneBundle, Payload: b})
		if err != nil {
			return err
		}
		r.Bundle = resp.Digest
	}
	if _, err := Call(ctx, dial, client.BrokerRequest{Op: client.OpPane, Pane: &r}); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, "ok")
	return err
}
