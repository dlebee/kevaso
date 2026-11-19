package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/restore"
)

// restoreCommand is kvo restore status, and kvo restore settle SILO --to HOST [-n NS].
// Settle is the same write as kvoadm restore settle: cluster-admin only, on a host that
// reported a copy. It waits until every other holder's report says that copy is stopped.
func restoreCommand(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) < 1 {
		return errors.New("restore status | restore settle SILO --to HOST [-n NS]")
	}
	switch o.args[0] {
	case "status":
		return printRestoreStatus(ctx, c, stdout)
	case "settle":
		if len(o.args) != 2 || o.moveTo == "" {
			return errors.New("restore settle SILO --to HOST [-n NS]")
		}
		ns := defaultNS(o)
		if err := restore.SettleCopy(ctx, c, ns, o.args[1], o.moveTo); err != nil {
			return err
		}
		_, err := fmt.Fprintf(stdout, "silo/%s settled on %s; the other copies stay stopped with their disks\n", o.args[1], o.moveTo)
		return err
	default:
		return fmt.Errorf("unknown restore command %q", o.args[0])
	}
}

func printRestoreStatus(ctx context.Context, c *client.Client, stdout io.Writer) error {
	var g v1.RestoreGate
	if err := c.Get(ctx, "RestoreGate", "", v1.RestoreGateName, &g); err != nil {
		return err
	}
	hosts, err := listKind[*v1.Host](ctx, c, "Host")
	if err != nil {
		return err
	}
	silos, err := listKind[*v1.Silo](ctx, c, "Silo")
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(stdout, restore.Account(&g, hosts, silos))
	return err
}

func listKind[T any](ctx context.Context, c *client.Client, kind string) ([]T, error) {
	l, err := c.List(ctx, kind, "")
	if err != nil {
		return nil, err
	}
	var out []T
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return nil, err
		}
		typed, ok := obj.(T)
		if !ok {
			return nil, fmt.Errorf("%s: unexpected object", kind)
		}
		out = append(out, typed)
	}
	return out, nil
}
