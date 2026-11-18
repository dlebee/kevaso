package kvoadm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/restore"
)

// printRestoreAccount tells the operator what the restored history is still waiting on.
func printRestoreAccount(ctx context.Context, c *client.Client, out io.Writer) error {
	var g v1.RestoreGate
	if err := c.Get(ctx, "RestoreGate", "", v1.RestoreGateName, &g); err != nil {
		return err
	}
	hosts, err := accountHosts(ctx, c)
	if err != nil {
		return err
	}
	silos, err := accountSilos(ctx, c)
	if err != nil {
		return err
	}
	var unsettled, frozen []string
	for _, s := range silos {
		if !restore.BlocksPlacement(s, &g) {
			continue
		}
		if s.Status.Restore != nil && s.Status.Restore.Phase == v1.RestoreFrozen {
			frozen = append(frozen, fmt.Sprintf("%s/%s (copies on %s)", s.Namespace, s.Name, strings.Join(s.Status.Restore.Holders, ", ")))
			continue
		}
		unsettled = append(unsettled, s.Namespace+"/"+s.Name)
	}
	sort.Strings(unsettled)
	sort.Strings(frozen)
	_, _ = fmt.Fprintf(out, "restore: history %s\nhosts that have not reported: %s\nunsettled silos: %s\nfrozen silos: %s\n",
		g.Spec.History, orNone(restore.Unreported(&g, hosts)), orNone(unsettled), orNone(frozen))
	return nil
}

func orNone(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

func accountHosts(ctx context.Context, c *client.Client) ([]*v1.Host, error) {
	l, err := c.List(ctx, "Host", "")
	if err != nil {
		return nil, err
	}
	var out []*v1.Host
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, obj.(*v1.Host))
	}
	return out, nil
}

func accountSilos(ctx context.Context, c *client.Client) ([]*v1.Silo, error) {
	l, err := c.List(ctx, "Silo", "")
	if err != nil {
		return nil, err
	}
	var out []*v1.Silo
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, obj.(*v1.Silo))
	}
	return out, nil
}

// hostConfirmOff records that a host the restored history is waiting on is off or wiped.
// The host need not be a Host object: the operator's list of hosts added since the backup
// has names the store does not.
func hostConfirmOff(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	if len(args) < 1 {
		return errors.New("host confirm-off NAME [--yes|--confirm-off] [--context NAME]")
	}
	name, kctx, yes := args[0], "", false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--yes", "--confirm-off":
			yes = true
		case "--context":
			if i+1 >= len(args) {
				return errors.New("--context needs a value")
			}
			i++
			kctx = args[i]
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
	}
	c, _, err := adminClient(kctx)
	if err != nil {
		return err
	}
	var g v1.RestoreGate
	if err := c.Get(ctx, "RestoreGate", "", v1.RestoreGateName, &g); err != nil {
		return fmt.Errorf("no restored history is open: %w", err)
	}
	if restore.ConfirmedOff(&g, name) {
		_, _ = fmt.Fprintf(out, "host %s is already confirmed off\n", name)
		return nil
	}
	if !yes {
		_, _ = fmt.Fprintf(out, "Is %s off or wiped? [y/N]\n", name)
		if stdin == nil {
			return fmt.Errorf("host %s was not confirmed off (pass --confirm-off, or answer yes)", name)
		}
		line, err := readLine(bufio.NewReader(stdin))
		if err != nil && line == "" {
			return fmt.Errorf("host %s was not confirmed off", name)
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
		default:
			return fmt.Errorf("host %s was not confirmed off", name)
		}
	}
	g.Spec.ConfirmedOff = append(g.Spec.ConfirmedOff, name)
	if err := c.Update(ctx, &g); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "host %s confirmed off\n", name)
	return nil
}
