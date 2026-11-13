package kvoadm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/ips"
)

// The extra addresses routed to a host (design §7.2c-1), which the built-in ip-pool class hands
// out as IP objects:
//
//	kvoadm host addresses HOST add CIDR…      e.g. 203.0.113.20/30 or 203.0.113.9
//	kvoadm host addresses HOST remove CIDR…   refused for an address an IP holds
//	kvoadm host addresses HOST list           each range, and which IP holds each address

// EditAddresses is a host's extra addresses after adding or removing some (each IPv4 CIDR or
// single address, masked; a single address as itself). Pure.
func EditAddresses(cur []string, op string, args []string) ([]string, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("addresses %s needs at least one CIDR or address", op)
	}
	out := slices.Clone(cur)
	for _, a := range args {
		p, err := ips.Parse(a)
		if err != nil {
			return nil, err
		}
		norm := p.String()
		if p.IsSingleIP() {
			norm = p.Addr().String()
		}
		has := func(x string) bool {
			q, err := ips.Parse(x)
			return err == nil && q == p
		}
		switch op {
		case "add":
			if !slices.ContainsFunc(out, has) {
				out = append(out, norm)
			}
		case "remove":
			if !slices.ContainsFunc(out, has) {
				return nil, fmt.Errorf("%s isn't one of the host's addresses", norm)
			}
			out = slices.DeleteFunc(out, has)
		default:
			return nil, fmt.Errorf("unknown addresses command %q: add, remove or list", op)
		}
	}
	return out, nil
}

func hostAddresses(ctx context.Context, args []string, out io.Writer) error {
	kctx := ""
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--context" && i+1 < len(args) {
			kctx = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	if len(rest) < 2 {
		return errors.New("host addresses HOST add|remove|list [CIDR…]")
	}
	name, op, cidrs := rest[0], rest[1], rest[2:]
	c, _, err := adminClient(kctx)
	if err != nil {
		return err
	}
	if op == "list" {
		return listHostAddresses(ctx, c, name, out)
	}
	for attempt := 0; ; attempt++ {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", name, &h); err != nil {
			return err
		}
		next, err := EditAddresses(h.Spec.Network.Addresses, op, cidrs)
		if err != nil {
			return err
		}
		h.Spec.Network.Addresses = next
		err = c.Update(ctx, &h)
		if err == nil {
			_, _ = fmt.Fprintf(out, "→ %s's extra addresses: %s\n", name, dashOr(strings.Join(next, ", ")))
			return nil
		}
		if !client.IsConflict(err) || attempt > 5 || strings.Contains(err.Error(), "in use") || strings.Contains(err.Error(), "overlaps") {
			return err // a held or overlapping address (Conflict, saying which) isn't worth retrying
		}
	}
}

func listHostAddresses(ctx context.Context, c *client.Client, name string, out io.Writer) error {
	var h v1.Host
	if err := c.Get(ctx, "Host", "", name, &h); err != nil {
		return err
	}
	l, err := c.List(ctx, "IP", "")
	if err != nil {
		return err
	}
	holder := map[string]string{}
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return err
		}
		if x := obj.(*v1.IP); x.Spec.Class == v1.LBIPPool && x.Status.Host == name && x.Status.Address != "" {
			who := "ip " + x.Namespace + "/" + x.Name
			if len(x.Status.BoundTo) > 0 {
				who += " (held by " + x.Status.Holders() + ")"
			}
			holder[x.Status.Address] = who
		}
	}
	addrs, err := ips.Expand(h.Spec.Network.Addresses)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ADDRESS\tIP")
	for _, a := range addrs {
		_, _ = fmt.Fprintf(tw, "%s\t%s\n", a, dashOr(holder[a.String()]))
	}
	if len(addrs) == 0 {
		_, _ = fmt.Fprintf(tw, "(none: kvoadm host addresses %s add CIDR)\n", name)
	}
	return tw.Flush()
}
