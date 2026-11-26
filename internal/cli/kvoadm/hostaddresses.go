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

// A host's named extra addresses (networking v2), each reserved by an IP of type Host by name:
//
//	kvoadm host addresses HOST add NAME ADDRESS --external|--internal
//	kvoadm host addresses HOST remove NAME     refused for an address an IP reserves
//	kvoadm host addresses HOST list            each address, and which IP reserves it

// EditAddresses is a host's extra addresses after adding or removing one. Pure; the server
// checks the rest (one IPv4 address each, names unique in the cluster).
func EditAddresses(cur []v1.HostAddress, op string, args []string) ([]v1.HostAddress, error) {
	out := slices.Clone(cur)
	switch op {
	case "add":
		kind := ""
		var rest []string
		for _, a := range args {
			switch a {
			case "--external":
				kind = v1.NetworkExternal
			case "--internal":
				kind = v1.NetworkInternal
			default:
				rest = append(rest, a)
			}
		}
		if len(rest) != 2 || kind == "" {
			return nil, errors.New("addresses add NAME ADDRESS --external|--internal")
		}
		if slices.ContainsFunc(out, func(a v1.HostAddress) bool { return a.Name == rest[0] }) {
			return nil, fmt.Errorf("the host has an address named %s already", rest[0])
		}
		if _, err := ips.ParseAddress(rest[1]); err != nil {
			return nil, err
		}
		return append(out, v1.HostAddress{Name: rest[0], Kind: kind, Address: rest[1]}), nil
	case "remove":
		if len(args) != 1 {
			return nil, errors.New("addresses remove NAME")
		}
		i := slices.IndexFunc(out, func(a v1.HostAddress) bool { return a.Name == args[0] })
		if i < 0 {
			return nil, fmt.Errorf("%s isn't one of the host's addresses", args[0])
		}
		return slices.Delete(out, i, i+1), nil
	}
	return nil, fmt.Errorf("unknown addresses command %q: add, remove or list", op)
}

// addressesUsage is the command's forms, and how an IP then reserves an address.
const addressesUsage = `host addresses HOST add NAME ADDRESS --external|--internal | remove NAME | list
an IP in a namespace then reserves one by name, and a silo uses that IP:
  kind: IP
  spec: { type: Host, hostAddress: NAME }      # or: kvo create ip IPNAME --type Host --host-address NAME
  services: [{ name: mail, type: HostPort, hostPort: { ip: IPNAME }, ports: [{ port: smtp }] }]`

func hostAddresses(ctx context.Context, args []string, out io.Writer) error {
	kctx := ""
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--cluster" && i+1 < len(args) {
			kctx = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	if len(rest) < 2 {
		return errors.New(addressesUsage)
	}
	c, _, err := adminClient(kctx)
	if err != nil {
		return err
	}
	return editHostAddresses(ctx, c, rest[0], rest[1], rest[2:], out)
}

// editHostAddresses is kvoadm host addresses HOST OP ARGS… on the cluster c.
func editHostAddresses(ctx context.Context, c *client.Client, name, op string, more []string, out io.Writer) error {
	if op == "list" {
		if len(more) > 0 {
			return errors.New("addresses list takes no arguments: " + addressesUsage)
		}
		return listHostAddresses(ctx, c, name, out)
	}
	if op != "add" && op != "remove" {
		return fmt.Errorf("unknown addresses command %q\n%s", op, addressesUsage)
	}
	if op == "remove" && len(more) == 1 {
		ips, err := hostIPs(ctx, c)
		if err != nil {
			return err
		}
		if x := reserving(ips, more[0]); x != nil {
			who := "no silo uses it now"
			if x.Status.Holder != nil {
				who = "used by " + x.Status.Holders()
			}
			return fmt.Errorf("address %s is reserved by IP %s/%s (%s): it stays until that IP is deleted (kvo delete ip %s -n %s, once nothing uses it)",
				more[0], x.Namespace, x.Name, who, x.Name, x.Namespace)
		}
	}
	for attempt := 0; ; attempt++ {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", name, &h); err != nil {
			return err
		}
		next, err := EditAddresses(h.Spec.Addresses, op, more)
		if err != nil {
			return err
		}
		h.Spec.Addresses = next
		err = c.Update(ctx, &h)
		if err == nil {
			var names []string
			for _, a := range next {
				names = append(names, a.Name+" "+a.Address)
			}
			_, _ = fmt.Fprintf(out, "→ %s's extra addresses: %s\n", name, dashOr(strings.Join(names, ", ")))
			return nil
		}
		var e *client.Error
		if client.IsConflict(err) && errors.As(err, &e) && (strings.Contains(e.Message, "reserved") || strings.Contains(e.Message, "already") || strings.Contains(e.Message, "both")) {
			return errors.New(e.Message) // a reserved or duplicate address: the server says which
		}
		if !client.IsConflict(err) || attempt > 5 {
			return err
		}
	}
}

// hostIPs are the cluster's IPs of type Host.
func hostIPs(ctx context.Context, c *client.Client) ([]*v1.IP, error) {
	l, err := c.List(ctx, "IP", "")
	if err != nil {
		return nil, err
	}
	var out []*v1.IP
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			return nil, err
		}
		if x := obj.(*v1.IP); x.Spec.Type == v1.IPTypeHost {
			out = append(out, x)
		}
	}
	return out, nil
}

// reserving is the IP reserving the host address named name (nil: it's free).
func reserving(ips []*v1.IP, name string) *v1.IP {
	for _, x := range ips {
		if x.Spec.HostAddress == name {
			return x
		}
	}
	return nil
}

func listHostAddresses(ctx context.Context, c *client.Client, name string, out io.Writer) error {
	var h v1.Host
	if err := c.Get(ctx, "Host", "", name, &h); err != nil {
		return err
	}
	ips, err := hostIPs(ctx, c)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tKIND\tADDRESS\tRESERVED BY")
	_, _ = fmt.Fprintf(tw, "(main)\t%s\t%s\t%s\n", v1.NetworkExternal, dashOr(h.External()), "the worker's (hostPort: { worker: external })")
	_, _ = fmt.Fprintf(tw, "(main)\t%s\t%s\t%s\n", v1.NetworkInternal, dashOr(h.Internal()), "the worker's (hostPort: { worker: internal })")
	for _, a := range h.Spec.Addresses {
		who := "-"
		if x := reserving(ips, a.Name); x != nil {
			who = "ip " + x.Namespace + "/" + x.Name
			if x.Status.Holder != nil {
				who += ", used by " + x.Status.Holders()
			}
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.Name, a.Kind, a.Address, who)
	}
	if len(h.Spec.Addresses) == 0 {
		_, _ = fmt.Fprintf(tw, "(no extra addresses: kvoadm host addresses %s add NAME ADDRESS --external)\n", name)
	}
	return tw.Flush()
}
