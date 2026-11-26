package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// IP objects (networking v2): addresses you keep, until you delete them.
//
//	kvo create ip NAME --type Host --host-address NAME
//	kvo create ip NAME --type Provider --provider PROVIDER --region REGION
//	kvo get ips
//	kvo describe ip NAME
//
// TODO(net-v2 wave 2): kvo get ips with TYPE, ADDRESS, WHERE, SET, USED BY, MOVES; IPSets.

type ipOpts struct{ typ, hostAddress, provider, region string }

var ipHead = []string{"TYPE", "ADDRESS", "WHERE", "HELD-BY"}

func ipRow(x *v1.IP) []string {
	return []string{x.Spec.Type, dash(x.Status.Address), dash(x.Status.Where), dash(x.Status.Holders())}
}

func createIP(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 2 || o.ip.typ == "" {
		return errors.New("create ip needs a NAME and a type: kvo create ip NAME --type Host --host-address NAME, or --type Provider --provider PROVIDER --region REGION")
	}
	x := &v1.IP{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IP"},
		ObjectMeta: meta.ObjectMeta{Name: o.args[1], Namespace: defaultNS(o)},
		Spec:       v1.IPSpec{Type: o.ip.typ, HostAddress: o.ip.hostAddress, Provider: o.ip.provider, Region: o.ip.region}}
	if err := c.Create(ctx, x); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "ip/%s created: its address shows in kvo get ips once reserved\n", x.Name)
	return nil
}

// ipCommand: kvo ip keep and release are gone; an IP is kept until it is deleted.
func ipCommand(context.Context, *client.Client, opts, io.Writer) error {
	return errors.New("an IP is kept until you delete it (kvo delete ip NAME): there is no keep or release")
}

// describeIP: the address, where it comes from, who holds it, whether it's kept, and whether its
// holder sends from it too.
func describeIP(ctx context.Context, c *client.Client, x *v1.IP, w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	kv := func(k, v string) { _, _ = fmt.Fprintf(tw, "%s:\t%s\n", k, v) }
	kv("Name", x.Name)
	kv("Namespace", x.Namespace)
	if x.CreationTimestamp != nil {
		kv("Created", fmt.Sprintf("%s (%s ago)", x.CreationTimestamp.Local().Format("2006-01-02 15:04:05"), since(*x.CreationTimestamp)))
	}
	if x.DeletionTimestamp != nil {
		kv("Deleting", "releasing its address, since "+since(*x.DeletionTimestamp)+" ago")
	}
	kv("Address", dash(x.Status.Address))
	from := x.Spec.Type
	switch x.Spec.Type {
	case v1.IPTypeHost:
		from += " (host address " + x.Spec.HostAddress + ")"
	case v1.IPTypeProvider:
		from += " (" + x.Spec.Provider + ", " + x.Spec.Region + ")"
	}
	kv("Type", from)
	kv("Where", dash(x.Status.Where))
	if set := x.Labels[v1.LabelIPSet]; set != "" {
		kv("Set", set+" #"+x.Labels[v1.LabelIPSetOrdinal])
	}
	kv("Held by", dash(x.Status.Holders()))
	if h := x.Status.Holder; h != nil {
		if strings.HasPrefix(h.Holder, v1.HolderSiloPrefix) {
			var s v1.Silo
			if err := c.Get(ctx, "Silo", x.Namespace, strings.TrimPrefix(h.Holder, v1.HolderSiloPrefix), &s); err == nil {
				kv("  "+h.Holder+" in and out", s.Status.Service.AddressesLine())
			}
		}
	}
	for _, w := range x.Status.Waiting {
		kv("Waiting", w.Holder+": "+w.Reason)
	}
	for _, cd := range x.Status.Conditions {
		line := string(cd.Status) + " " + cd.Reason
		if cd.Message != "" {
			line += ": " + cd.Message
		}
		kv(cd.Type, line)
	}
	return tw.Flush()
}
