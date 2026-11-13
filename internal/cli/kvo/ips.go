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

// IP objects (design §7.2c-1): addresses you keep.
//
//	kvo create ip NAME --class CLASS [--host HOST | --region REGION] [--address A] [--reclaim Delete]
//	kvo get ips
//	kvo ip keep NAME       its address stays when its holder goes (reclaim Retain; no longer owned)
//	kvo ip release NAME    it goes with its holder (reclaim Delete), or now if nothing holds it
//	kvo describe ip NAME

type ipOpts struct{ class, host, region, address, reclaim string }

var ipHead = []string{"ADDRESS", "CLASS", "HELD-BY", "KEPT"}

func ipRow(x *v1.IP) []string {
	kept := "yes"
	if !x.Kept() {
		kept = "no, goes with " + dash(ownerOf(x))
	}
	return []string{dash(x.Status.Address), x.Spec.Class, dash(x.Status.BoundTo), kept}
}

func ownerOf(x *v1.IP) string {
	for _, r := range x.OwnerReferences {
		return strings.ToLower(r.Kind) + "/" + r.Name
	}
	if x.Status.BoundTo != "" {
		return x.Status.BoundTo
	}
	return ""
}

func createIP(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 2 || o.ip.class == "" {
		return errors.New("create ip needs a NAME and a class: kvo create ip NAME --class ip-pool|CLASS [--host HOST | --region REGION]")
	}
	x := &v1.IP{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IP"},
		ObjectMeta: meta.ObjectMeta{Name: o.args[1], Namespace: defaultNS(o)},
		Spec:       v1.IPSpec{Class: o.ip.class, Host: o.ip.host, Region: o.ip.region, Address: o.ip.address, Reclaim: o.ip.reclaim}}
	if x.Spec.Reclaim == "" {
		x.Spec.Reclaim = v1.ReclaimRetain
	}
	if err := c.Create(ctx, x); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "ip/%s created: its address shows in kvo get ips once reserved\n", x.Name)
	return nil
}

func ipCommand(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 2 || (o.args[0] != "keep" && o.args[0] != "release") {
		return errors.New("usage: kvo ip keep|release NAME")
	}
	ns, name := defaultNS(o), o.args[1]
	for attempt := 0; attempt < 5; attempt++ {
		var x v1.IP
		if err := c.Get(ctx, "IP", ns, name, &x); err != nil {
			return err
		}
		msg := ""
		if o.args[0] == "keep" {
			if x.Kept() && len(x.OwnerReferences) == 0 {
				_, _ = fmt.Fprintf(stdout, "ip/%s is kept already\n", name)
				return nil
			}
			x.Spec.Reclaim, x.OwnerReferences = v1.ReclaimRetain, nil
			msg = fmt.Sprintf("ip/%s kept: %s stays until you delete the IP", name, dash(x.Status.Address))
		} else {
			if x.Status.BoundTo == "" {
				if err := c.Delete(ctx, "IP", ns, name); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(stdout, "ip/%s released: nothing held it, so it's deleted and %s goes back\n", name, dash(x.Status.Address))
				return nil
			}
			x.Spec.Reclaim = v1.ReclaimDelete
			msg = fmt.Sprintf("ip/%s released: it goes when %s lets go of it", name, x.Status.BoundTo)
		}
		err := c.Update(ctx, &x)
		if client.IsConflict(err) {
			continue
		}
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stdout, msg)
		return nil
	}
	return errors.New("the IP kept changing; try again")
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
	from := x.Spec.Class
	switch {
	case x.Spec.Class == v1.LBIPPool && x.Status.Host != "":
		from += " (one of " + x.Status.Host + "'s extra addresses)"
	case x.Status.Region != "":
		from += " (in " + x.Status.Region + ")"
	}
	kv("Class", from)
	if x.Status.Follows != "" {
		kv("Follows its holder", x.Status.Follows)
	}
	kept := "yes: reclaim Retain, it stays until the IP is deleted"
	if !x.Kept() {
		kept = "no: reclaim Delete, it goes when " + dash(ownerOf(x)) + " lets go of it (kvo ip keep " + x.Name + " keeps it)"
	}
	kv("Kept", kept)
	kv("Held by", dash(x.Status.BoundTo))
	if strings.HasPrefix(x.Status.BoundTo, v1.HolderSiloPrefix) {
		var s v1.Silo
		if err := c.Get(ctx, "Silo", x.Namespace, strings.TrimPrefix(x.Status.BoundTo, v1.HolderSiloPrefix), &s); err == nil {
			kv("In and out", s.Status.Service.AddressesLine())
		}
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
