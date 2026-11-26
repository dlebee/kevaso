package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// IP objects (networking v2): addresses you keep, until you delete them.
//
//	kvo create ip NAME --type Host --host-address NAME
//	kvo create ip NAME --type Provider --provider PROVIDER --region REGION
//	kvo get ips | kvo describe ip NAME | kvo delete ip NAME
//	kvo get ipsets | kvo describe ipset NAME
//
// The layouts are in netview.go.

type ipOpts struct{ typ, hostAddress, provider, region string }

// ipForms is how an IP and its users are written, for errors that point at the fix.
const ipForms = `  kvo create ip NAME --type Host --host-address ADDRESS-NAME        (one of a host's extra addresses: pinned to that host)
  kvo create ip NAME --type Provider --provider PROVIDER --region R  (reserved from a provider: follows its silo within the region)
then a silo names it in a HostPort service:
  services:
    - name: api
      type: HostPort
      hostPort: { ip: NAME }               # or { worker: external }, { worker: internal }, { own: true } in a SiloSet
      ports: [{ port: https, as: 443 }]
  network:
    egress: { source: { ip: NAME } }       # optional: send out from the same address`

// ipSpecFromFlags is the IP kvo create ip makes, checked here so a wrong combination says the
// strict form at once (the server checks it again).
func ipSpecFromFlags(o ipOpts) (v1.IPSpec, error) {
	spec := v1.IPSpec{Type: o.typ, HostAddress: o.hostAddress, Provider: o.provider, Region: o.region}
	switch o.typ {
	case v1.IPTypeHost:
		switch {
		case o.hostAddress == "":
			return spec, errors.New("--type Host needs --host-address NAME: the name of one of a host's extra addresses (kvoadm host addresses HOST list)\n" + ipForms)
		case o.provider != "" || o.region != "":
			return spec, errors.New("--type Host takes --host-address only: --provider and --region are for --type Provider\n" + ipForms)
		}
	case v1.IPTypeProvider:
		switch {
		case o.provider == "" || o.region == "":
			return spec, errors.New("--type Provider needs --provider PROVIDER and --region REGION (e.g. --provider linode --region us-ord)\n" + ipForms)
		case o.hostAddress != "":
			return spec, errors.New("--type Provider takes --provider and --region only: --host-address is for --type Host\n" + ipForms)
		}
	case "":
		return spec, errors.New("create ip needs a NAME and a --type:\n" + ipForms)
	default:
		return spec, fmt.Errorf("--type %s: an IP's type is Host or Provider\n%s", o.typ, ipForms)
	}
	return spec, nil
}

func createIP(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 2 {
		return errors.New("create ip needs a NAME and a --type:\n" + ipForms)
	}
	spec, err := ipSpecFromFlags(o.ip)
	if err != nil {
		return err
	}
	x := &v1.IP{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IP"},
		ObjectMeta: meta.ObjectMeta{Name: o.args[1], Namespace: defaultNS(o)}, Spec: spec}
	if err := c.Create(ctx, x); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "ip/%s created: its address shows in kvo get ips once reserved; a silo uses it with hostPort: { ip: %s }\n", x.Name, x.Name)
	return nil
}

// ipCommand: kvo ip keep and release are gone; an IP is kept until it is deleted.
func ipCommand(context.Context, *client.Client, opts, io.Writer) error {
	return errors.New("an IP is kept until you delete it (kvo delete ip NAME): there is no keep or release")
}

// deleteRefusal is the server's reason when it refuses to delete an IP that is held (a 409):
// its own message, which says who holds it and what to do, without the status code.
func deleteRefusal(kind string, err error) error {
	var e *client.Error
	if kind == "IP" && errors.As(err, &e) && e.Reason == "Conflict" && e.Message != "" {
		return errors.New(e.Message)
	}
	return err
}

// servicesForm is how a silo's ways in are written (networking v2), for a manifest in an older
// shape.
const servicesForm = `a silo's ways in are a services: list, one way in each (strict fields, no strings):
  services:
    - name: web
      type: HostPort                       # no hostPort: = { worker: external }
      ports: [{ port: http, as: 80 }]
    - name: api
      type: HostPort
      hostPort: { ip: NAME }               # exactly one of { worker: external|internal }, { ip: NAME }, { own: true } (SiloSet)
      ports: [{ port: https, as: 443 }]
    - name: shop
      type: LoadBalancer
      loadBalancer: { provider: linode }
      ports: [{ port: https, as: 443 }]
    - name: metrics                        # type: Internal is the default
      ports: [{ port: metrics, allowFrom: [monitoring/prometheus] }]
  network:
    egress: { source: { ip: NAME } }       # or { own: true }`

// networkingHint adds the strict form to a decode error from a manifest in an older shape: a
// single service:, per-port hostPort or loadBalancer, a hostPort or loadBalancer as a string,
// load-balancer classes and dedicated IPs, ip-pool IPs.
func networkingHint(err error) error {
	msg := err.Error()
	for _, old := range []string{`unknown field "service"`, `unknown field "hostPort"`, `unknown field "class"`, `unknown field "dedicated"`,
		`unknown field "ip"`, `unknown field "sameAsService"`, `unknown field "pool"`, "hostPort of type", "loadBalancer of type", "source of type",
		`unknown field "reclaim"`, `unknown field "host"`, `unknown field "address"`} {
		if strings.Contains(msg, old) {
			switch {
			case strings.HasPrefix(msg, "decode IP:"):
				return fmt.Errorf("%w\nan IP is one address with an explicit type:\n  spec: { type: Host, hostAddress: NAME }\n  spec: { type: Provider, provider: linode, region: us-ord }", err)
			case strings.HasPrefix(msg, "decode Silo") || strings.HasPrefix(msg, "decode SiloSet"):
				return fmt.Errorf("%w\n%s", err, servicesForm)
			}
		}
	}
	return err
}
