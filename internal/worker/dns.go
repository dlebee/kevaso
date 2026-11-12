package worker

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	v1 "kevaso.com/core/api/v1"
)

// Zone is the private names' domain (design §7.1): NAME.NAMESPACE.kevaso.
const Zone = "kevaso."

// Lookup answers a private name from the silos: NAME.NAMESPACE.kevaso → the silo's address. ok
// is false for names outside the zone (forward them); found is false for an unknown silo (NXDOMAIN).
// Resolving a name grants no connection: allowFrom does. Pure.
func Lookup(name string, silos []*v1.Silo) (ip netip.Addr, inZone, found bool) {
	name = strings.ToLower(dns.Fqdn(name))
	if name != Zone && !strings.HasSuffix(name, "."+Zone) {
		return netip.Addr{}, false, false
	}
	labels := dns.SplitDomainName(strings.TrimSuffix(name, Zone))
	if len(labels) != 2 {
		return netip.Addr{}, true, false
	}
	for _, s := range silos {
		if s.Name == labels[0] && s.Namespace == labels[1] && s.DeletionTimestamp == nil {
			if a, err := netip.ParseAddr(s.Status.Address); err == nil {
				return a, true, true
			}
		}
	}
	return netip.Addr{}, true, false
}

// DNS serves private names on the silos' gateway and forwards everything else to the host's
// resolvers.
type DNS struct {
	Listen   string               // e.g. 10.64.3.1:53
	Silos    func() []*v1.Silo    // the current silos
	Upstream []string             // default: the host's resolvers
	Log      func(string, ...any) //

	once sync.Once
}

func upstreams() []string {
	for _, f := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
		cfg, err := dns.ClientConfigFromFile(f)
		if err != nil {
			continue
		}
		var out []string
		for _, s := range cfg.Servers {
			if !strings.HasPrefix(s, "127.") { // a stub the silos' queries can't usefully reach through
				out = append(out, net.JoinHostPort(s, cfg.Port))
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{"1.1.1.1:53", "9.9.9.9:53"}
}

// ServeDNS implements dns.Handler.
func (d *DNS) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	d.once.Do(func() {
		if len(d.Upstream) == 0 {
			d.Upstream = upstreams()
		}
	})
	if len(req.Question) != 1 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	ip, inZone, found := Lookup(q.Name, d.Silos())
	if inZone {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		switch {
		case !found:
			m.Rcode = dns.RcodeNameError
		case q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY:
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: ip.AsSlice()})
		}
		_ = w.WriteMsg(m)
		return
	}
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	if _, tcp := w.RemoteAddr().(*net.TCPAddr); tcp {
		c.Net = "tcp"
	}
	for _, up := range d.Upstream {
		resp, _, err := c.Exchange(req, up)
		if err == nil {
			_ = w.WriteMsg(resp)
			return
		}
	}
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	_ = w.WriteMsg(m)
}

// Run serves until ctx ends (UDP and TCP).
func (d *DNS) Run(ctx context.Context) {
	servers := []*dns.Server{{Addr: d.Listen, Net: "udp", Handler: d}, {Addr: d.Listen, Net: "tcp", Handler: d}}
	for _, s := range servers {
		go func(s *dns.Server) {
			for ctx.Err() == nil {
				if err := s.ListenAndServe(); err != nil && ctx.Err() == nil && d.Log != nil {
					d.Log("dns %s/%s: %v (retrying)", s.Addr, s.Net, err)
				}
				select {
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
				}
			}
		}(s)
	}
	<-ctx.Done()
	for _, s := range servers {
		_ = s.Shutdown()
	}
}
