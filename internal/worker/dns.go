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
	"kevaso.com/core/internal/names"
)

// DNS answers Kevaso's names (design §7.0, internal/names) on one address, for one kind of
// asker: the silos' gateway (silos: their services by plain or short name; everything else is
// forwarded to the host's resolvers), the host's mesh IP (hosts: everything), and, only where the
// operator turns them on (Host spec.network.dns), its internal IP (machines on its network) and
// external IP (anyone). Only silos get names forwarded: a Kevaso host is never an open resolver.
type DNS struct {
	Listen string      // e.g. 10.64.3.1:53
	From   names.Asker // who asks on Listen
	View   func() names.View
	// SiloNamespace is the namespace of the silo with this silo IP (ok false: none): a silo's
	// short names are in its namespace, and an address that isn't a silo's gets no answer.
	SiloNamespace func(netip.Addr) (string, bool)
	Upstream      []string             // default: the host's resolvers
	Log           func(string, ...any) //

	once sync.Once
}

// SiloNamespaces maps silo IPs to their namespaces, for DNS.SiloNamespace.
func SiloNamespaces(silos []*v1.Silo) func(netip.Addr) (string, bool) {
	return func(a netip.Addr) (string, bool) {
		for _, s := range silos {
			if s.Status.SiloIP == a.String() && s.DeletionTimestamp == nil {
				return s.Namespace, true
			}
		}
		return "", false
	}
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
	question := names.Question{Name: q.Name, From: d.From}
	if d.From == names.FromSilo {
		ns, ok := "", false
		if src := addrOf(w.RemoteAddr()); src.IsValid() && d.SiloNamespace != nil {
			ns, ok = d.SiloNamespace(src)
		}
		if !ok { // not a silo: nothing for it here
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		question.Namespace = ns
	}
	a := names.Resolve(question, d.View())
	if a.InZone || d.From != names.FromSilo {
		m := new(dns.Msg)
		m.SetReply(req)
		switch {
		case !a.InZone || a.Refused:
			m.Rcode = dns.RcodeRefused
		case !a.Found:
			m.Authoritative, m.Rcode = true, dns.RcodeNameError
		default: // no address (held, or nothing on that network): NODATA, short-lived
			m.Authoritative = true
			if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
				for _, ip := range a.IPs {
					m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: ip.AsSlice()})
				}
			}
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

func addrOf(a net.Addr) netip.Addr {
	switch x := a.(type) {
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(x.IP)
		return ip.Unmap()
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(x.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}
