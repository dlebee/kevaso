package worker

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/names"
)

func viewForDNS() names.View {
	api := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "payments"}}
	api.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 8080}}
	api.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Port: "http", HostPort: []string{"external"}}}}
	api.Status.Host, api.Status.SiloIP = "hv1", "10.64.3.7"
	client := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "client", Namespace: "payments"}}
	client.Status.SiloIP = "127.0.0.1" // the test asks from loopback, as this silo
	hv1 := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "hv1"}, Spec: v1.HostSpec{ExternalIP: "198.51.100.10"}}
	return names.View{Silos: []*v1.Silo{api, client}, Hosts: []*v1.Host{hv1}}
}

// serve runs a DNS server for from on a free loopback port, with a fake upstream, and returns ask.
func serve(t *testing.T, from names.Asker, silos bool) func(string) *dns.Msg {
	up, _ := net.ListenPacket("udp", "127.0.0.1:0")
	upSrv := &dns.Server{PacketConn: up, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(203, 0, 113, 9)})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = upSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = upSrv.Shutdown() })
	l, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := l.LocalAddr().String()
	_ = l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	v := viewForDNS()
	d := &DNS{Listen: addr, From: from, View: func() names.View { return v }, Upstream: []string{up.LocalAddr().String()}}
	if silos {
		d.SiloNamespace = SiloNamespaces(v.Silos)
	} else {
		d.SiloNamespace = func(netip.Addr) (string, bool) { return "", false }
	}
	go d.Run(ctx)
	return func(name string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
		for i := 0; i < 50; i++ {
			if r, _, err := (&dns.Client{Timeout: time.Second}).Exchange(m, addr); err == nil {
				return r
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("no answer for %s", name)
		return nil
	}
}

func a(r *dns.Msg) string {
	if len(r.Answer) != 1 {
		return ""
	}
	return r.Answer[0].(*dns.A).A.String()
}

func TestDNSServerForSilos(t *testing.T) {
	ask := serve(t, names.FromSilo, true)
	if r := ask("api.payments.kevaso"); a(r) != "10.64.3.7" || !r.Authoritative {
		t.Fatalf("plain name: %v", r)
	}
	if r := ask("api"); a(r) != "10.64.3.7" {
		t.Fatalf("short name: %v", r)
	}
	if r := ask("ghost.payments.kevaso"); r.Rcode != dns.RcodeNameError {
		t.Fatalf("unknown: %v", r)
	}
	if r := ask("hv1.external.kevaso"); r.Rcode != dns.RcodeRefused {
		t.Fatalf("a host's name from a silo: %v", r)
	}
	if r := ask("ubuntu.com"); a(r) != "203.0.113.9" {
		t.Fatalf("forwarded: %v", r)
	}
	// An asker that isn't a silo gets nothing on the silos' listener.
	if r := serve(t, names.FromSilo, false)("api.payments.kevaso"); r.Rcode != dns.RcodeRefused {
		t.Fatalf("not a silo: %v", r)
	}
}

func TestDNSServerForOutside(t *testing.T) {
	ask := serve(t, names.FromOutside, false)
	if r := ask("api.payments.kevaso"); a(r) != "198.51.100.10" {
		t.Fatalf("plain name from outside: %v", r)
	}
	if r := ask("api.payments.mesh.kevaso"); r.Rcode != dns.RcodeRefused {
		t.Fatalf("mesh from outside: %v", r)
	}
	if r := ask("ubuntu.com"); r.Rcode != dns.RcodeRefused || len(r.Answer) != 0 {
		t.Fatalf("an open resolver: %v", r)
	}
}

// Where a host listens: silos and the mesh always; internal and external only when asked.
func TestDNSListeners(t *testing.T) {
	h := &v1.Host{Spec: v1.HostSpec{InternalIP: "10.0.0.5", ExternalIP: "51.38.10.20"}}
	h.Status.Network.MeshIP = "10.63.0.2"
	got := DNSListeners(h)
	if len(got) != 2 || got["10.64.0.1:53"] != names.FromSilo || got["10.63.0.2:53"] != names.FromHost {
		t.Fatalf("default: %v", got)
	}
	h.Spec.Network.DNS = []string{"internal", "external"}
	got = DNSListeners(h)
	if len(got) != 4 || got["10.0.0.5:53"] != names.FromNetwork || got["51.38.10.20:53"] != names.FromOutside {
		t.Fatalf("turned on: %v", got)
	}
	h.Spec.ExternalIP = ""
	if got = DNSListeners(h); len(got) != 3 {
		t.Fatalf("external asked, none: %v", got)
	}
}
