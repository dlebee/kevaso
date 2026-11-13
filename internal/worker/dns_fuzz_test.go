package worker

import (
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"kevaso.com/core/internal/names"
)

// recorder is a dns.ResponseWriter that keeps what was written.
type recorder struct {
	remote net.Addr
	msgs   []*dns.Msg
}

func (r *recorder) LocalAddr() net.Addr         { return &net.UDPAddr{IP: net.IPv4(10, 64, 0, 1), Port: 53} }
func (r *recorder) RemoteAddr() net.Addr        { return r.remote }
func (r *recorder) WriteMsg(m *dns.Msg) error   { r.msgs = append(r.msgs, m); return nil }
func (r *recorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *recorder) Close() error                { return nil }
func (r *recorder) TsigStatus() error           { return nil }
func (r *recorder) TsigTimersOnly(bool)         {}
func (r *recorder) Hijack()                     {}

// FuzzDNSQuery: any packet anyone can send to a host's DNS listeners. Whatever it is, the server
// answers it exactly once, with its ID; only a silo's queries are ever forwarded; an address that
// isn't a silo's gets REFUSED on the silos' listener; and every address answered is in the view,
// for the name asked.
//
//	go test ./internal/worker -run '^$' -fuzz FuzzDNSQuery -fuzztime 60s
func FuzzDNSQuery(f *testing.F) {
	for _, n := range []string{"api.payments.kevaso.", "api.", "hv1.external.kevaso.", "ubuntu.com.", "API.Payments.Mesh.Kevaso.", "kevaso.", "."} {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeANY, dns.TypeTXT} {
			m := new(dns.Msg)
			m.SetQuestion(n, qt)
			b, _ := m.Pack()
			f.Add(b, uint8(0))
		}
	}
	two := new(dns.Msg)
	two.Question = []dns.Question{{Name: "a.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, {Name: "b.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	b, _ := two.Pack()
	f.Add(b, uint8(1))
	f.Add([]byte{}, uint8(2))

	// A fake upstream that counts what's forwarded to it.
	var forwarded atomic.Int64
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		f.Skip("no loopback UDP:", err)
	}
	upSrv := &dns.Server{PacketConn: up, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		forwarded.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = upSrv.ActivateAndServe() }()
	f.Cleanup(func() { _ = upSrv.Shutdown() })

	v := viewForDNS()
	known := map[string]bool{}
	for _, s := range v.Silos {
		known[s.Status.SiloIP] = true
	}
	for _, h := range v.Hosts {
		known[h.Spec.ExternalIP], known[h.Spec.InternalIP] = true, true
	}
	askers := []names.Asker{names.FromSilo, names.FromHost, names.FromNetwork, names.FromOutside}

	f.Fuzz(func(t *testing.T, data []byte, who uint8) {
		req := new(dns.Msg)
		if err := req.Unpack(data); err != nil {
			return // the server library drops what doesn't parse
		}
		from := askers[int(who)%len(askers)]
		silo := who&4 == 0 // the silos' listener: asked by a silo, or by an address that isn't one
		d := &DNS{From: from, View: func() names.View { return v }, Upstream: []string{up.LocalAddr().String()},
			SiloNamespace: func(netip.Addr) (string, bool) { return "payments", silo }}
		before := forwarded.Load()
		w := &recorder{remote: &net.UDPAddr{IP: net.IPv4(10, 64, 3, 9), Port: 5353}}
		d.ServeDNS(w, req)
		if len(w.msgs) != 1 {
			t.Fatalf("%d replies", len(w.msgs))
		}
		resp := w.msgs[0]
		if resp.Id != req.Id {
			t.Fatalf("reply ID %d to query %d", resp.Id, req.Id)
		}
		if fwd := forwarded.Load() - before; fwd > 0 && (from != names.FromSilo || !silo) {
			t.Fatalf("%s's query %v forwarded upstream: an open resolver", from, req.Question)
		}
		if from == names.FromSilo && !silo && (resp.Rcode != dns.RcodeRefused && resp.Rcode != dns.RcodeFormatError || len(resp.Answer) > 0) {
			t.Fatalf("an address that isn't a silo's got %v", resp)
		}
		if forwarded.Load() != before {
			return // the upstream's answer, passed on as is
		}
		for _, rr := range resp.Answer {
			a, ok := rr.(*dns.A)
			if !ok {
				t.Fatalf("answer %v", rr)
			}
			if !known[a.A.String()] {
				t.Fatalf("%s is nobody's address", a.A)
			}
			if len(req.Question) != 1 || !strings.EqualFold(a.Hdr.Name, req.Question[0].Name) {
				t.Fatalf("answer for %q to a question about %v", a.Hdr.Name, req.Question)
			}
		}
	})
}
