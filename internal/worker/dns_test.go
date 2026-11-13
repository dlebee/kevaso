package worker

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func silosForDNS() []*v1.Silo {
	api := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "payments"}}
	api.Status.SiloIP = "10.64.3.7"
	pending := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "new", Namespace: "payments"}}
	return []*v1.Silo{api, pending}
}

func TestLookup(t *testing.T) {
	s := silosForDNS()
	for name, want := range map[string]struct {
		ip         string
		inZone, ok bool
	}{
		"api.payments.kevaso.": {"10.64.3.7", true, true},
		"API.Payments.kevaso":  {"10.64.3.7", true, true},
		"new.payments.kevaso.": {"", true, false}, // no address yet
		"nope.payments.kevaso": {"", true, false},
		"api.kevaso.":          {"", true, false}, // the search list makes api.payments.kevaso first
		"ubuntu.com.":          {"", false, false},
	} {
		ip, inZone, found := Lookup(name, s)
		if inZone != want.inZone || found != want.ok || (found && ip.String() != want.ip) {
			t.Errorf("%s: %v %v %v", name, ip, inZone, found)
		}
	}
}

func TestDNSServer(t *testing.T) {
	// A fake upstream for names outside the zone.
	up, _ := net.ListenPacket("udp", "127.0.0.1:0")
	upSrv := &dns.Server{PacketConn: up, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(203, 0, 113, 9)})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = upSrv.ActivateAndServe() }()
	defer func() { _ = upSrv.Shutdown() }()

	l, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := l.LocalAddr().String()
	_ = l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (&DNS{Listen: addr, Silos: silosForDNS, Upstream: []string{up.LocalAddr().String()}}).Run(ctx)

	ask := func(name string) *dns.Msg {
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
	if r := ask("api.payments.kevaso"); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "10.64.3.7" || !r.Authoritative {
		t.Fatalf("private name: %v", r)
	}
	if r := ask("ghost.payments.kevaso"); r.Rcode != dns.RcodeNameError {
		t.Fatalf("unknown silo: %v", r)
	}
	if r := ask("ubuntu.com"); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "203.0.113.9" {
		t.Fatalf("forwarded: %v", r)
	}
}
