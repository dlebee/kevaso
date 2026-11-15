package ingress

import (
	"strings"
	"testing"

	"kevaso.com/core/sdk/kic"
)

// K-086, ingress items. An Ingress may not take the path ACME HTTP-01 challenges are answered on
// (it would answer, or block, every host's challenges); and a host and path is one claim whatever
// the case of the path (Caddy matches paths without case: two Ingresses with /Foo and /foo would
// both be in the state for one route).

func TestK086AnIngressCantTakeTheChallengePath(t *testing.T) {
	for _, p := range []string{"/.well-known/acme-challenge/", "/.well-known/acme-challenge/tok", "/.well-known/acme-challenge", "/.WELL-KNOWN/Acme-Challenge/x"} {
		bad := ing("shop", "web", []string{"shop.example.com"}, rule(p, "web"))
		good := ing("shop", "ok", []string{"ok.example.com"}, rule("/.well-known/other", "web"))
		d := Desire(inputs(bad, good))
		if d.Refused["shop/web"] == "" {
			t.Errorf("%s accepted", p)
		}
		for _, r := range d.State.Routes {
			if r.Ingress == "shop/web" {
				t.Errorf("%s routed: %+v", p, r)
			}
		}
		if d.Refused["shop/ok"] != "" {
			t.Errorf("/.well-known/other refused: %s", d.Refused["shop/ok"])
		}
		if err := kic.CheckState(kic.State{Routes: []kic.Route{{Ingress: "x/y", Host: "a.example.com", Path: p, Backend: kic.Backend{Address: "10.0.0.1", Port: 80}}}}); err == nil {
			t.Errorf("CheckState took %s", p)
		}
	}
}

func TestK086APathClaimIgnoresCase(t *testing.T) {
	first := ing("a", "first", []string{"shop.example.com"}, rule("/Foo", "web"))
	second := ing("b", "second", []string{"shop.example.com"}, rule("/foo", "web"))
	first.Namespace, second.Namespace = "shop", "shop"
	d := Desire(inputs(second, first))
	n := 0
	for _, r := range d.State.Routes {
		if strings.EqualFold(r.Path, "/foo") {
			n++
			if r.Ingress != "shop/first" {
				t.Errorf("the route went to %s, the first by name is shop/first", r.Ingress)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d routes for one host and path (case aside): %+v", n, d.State.Routes)
	}
}
