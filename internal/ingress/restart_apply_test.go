package ingress_test

import (
	"context"
	"testing"

	"kevaso.com/core/builtin/kic/nginx"
	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/internal/ingress/ingresstest"
	"kevaso.com/core/sdk/kic/kictest"
)

// kevasod stopped (SIGTERM: its context cancelled) after the new config was moved over the old
// one and before the proxy reloaded: the file says the new plan, the proxy still runs the old one.
// The restarted agent must have the proxy load it; it saw the file match and did nothing, so new
// routes, renewed certificates and ACME answers were never served.
func TestARestartAfterTheMoveStillReloads(t *testing.T) {
	ctx := context.Background()
	px := ingresstest.New()
	p := render(t, kictest.Sample(nil))
	// What the stopped agent left: the files and the config in place, no reload.
	for _, f := range append(p.Files, p.Config) {
		if out, code := px.Handle(ingress.WriteCmd(f.Path, "0600"), f.Data); code != 0 {
			t.Fatal(out)
		}
	}
	if _, _, reloads := px.Snapshot(); reloads != 0 {
		t.Fatal("reloaded already")
	}
	if _, err := ingress.Apply(ctx, execOn(px), nil, nginx.Driver{}, p, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, reloads := px.Snapshot(); reloads != 1 {
		t.Fatalf("the restarted agent left the proxy on its old config: %d reloads; ran %v", reloads, px.Commands())
	}
}
