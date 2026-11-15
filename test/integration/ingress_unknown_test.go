package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kic/nginx"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/ingress/ingresstest"
	"kevaso.com/core/sdk/kic"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// K-120, the class status half (host lane: internal/agent/ingress.go, `report`). While the agent
// can't tell what the proxy serves, one refused Ingress, here another namespace's that was never
// served, holds the class with no automatic end (the owner's decision). ApplyEach now says so:
// EachResult.Unknown is set and Held names the Ingresses holding the class and says it "does not
// end by itself" (internal/ingress, each.go). The class's status must alert at once, apart from an
// ordinary refusal: today the agent writes the same Applied=False reason "Rejected" for a single
// Ingress left out (the class serving everything else, which ends when the Ingress is fixed) and
// for this hold (nothing new is served, ever, until a person acts).
//
// Fix: in `apply`, carry res.Unknown into ingressReport; in `report`, while any controller entry
// is held as unknown, set a condition Type "Held", Status True, Reason "UnknownServed", Message
// the entry's silo and res.Held, written on that first pass (removed, or Status False, once
// the class applies again); keep Applied as it is. Then remove the skip.
func TestK120AnUnknownHoldIsACondition(t *testing.T) {
	t.Skip("K-120, host lane: the class has no condition of its own for a hold that doesn't end by itself (internal/agent/ingress.go report)")
	c := newCluster(t)
	for _, n := range []string{"kevaso-system", "shop", "other"} {
		_ = c.admin.Create(c.ctx, ns(n))
	}
	if err := c.admin.Create(c.ctx, &v1.IngressClass{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IngressClass"},
		ObjectMeta: meta.ObjectMeta{Name: "web"}, Spec: v1.IngressClassSpec{
			Controller: v1.IngressController{Driver: "nginx", Silo: "ingress-web", Namespace: "kevaso-system"}}}); err != nil {
		t.Fatal(err)
	}
	ing := func(namespace, name, host string) *v1.Ingress {
		return &v1.Ingress{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Ingress"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace},
			Spec: v1.IngressSpec{IngressClass: "web", Hosts: []string{host}, TLS: v1.IngressTLS{None: true},
				Rules: []v1.IngressRule{{Path: "/", Service: v1.IngressTarget{Name: "app", Port: "http"}}}}}
	}
	// The proxy runs a configuration of Kevaso's that is no render of the current Ingresses and
	// has no record (a hand edit, an older copy of the silo): what it serves is unknown.
	plan, err := nginx.Driver{}.Render(kic.State{Class: "web", Routes: []kic.Route{{Ingress: "shop/gone", Host: "gone.example.com", Path: "/",
		Backend: kic.Backend{Address: "10.64.0.9", Port: 80}}}})
	if err != nil {
		t.Fatal(err)
	}
	proxy := ingresstest.New()
	proxy.Reset(map[string][]byte{nginx.ConfigPath: plan.Config.Data})
	proxy.Check = func(cfg []byte, _ map[string][]byte) string {
		for i, l := range strings.Split(string(cfg), "\n") {
			if strings.Contains(l, "server_name broken.example.com;") {
				return fmt.Sprintf("nginx: [emerg] could not build server_names_hash in %s:%d", nginx.ConfigPath, i+1)
			}
		}
		return ""
	}
	rt := fake.New()
	rt.Handler = func(id kri.ID, cmd []string, stdin []byte) (string, int) {
		if id.Name == "ingress-web" {
			return proxy.Handle(cmd, stdin)
		}
		return "", 0
	}
	place := func(name, namespace string) {
		t.Helper()
		s := containerSilo(name, namespace, "docker")
		s.Spec.Ports, s.Spec.Service = []v1.SiloPort{{Name: "http", Port: 80}}, &v1.SiloService{Ports: []v1.ServicePort{{Port: "http"}}}
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host = "hv1"
		if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	place("ingress-web", "kevaso-system")
	place("app", "shop")
	place("app", "other")
	for _, i := range []*v1.Ingress{ing("shop", "a", "a.example.com"), ing("other", "bad", "broken.example.com")} {
		if err := c.admin.Create(c.ctx, i); err != nil {
			t.Fatal(err)
		}
	}
	a := &agent.Agent{Client: c.host(t, "hv1"), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{},
		IngressEvery: 50 * time.Millisecond, Log: func(string, ...any) {}}
	ctx, cancel := context.WithCancel(c.ctx)
	done := make(chan struct{})
	go func() { defer close(done); a.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var cl v1.IngressClass
		_ = c.admin.Get(c.ctx, "IngressClass", "", "web", &cl)
		if cond := meta.FindCondition(cl.Status.Conditions, "Held"); cond != nil {
			if cond.Status != meta.ConditionTrue || cond.Reason != "UnknownServed" ||
				!strings.Contains(cond.Message, "other/bad") || !strings.Contains(cond.Message, "does not end by itself") {
				t.Fatalf("Held condition %+v", *cond)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no Held condition on the class: %+v", cl.Status)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if files, _, _ := proxy.Snapshot(); string(files[nginx.ConfigPath]) != string(plan.Config.Data) {
		t.Error("the proxy's configuration was changed while what it serves is unknown")
	}
}
