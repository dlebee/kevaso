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

// T-11: the pretend nginx of TestIngressClassHoldsBackOnlyTheBrokenIngress names the server_name
// line, which is outside every Ingress's marked section, so the driver's blame is never used
// there. Here the pretend nginx names what a real one does, the directive it can't take inside
// the Ingress's own part (the proxy_pass to a backend it can't resolve), so the agent finds the
// culprit by the driver's blame: the broken Ingress's reason is the blame's ("refused the
// configuration with it"), not bisecting's ("refused it") or the one-by-one step's.
func TestIngressBlameFindsTheBrokenIngress(t *testing.T) {
	c := newCluster(t)
	for _, n := range []string{"kevaso-system", "shop"} {
		_ = c.admin.Create(c.ctx, ns(n))
	}
	if err := c.admin.Create(c.ctx, &v1.IngressClass{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IngressClass"},
		ObjectMeta: meta.ObjectMeta{Name: "web"}, Spec: v1.IngressClassSpec{
			Controller: v1.IngressController{Driver: "nginx", Silo: "ingress-web", Namespace: "kevaso-system"},
			Hosts:      []v1.HostAssignment{{Host: "*.example.com", Namespaces: []string{"shop"}}}}}); err != nil {
		t.Fatal(err)
	}
	ing := func(name, host string) *v1.Ingress {
		return &v1.Ingress{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Ingress"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "shop"},
			Spec: v1.IngressSpec{IngressClass: "web", Hosts: []string{host}, TLS: v1.IngressTLS{None: true},
				Rules: []v1.IngressRule{{Path: "/", Service: v1.IngressTarget{Name: "app", Port: "http"}}}}}
	}
	proxy := ingresstest.New()
	blamed := 0
	proxy.Check = func(cfg []byte, _ map[string][]byte) string {
		lines := strings.Split(string(cfg), "\n")
		for i, l := range lines {
			if !strings.Contains(l, "server_name broken.example.com;") {
				continue
			}
			for n := i + 1; n < len(lines); n++ { // its proxy_pass, inside the Ingress's marked section
				if strings.Contains(lines[n], "proxy_pass") {
					if got := kic.MarkedBlame(cfg, n+1); len(got) != 1 || got[0] != "shop/broken" {
						t.Errorf("line %d is in %v's section, not shop/broken's", n+1, got)
					}
					blamed++
					return fmt.Sprintf("nginx: [emerg] host not found in upstream \"x\" in %s:%d", nginx.ConfigPath, n+1)
				}
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
	a := &agent.Agent{Client: c.host(t, "hv1"), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{},
		IngressEvery: 50 * time.Millisecond, Log: func(string, ...any) {}}
	ctx, cancel := context.WithCancel(c.ctx)
	done := make(chan struct{})
	go func() { defer close(done); a.Run(ctx) }()
	defer func() { cancel(); <-done }()
	place := func(name, ns string) {
		t.Helper()
		s := containerSilo(name, ns, "docker")
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
	for _, i := range []*v1.Ingress{ing("a", "a.example.com"), ing("broken", "broken.example.com"), ing("c", "c.example.com"), ing("d", "d.example.com")} {
		if err := c.admin.Create(c.ctx, i); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		files, _, _ := proxy.Snapshot()
		cfg := string(files[nginx.ConfigPath])
		var cl v1.IngressClass
		_ = c.admin.Get(c.ctx, "IngressClass", "", "web", &cl)
		if len(cl.Status.Controllers) == 1 && strings.Join(cl.Status.Controllers[0].Blamed, ",") == "shop/broken" &&
			strings.Contains(cfg, "server_name d.example.com;") && strings.Contains(cfg, "server_name a.example.com;") {
			rej := cl.Status.Controllers[0].Rejected
			if !strings.Contains(rej, "ingress shop/broken: the proxy refused the configuration with it: nginx: [emerg] host not found in upstream") {
				t.Errorf("the culprit wasn't found by the driver's blame: %q", rej)
			}
			if strings.Contains(cfg, "broken.example.com") {
				t.Error("the broken Ingress is served")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("class %+v\n%s", cl.Status, cfg)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if blamed == 0 {
		t.Error("the pretend nginx never refused")
	}
}
