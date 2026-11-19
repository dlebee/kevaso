package integration

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	kicdrivers "kevaso.com/core/builtin/kic"
	"kevaso.com/core/builtin/kic/nginx"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/internal/ingress/ingresstest"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// Design §0.8 (2026-11-14): a held ingress class holds back only the broken Ingress. With one
// Ingress the proxy refuses (its config test fails on it) and another the driver refuses (an
// annotation), a new Ingress in the same class still goes out at once, the broken ones keep their
// last good version, and each says why on its own: the class's controller entry names them, and
// each one's own reason (ingress.Refused, what the control plane puts on it) is its own, not the
// other's.
func TestIngressClassHoldsBackOnlyTheBrokenIngress(t *testing.T) {
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
	proxy.Check = func(cfg []byte, _ map[string][]byte) string { // nginx -t refuses one host it can't resolve
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
	var logMu sync.Mutex
	var logs bytes.Buffer
	// start runs an agent on hv1; the function it returns stops it and waits until it has.
	start := func() (stop func()) {
		a := &agent.Agent{Client: c.host(t, "hv1"), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{},
			IngressEvery: 50 * time.Millisecond, Log: func(f string, args ...any) {
				logMu.Lock()
				defer logMu.Unlock()
				fmt.Fprintf(&logs, f+"\n", args...)
			}}
		ctx, cancel := context.WithCancel(c.ctx)
		done := make(chan struct{})
		go func() { defer close(done); a.Run(ctx) }()
		return func() { cancel(); <-done }
	}
	stop := start()
	defer func() { stop() }()
	place := func(name, ns string, ports []v1.SiloPort, svc *v1.SiloService) {
		t.Helper()
		s := containerSilo(name, ns, "docker")
		s.Spec.Ports, s.Spec.Service = ports, svc
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host = "hv1"
		if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	place("ingress-web", "kevaso-system", []v1.SiloPort{{Name: "http", Port: 80}}, &v1.SiloService{Ports: []v1.ServicePort{{Port: "http"}}})
	place("app", "shop", []v1.SiloPort{{Name: "http", Port: 8080}}, &v1.SiloService{Ports: []v1.ServicePort{{Port: "http"}}})
	for _, i := range []*v1.Ingress{ing("a", "a.example.com"), ing("b", "b.example.com")} {
		if err := c.admin.Create(c.ctx, i); err != nil {
			t.Fatal(err)
		}
	}
	served := func(what string, ok func(cfg string) bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			files, _, _ := proxy.Snapshot()
			if ok(string(files[nginx.ConfigPath])) {
				return
			}
			if time.Now().After(deadline) {
				logMu.Lock()
				t.Fatalf("%s:\n%s\nagent:\n%s", what, files[nginx.ConfigPath], logs.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	has := func(cfg string, hosts ...string) bool {
		for _, h := range hosts {
			if !strings.Contains(cfg, "server_name "+h+";") {
				return false
			}
		}
		return true
	}
	served("a and b", func(cfg string) bool { return has(cfg, "a.example.com", "b.example.com") })

	// a: an edit the proxy refuses; b: an annotation the driver refuses. Then a new Ingress.
	update := func(name string, f func(*v1.Ingress)) {
		t.Helper()
		var cur v1.Ingress
		if err := c.admin.Get(c.ctx, "Ingress", "shop", name, &cur); err != nil {
			t.Fatal(err)
		}
		f(&cur)
		if err := c.admin.Update(c.ctx, &cur); err != nil {
			t.Fatal(err)
		}
	}
	update("a", func(i *v1.Ingress) { i.Spec.Hosts = []string{"broken.example.com"} })
	update("b", func(i *v1.Ingress) { i.Annotations = map[string]string{"nginx/proxy-body-size": "a lot"} })
	if err := c.admin.Create(c.ctx, ing("new", "new.example.com")); err != nil {
		t.Fatal(err)
	}
	served("the new Ingress, with a and b at their last good versions", func(cfg string) bool {
		return has(cfg, "new.example.com", "a.example.com", "b.example.com") && !strings.Contains(cfg, "broken.example.com")
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		var cl v1.IngressClass
		_ = c.admin.Get(c.ctx, "IngressClass", "", "web", &cl)
		// What the control plane writes on each Ingress (the certificate controller's Refused).
		var aw, bw, nw string
		for _, name := range []string{"a", "b", "new"} {
			var i v1.Ingress
			_ = c.admin.Get(c.ctx, "Ingress", "shop", name, &i)
			_, msg := ingress.Refused(kicdrivers.Builtin(), &cl, &i)
			switch name {
			case "a":
				aw = msg
			case "b":
				bw = msg
			case "new":
				nw = msg
			}
		}
		ok := len(cl.Status.Controllers) == 1 && strings.Contains(strings.Join(cl.Status.Controllers[0].Blamed, ","), "shop/a") &&
			strings.Contains(aw, "server_names_hash") && !strings.Contains(aw, "proxy-body-size") &&
			strings.Contains(bw, "proxy-body-size") && !strings.Contains(bw, "server_names_hash") && nw == ""
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("statuses: class %+v\na: %q\nb: %q\nnew: %q", cl.Status, aw, bw, nw)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// K-063: kevasod restarts, nothing changes. The new agent has no memory; what the proxy serves
	// is read back from the record in the silo. Not a route changes: a stays at its last good
	// version, new stays served, and the statuses stay as they were.
	files, _, reloads := proxy.Snapshot()
	cfg := string(files[nginx.ConfigPath])
	ran := len(proxy.Commands())
	stop()
	var web v1.Silo
	if err := c.admin.Get(c.ctx, "Silo", "kevaso-system", "ingress-web", &web); err != nil {
		t.Fatal(err)
	}
	ingress.ForgetMemory(web.UID)
	stop = start()
	deadline = time.Now().Add(10 * time.Second)
	for { // until the new agent has read the record and settled (the reload of what's there)
		_, _, r := proxy.Snapshot()
		if r > reloads {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the restarted agent never got to the proxy: %v", proxy.Commands()[ran:])
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // a few more passes
	files, _, after := proxy.Snapshot()
	if got := string(files[nginx.ConfigPath]); got != cfg {
		t.Fatalf("a restart changed the proxy's configuration:\n%s\nwas:\n%s", got, cfg)
	}
	if after != reloads+1 {
		t.Errorf("%d reloads after the restart, want 1 (of what's there)", after-reloads)
	}
	var cl v1.IngressClass
	_ = c.admin.Get(c.ctx, "IngressClass", "", "web", &cl)
	if len(cl.Status.Controllers) != 1 || strings.Join(cl.Status.Controllers[0].Blamed, ",") != "shop/a,shop/b" || strings.HasPrefix(cl.Status.Controllers[0].Rejected, "held") {
		t.Errorf("after the restart, the class says %+v", cl.Status.Controllers)
	}

	// Fixed: a's new version goes out.
	update("a", func(i *v1.Ingress) { i.Spec.Hosts = []string{"a2.example.com"} })
	served("a's fixed version", func(cfg string) bool { return has(cfg, "a2.example.com", "new.example.com", "b.example.com") })
}
