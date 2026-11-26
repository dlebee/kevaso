package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// gate wraps the API: the first list of each kind in hold waits until release is closed, and
// every write to an IP is reported on ipWrites (method, path, and the holders it writes).
type gate struct {
	next     http.Handler
	hold     map[string]bool // collection path suffixes, e.g. "/silos"
	release  chan struct{}
	ipWrites chan string
}

func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if r.Method == http.MethodGet && r.URL.Query().Get("watch") == "" {
		for suffix := range g.hold {
			if strings.HasSuffix(p, suffix) {
				select {
				case <-g.release:
				case <-r.Context().Done():
					return
				}
			}
		}
	}
	if r.Method == http.MethodGet || !strings.Contains(p, "/ips/") {
		g.next.ServeHTTP(w, r)
		return
	}
	what := r.Method + " " + p
	if r.Body != nil {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		var x v1.IP
		if json.Unmarshal(body, &x) == nil {
			what += fmt.Sprintf(" (held by %v)", x.Status.Holder)
		}
	}
	g.next.ServeHTTP(w, r) // reported once it is done, so a read after the report sees it
	select {
	case g.ipWrites <- what:
	default:
	}
}

// K-027: when the controllers start (a restart, or this node becoming leader), no controller may
// act before every cache it reads has its first list. Here the IP cache loads while the Silo and
// Service lists are held back: an IP controller that ran now would see no claimant for an IP a
// live silo holds, unbind it and delete it. Nothing may write to the IP until those lists are
// in, and once they are, the IP must still be bound to its silo.
func TestK027ControllersWaitForEveryCacheBeforeActing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	g := &gate{next: srv, hold: map[string]bool{}, release: make(chan struct{}), ipWrites: make(chan string, 64)}
	ts := httptest.NewServer(g)
	defer ts.Close()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}); err != nil {
		t.Fatal(err)
	}
	silo := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "d"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", VM: &v1.VMSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 2, Memory: "4Gi"},
			Ports:    []v1.SiloPort{{Name: "http", Port: 80}},
			Services: []v1.SiloService{{Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "web-ip"}, Ports: []v1.ServicePort{{Port: "http"}}}}}}
	if err := c.Create(ctx, silo); err != nil {
		t.Fatal(err)
	}
	ipName := "web-ip"
	if err := c.Create(ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: ipName, Namespace: "d"}, Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "a1"}}); err != nil {
		t.Fatal(err)
	}
	cfg := Config{ClusterName: "test", HostName: "cp-1", Clock: clock.Real{}}
	logs := make(chan string, 256)
	cfg.Log = func(f string, a ...any) {
		select {
		case logs <- f:
		default:
		}
	}

	// First run: the controllers bind the IP to the silo naming it.
	ctx1, stop1 := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); runControllers(ctx1, c, cfg, certDeps{}) }()
	var ip v1.IP
	for {
		var l v1.IP
		err := c.Get(ctx, "IP", "d", ipName, &l)
		if err == nil && l.Status.Holder != nil && l.Status.Holder.Holder == "silo/web" {
			ip = l
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the IP was never bound: %v %+v", err, l.Status)
		case <-time.After(10 * time.Millisecond):
		}
	}
	stop1()
	wg.Wait()
	// Give the next run something to write once it looks: its Bound condition, taken away here.
	ip.Status.Conditions = nil
	if err := c.UpdateStatus(ctx, &ip); err != nil {
		t.Fatal(err)
	}
	for len(g.ipWrites) > 0 {
		<-g.ipWrites
	}

	// Second run, as after a restart or a leader change: Silo and Service lists held back.
	g.hold["/silos"], g.hold["/services"] = true, true
	ctx2, stop2 := context.WithCancel(ctx)
	defer func() { stop2(); wg.Wait() }()
	wg.Add(1)
	go func() { defer wg.Done(); runControllers(ctx2, c, cfg, certDeps{}) }()
	waiting := false
	for !waiting {
		select {
		case w := <-g.ipWrites:
			t.Fatalf("%s while the Silo and Service caches were still empty", w)
		case l := <-logs:
			waiting = strings.HasPrefix(l, "controllers wait for")
		case <-ctx.Done():
			t.Fatal("the controllers neither acted nor said they wait for their caches")
		}
	}
	close(g.release)
	// Once the lists are in, the IP controller looks at the IP (its Bound condition says who holds
	// it): it must still be the same IP, bound to the silo.
	for {
		var now v1.IP
		if err := c.Get(ctx, "IP", "d", ip.Name, &now); err != nil {
			t.Fatalf("the IP is gone: %v", err)
		}
		if now.UID != ip.UID || now.DeletionTimestamp != nil || now.Status.Holder == nil {
			t.Fatalf("the IP was unbound or deleted: uid %s→%s, deleting %v, held by %v", ip.UID, now.UID, now.DeletionTimestamp != nil, now.Status.Holder)
		}
		if meta.FindCondition(now.Status.Conditions, "Bound") != nil {
			break // the controller looked, and it is still bound
		}
		select {
		case <-g.ipWrites:
		case <-ctx.Done():
		}
	}
}
