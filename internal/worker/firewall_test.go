package worker

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

func TestFirewallKeepsTheLastGoodAndRetries(t *testing.T) {
	var calls []string
	fail := false
	f := &firewall{apply: func(_ context.Context, s string) error {
		calls = append(calls, s)
		if fail {
			return errors.New("nft: syntax error")
		}
		return nil
	}}
	ctx := context.Background()
	if ok, err := f.load(ctx, "A"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := f.load(ctx, "A"); ok {
		t.Fatal("the loaded table was loaded again")
	}
	fail = true
	if _, err := f.load(ctx, "B"); err == nil || f.last != "A" {
		t.Fatalf("refused: err %v, last %q (want A kept)", err, f.last)
	}
	first := f.retryAfter()
	if _, err := f.load(ctx, "B"); err == nil || f.retryAfter() <= first {
		t.Fatalf("the same refused table wasn't tried again, or the pause didn't grow (%s, %s)", first, f.retryAfter())
	}
	fail = false
	if ok, err := f.load(ctx, "B"); !ok || err != nil || f.last != "B" || f.err != nil {
		t.Fatalf("after the fix: %v %v last %q", ok, err, f.last)
	}
	if len(calls) != 4 {
		t.Fatalf("loads %v", calls)
	}
	for f.fails = 1; f.fails < 20; f.fails++ {
		if d := f.retryAfter(); d > time.Minute || d < 2*time.Second {
			t.Fatalf("pause %s after %d refusals", d, f.fails)
		}
	}
}

// One silo with entries nft can't take (here a plugin's answer in status: IPv6 ranges and rule
// text) never stops the firewall for the others: the first table already has every good port, a
// change to another silo is loaded at once, the bad entries are reported on their silo, and a
// table nft refuses is retried with nothing changed, the refusal shown on the Host meanwhile.
func TestOneBadSiloCannotStopTheFirewall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	api := httptest.NewServer(srv)
	defer api.Close()
	admin := client.New(api.URL)
	mk := func(o meta.Object) {
		t.Helper()
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	mk(&v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	mk(&v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}})
	silo := func(name string, port int, sources []string, lb bool) *v1.Silo {
		sp := v1.ServicePort{Port: "web", HostPort: []string{v1.NetworkInternal}, Sources: sources}
		svc := &v1.SiloService{Ports: []v1.ServicePort{sp}}
		if lb {
			svc.Ports[0] = v1.ServicePort{Port: "web", LoadBalancer: true}
			svc.LoadBalancer = &v1.LoadBalancerSpec{Class: v1.LBIPPool}
		}
		return &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "nginx"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
				Ports: []v1.SiloPort{{Name: "web", Port: port}}, Service: svc}}
	}
	good, bad := silo("good", 8080, []string{"192.0.2.0/24"}, false), silo("bad", 9090, nil, true)
	mk(good)
	mk(bad)
	place := func(s *v1.Silo, ip string, f func(*v1.SiloStatus)) {
		t.Helper()
		if err := admin.Get(ctx, "Silo", "dev", s.Name, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host, s.Status.Phase, s.Status.SiloIP = "hv1", "Running", ip
		if f != nil {
			f(&s.Status)
		}
		if err := admin.UpdateStatus(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	place(good, "10.64.0.2", nil)
	place(bad, "10.64.0.3", func(st *v1.SiloStatus) {
		st.Service.NodePorts = []v1.NodePort{{Name: "web", Port: 9090, NodePort: 30001}}
		st.Service.SourceRanges = []string{"2001:db8::/32", "192.0.2.9\n    flush ruleset"}
	})

	var mu sync.Mutex
	refuse := 0
	applied := make(chan string, 64)
	old := applyRules
	applyRules = func(_ context.Context, rules string) error {
		mu.Lock()
		defer mu.Unlock()
		if strings.Contains(rules, "2001:db8") || strings.Contains(rules, "flush ruleset") {
			return errors.New("nft would refuse this") // what K-009/K-036 did to the whole table
		}
		if refuse > 0 {
			refuse--
			return errors.New("nft: Error: syntax error (injected)")
		}
		applied <- rules
		return nil
	}
	defer func() { applyRules = old }()
	done := make(chan struct{})
	go func() { RunNetwork(ctx, client.New(api.URL), "hv1", nil, nil, func(string, ...any) {}); close(done) }()
	defer func() { cancel(); <-done; api.CloseClientConnections() }()

	wait := func(what string, ok func(string) bool) {
		t.Helper()
		for {
			select {
			case r := <-applied:
				if ok(r) {
					return
				}
			case <-ctx.Done():
				t.Fatalf("never loaded: %s", what)
			}
		}
	}
	wait("good's port", func(r string) bool { return strings.Contains(r, "dnat ip to 10.64.0.2:8080") })
	eventually(t, ctx, "bad's PortRules condition", func() bool {
		var s v1.Silo
		_ = admin.Get(ctx, "Silo", "dev", "bad", &s)
		c := meta.FindCondition(s.Status.Conditions, CondPortRules)
		return c != nil && c.Status == meta.ConditionFalse && strings.Contains(c.Message, "2001:db8::/32") && !strings.Contains(c.Message, "\n")
	})

	// Another silo changes while bad is still there: it gets through.
	if err := admin.Get(ctx, "Silo", "dev", "good", good); err != nil {
		t.Fatal(err)
	}
	good.Spec.Service.Ports[0].Sources = []string{"203.0.113.0/24"}
	if err := admin.Update(ctx, good); err != nil {
		t.Fatal(err)
	}
	wait("good's new sources", func(r string) bool { return strings.Contains(r, "ip saddr 203.0.113.0/24") })

	// nft refuses the next table (twice): the Host says so, and it's retried with nothing changed.
	mu.Lock()
	refuse = 2
	mu.Unlock()
	if err := admin.Get(ctx, "Silo", "dev", "good", good); err != nil {
		t.Fatal(err)
	}
	good.Spec.Service.Ports[0].Sources = []string{"198.51.100.0/24"}
	if err := admin.Update(ctx, good); err != nil {
		t.Fatal(err)
	}
	eventually(t, ctx, "the Host's SiloFirewall Rejected", func() bool {
		var h v1.Host
		_ = admin.Get(ctx, "Host", "", "hv1", &h)
		c := meta.FindCondition(h.Status.Conditions, CondSiloFirewall)
		return c != nil && c.Status == meta.ConditionFalse && c.Reason == "Rejected"
	})
	wait("the retried table", func(r string) bool { return strings.Contains(r, "ip saddr 198.51.100.0/24") })
	eventually(t, ctx, "the Host's SiloFirewall back to Loaded", func() bool {
		var h v1.Host
		_ = admin.Get(ctx, "Host", "", "hv1", &h)
		c := meta.FindCondition(h.Status.Conditions, CondSiloFirewall)
		return c != nil && c.Status == meta.ConditionTrue
	})

	// The bad entries go: so does the condition.
	place(bad, "10.64.0.3", func(st *v1.SiloStatus) { st.Service.SourceRanges = []string{"192.0.2.9"} })
	eventually(t, ctx, "bad's PortRules condition removed", func() bool {
		var s v1.Silo
		_ = admin.Get(ctx, "Silo", "dev", "bad", &s)
		return meta.FindCondition(s.Status.Conditions, CondPortRules) == nil
	})
}

func eventually(t *testing.T, ctx context.Context, what string, ok func() bool) {
	t.Helper()
	for !ok() {
		select {
		case <-ctx.Done():
			t.Fatalf("never: %s", what)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestSiloProblemsAreOneLineEach(t *testing.T) {
	m := siloProblems([]kni.Problem{{Kind: "Silo", Owner: "dev/a", Port: "web", Entry: `"x\ny"`, Reason: "r"}, {Kind: "Service", Owner: "dev/s", Reason: "r"}})
	if len(m) != 1 || strings.ContainsAny(m["dev/a"], "\n\r") || !strings.Contains(m["dev/a"], "port web") {
		t.Fatalf("%q", m)
	}
}
