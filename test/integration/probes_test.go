package integration

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	servicecontroller "kevaso.com/core/internal/controllers/service"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/worker"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// probeRig is one host's agent on the fake runtime, with tcp probes dialled to a listener the
// test turns on and off, and the Service controller, against an in-process API server.
type probeRig struct {
	h      *harness
	c      *client.Client
	ctx    context.Context
	rt     *fake.Runtime
	target atomic.Value // where probes dial now: a live listener, or a closed port
	live   string
	closed string
}

func newProbeRig(t *testing.T, handler fake.Handler) *probeRig {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	r := &probeRig{h: h, c: client.New(h.server), ctx: ctx, rt: fake.New(), live: l.Addr().String(), closed: dead.Addr().String()}
	_ = dead.Close() // nothing listens there: connection refused
	r.target.Store(r.closed)
	r.rt.Handler = handler
	a := &agent.Agent{Client: r.c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": r.rt}, Clock: clock.Real{}, Log: t.Logf,
		// The host dials the silo's own address; here, wherever the test points it.
		ProbeDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !strings.HasPrefix(addr, "10.64.0.") {
				return nil, errors.New("probe dialled " + addr + ", not the silo's private address")
			}
			var d net.Dialer
			return d.DialContext(ctx, network, r.target.Load().(string))
		}}
	go a.Run(ctx)
	silos, services := informer.New(r.c, "Silo"), informer.New(r.c, "Service")
	e := engine.New(clock.Real{})
	e.Register(&servicecontroller.Controller{Client: r.c, Services: services, Silos: silos, Clock: clock.Real{}}, engine.Options{})
	silos.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Silo", Namespace: k.Namespace, Name: k.Name}) })
	services.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Service", Namespace: k.Namespace, Name: k.Name}) })
	go silos.Run(ctx)
	go services.Run(ctx)
	go e.Run(ctx)
	if err := r.c.Create(ctx, ns("web3")); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *probeRig) up(on bool) {
	if on {
		r.target.Store(r.live)
	} else {
		r.target.Store(r.closed)
	}
}

// place creates the silo and puts it on hv1 as the scheduler would (with its public address).
func (r *probeRig) place(t *testing.T, s *v1.Silo) {
	t.Helper()
	if err := r.c.Create(r.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if s.Spec.Service != nil {
		s.Status.Service = v1.SiloServiceStatus{Name: s.Name + ".web3.kevaso", PublicIP: "198.51.100.10"}
	}
	if err := r.c.UpdateStatus(r.ctx, s); err != nil {
		t.Fatal(err)
	}
}

func (r *probeRig) silo(name string) *v1.Silo {
	var s v1.Silo
	_ = r.c.Get(r.ctx, "Silo", "web3", name, &s)
	return &s
}

func (r *probeRig) service(name string) *v1.Service {
	var s v1.Service
	_ = r.c.Get(r.ctx, "Service", "web3", name, &s)
	return &s
}

func (r *probeRig) eventually(t *testing.T, what string, cond func() (bool, string)) {
	t.Helper()
	last := ""
	for r.ctx.Err() == nil {
		ok, s := cond()
		if ok {
			return
		}
		last = s
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: never happened; last: %s", what, last)
}

// outside is the host's rules for the silos as they are: does rpc's exposed port have a rule?
func (r *probeRig) outside() bool {
	var all []*v1.Silo
	list, _ := r.c.List(r.ctx, "Silo", "web3")
	for _, raw := range list.Items {
		if o, _, err := v1.Decode(raw); err == nil {
			all = append(all, o.(*v1.Silo))
		}
	}
	view := worker.NetworkView("hv1", &v1.Host{Spec: v1.HostSpec{Address: "198.51.100.10"}}, all, nil)
	return strings.Contains(kni.Rules(view), "fib daddr type local ip daddr != { 10.62.0.0/16, 10.63.0.0/16, 10.64.0.0/16, 10.65.0.0/16, 127.0.0.0/8 } tcp dport 8545 dnat ip to 10.64.0.4:8545")
}

// dns is what the host's resolver answers for rpc.web3.kevaso: an address, or "" while held.
func (r *probeRig) dns() string {
	ip, _, found := worker.Lookup("rpc.web3.kevaso", []*v1.Silo{r.silo("rpc")})
	if !found || !ip.IsValid() {
		return ""
	}
	return ip.String()
}

func endpointNames(eps []v1.ServiceEndpoint) string {
	var n []string
	for _, e := range eps {
		n = append(n, e.Silo)
	}
	return strings.Join(n, ",")
}

func rpcSilo(routeWhen string, probe bool) *v1.Silo {
	s := silo("rpc", "web3")
	s.Labels = map[string]string{"app": "rpc"}
	s.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Name: "rpc", Port: 8545}}, Expose: v1.ExposeHostPort, RouteWhen: routeWhen}
	if probe {
		s.Spec.Probes = &v1.Probes{Readiness: &v1.Probe{TCP: &v1.TCPProbe{Port: "rpc"}, Period: "1s", Failures: 1}}
	}
	return s
}

func svcOf(name, routeWhen string) *v1.Service {
	return &v1.Service{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Service"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3"},
		Spec: v1.ServiceSpec{Selector: map[string]string{"app": "rpc"}, Ports: []v1.ServicePortSpec{{Name: "rpc", Port: 8545, TargetPort: "rpc"}}, RouteWhen: routeWhen}}
}

// Design §0.6: routeWhen: ready sends nothing until readiness passes — no endpoint, no outside
// rule, no private name — takes it all away when it fails and gives it back; routeWhen: running
// routes throughout; and a routeWhen that isn't stated where it must be is refused.
func TestRouteWhen(t *testing.T) {
	r := newProbeRig(t, nil)
	invalid := func(what string, err error, want string) {
		t.Helper()
		var ce *client.Error
		if !errors.As(err, &ce) || ce.Code != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v, want a 422 saying %q", what, err, want)
		}
	}
	invalid("readiness probe and a service, routeWhen not stated", r.c.Create(r.ctx, rpcSilo("", true)), "say whether traffic waits")
	invalid("routeWhen: ready, no readiness probe", r.c.Create(r.ctx, rpcSilo(v1.RouteWhenReady, false)), "ready needs a readiness probe")

	r.place(t, rpcSilo(v1.RouteWhenReady, true))
	invalid("a Service stating nothing in front of a probed silo", r.c.Create(r.ctx, svcOf("bare", "")), "isn't stated")
	if err := r.c.Create(r.ctx, svcOf("rpc", v1.RouteWhenReady)); err != nil {
		t.Fatal(err)
	}
	if err := r.c.Create(r.ctx, svcOf("any", v1.RouteWhenRunning)); err != nil {
		t.Fatal(err)
	}
	plain := silo("plain", "web3")
	plain.Labels = map[string]string{"app": "plain"}
	r.place(t, plain)
	ready := svcOf("plain", v1.RouteWhenReady)
	ready.Spec.Selector = map[string]string{"app": "plain"}
	invalid("a ready Service in front of a silo with no probe", r.c.Create(r.ctx, ready), "no readiness probe")

	held := func(phase string) {
		t.Helper()
		r.eventually(t, phase+": held everywhere", func() (bool, string) {
			s, svc, any := r.silo("rpc"), r.service("rpc"), r.service("any")
			ok := s.Status.Phase == "Running" && !meta.IsTrue(s.Status.Conditions, "Ready") &&
				len(svc.Status.Endpoints) == 0 && endpointNames(svc.Status.Held) == "rpc" &&
				endpointNames(any.Status.Endpoints) == "rpc" && // running: routed throughout
				!r.outside() && r.dns() == "" && s.Status.Routing != nil && !s.Status.Routing.Routed
			return ok, endpointNames(svc.Status.Endpoints) + "|" + endpointNames(svc.Status.Held) + "|" + endpointNames(any.Status.Endpoints) + " " + condMsgs(s.Status.Conditions)
		})
		if h := r.service("rpc").Status.Held[0]; !strings.Contains(h.Reason, "not ready") || h.Since == nil {
			t.Fatalf("%s: held endpoint says %+v", phase, h)
		}
	}
	routed := func(phase string) {
		t.Helper()
		r.eventually(t, phase+": routed everywhere", func() (bool, string) {
			s, svc, any := r.silo("rpc"), r.service("rpc"), r.service("any")
			ok := meta.IsTrue(s.Status.Conditions, "Ready") && endpointNames(svc.Status.Endpoints) == "rpc" && len(svc.Status.Held) == 0 &&
				endpointNames(any.Status.Endpoints) == "rpc" && r.outside() && r.dns() == "10.64.0.4" && s.Status.Routing.Routed
			return ok, endpointNames(svc.Status.Endpoints) + "|" + endpointNames(svc.Status.Held) + " " + condMsgs(s.Status.Conditions)
		})
	}
	held("before readiness passes")
	// What people see while it's held.
	if out := r.h.ok("", "describe", "silo", "rpc", "-n", "web3"); !strings.Contains(out, "held since") || !strings.Contains(out, "Route when:  ready") ||
		!strings.Contains(out, "readiness") || !strings.Contains(out, "connection refused") {
		t.Fatalf("describe silo while held:\n%s", out)
	}
	if out := r.h.ok("", "describe", "service", "rpc", "-n", "web3"); !strings.Contains(out, "0 routed, 1 held") || !strings.Contains(out, "held since") {
		t.Fatalf("describe service while held:\n%s", out)
	}
	if out := r.h.ok("", "get", "silos", "-n", "web3"); !strings.Contains(out, "no (NotReady)") {
		t.Fatalf("get silos while not ready:\n%s", out)
	}

	r.up(true)
	routed("readiness passes")
	if out := r.h.ok("", "describe", "service", "rpc", "-n", "web3"); !strings.Contains(out, "1 routed, 0 held") || !strings.Contains(out, "routed") {
		t.Fatalf("describe service while routed:\n%s", out)
	}
	if out := r.h.ok("", "get", "silos", "-n", "web3"); !strings.Contains(out, "yes") {
		t.Fatalf("get silos while ready:\n%s", out)
	}
	r.up(false)
	held("readiness fails")
	r.up(true)
	routed("readiness passes again")

	// No probe, nothing stated: running, and the status says it wasn't stated.
	if rt := r.silo("plain").Status.Routing; rt != nil {
		t.Fatalf("a silo without a service has no routing: %+v", rt)
	}
}

// Startup past its deadline is StartFailed and the silo stays up; liveness report only marks it
// Degraded; liveness restart restarts it in place, with a backoff and a count.
func TestStartupAndLiveness(t *testing.T) {
	var mu sync.Mutex
	alive := map[string]bool{}
	r := newProbeRig(t, func(id kri.ID, cmd []string, _ []byte) (string, int) {
		mu.Lock()
		defer mu.Unlock()
		switch strings.Join(cmd, " ") {
		case "check-up":
			return "still booting", 1
		case "alive":
			if !alive[id.Name] {
				return "wedged", 1
			}
		}
		return "", 0
	})
	exec := func(cmd string) *v1.Probe {
		return &v1.Probe{Exec: &v1.ExecProbe{Command: []string{cmd}}, Period: "1s"}
	}

	slow := silo("slow", "web3")
	slow.Spec.Probes = &v1.Probes{Startup: exec("check-up"), Readiness: exec("ready")}
	slow.Spec.Probes.Startup.Timeout = "2s"
	r.place(t, slow)
	sick := silo("sick", "web3")
	sick.Spec.Probes = &v1.Probes{Liveness: exec("alive")}
	sick.Spec.Probes.Liveness.Failures = 1
	r.place(t, sick)
	crashy := silo("crashy", "web3")
	crashy.Spec.Probes = &v1.Probes{Liveness: exec("alive")}
	crashy.Spec.Probes.Liveness.Failures, crashy.Spec.Probes.Liveness.OnFailure = 1, v1.OnFailureRestart
	r.place(t, crashy)

	r.eventually(t, "startup past its deadline", func() (bool, string) {
		s := r.silo("slow")
		rs, _ := r.rt.Status(r.ctx, kri.ID{Namespace: "web3", Name: "slow", UID: s.UID})
		rd := v1.FindProbe(s.Status.Probes, v1.ProbeReadiness)
		return meta.IsTrue(s.Status.Conditions, "StartFailed") && !meta.IsTrue(s.Status.Conditions, "Ready") &&
			s.Status.Phase == "Running" && rs.State == kri.Running && rd != nil && rd.State == v1.ProbeDisabled, condMsgs(s.Status.Conditions)
	})
	if c := meta.FindCondition(r.silo("slow").Status.Conditions, "Started"); c.Reason != "StartupTimedOut" || !strings.Contains(c.Message, "still booting") {
		t.Fatalf("started: %+v", c)
	}

	r.eventually(t, "liveness report: Degraded, nothing else", func() (bool, string) {
		s := r.silo("sick")
		c := meta.FindCondition(s.Status.Conditions, "Degraded")
		return c != nil && c.Status == meta.ConditionTrue && c.Reason == "LivenessFailing" && strings.Contains(c.Message, "wedged") &&
			meta.IsTrue(s.Status.Conditions, "Ready"), condMsgs(s.Status.Conditions)
	})

	r.eventually(t, "liveness restart: restarted once", func() (bool, string) {
		s := r.silo("crashy")
		return s.Status.Restarts != nil && s.Status.Restarts.Count == 1 && s.Status.Phase == "Running", condMsgs(s.Status.Conditions)
	})
	// Still failing: the backoff holds the next restart back (10s for the second).
	time.Sleep(4 * time.Second)
	s := r.silo("crashy")
	if s.Status.Restarts.Count != 1 {
		t.Fatalf("restarted again within the backoff: %+v", s.Status.Restarts)
	}
	if !meta.IsTrue(s.Status.Conditions, "Degraded") {
		t.Fatalf("crashy isn't Degraded while failing: %s", condMsgs(s.Status.Conditions))
	}
	mu.Lock()
	alive["crashy"] = true
	mu.Unlock()
	r.eventually(t, "crashy healthy again", func() (bool, string) {
		s := r.silo("crashy")
		c := meta.FindCondition(s.Status.Conditions, "Degraded")
		return c != nil && c.Status == meta.ConditionFalse && meta.IsTrue(s.Status.Conditions, "Ready"), condMsgs(s.Status.Conditions)
	})

	calls := strings.Join(r.rt.Calls, ",")
	if strings.Count(calls, "stop web3/sick") != 0 || r.silo("sick").Status.Restarts != nil {
		t.Fatalf("report restarted: %s", calls)
	}
	// In place: stopped and started, never created again, reset or deleted.
	if strings.Count(calls, "stop web3/crashy") != 1 || strings.Count(calls, "start web3/crashy") != 2 ||
		strings.Count(calls, "create web3/crashy") != 1 || strings.Contains(calls, "reset web3/crashy") || strings.Contains(calls, "delete web3/crashy") {
		t.Fatalf("restart wasn't in place: %s", calls)
	}
	if out := r.h.ok("", "describe", "silo", "crashy", "-n", "web3"); !strings.Contains(out, "Liveness restarts:  1") || !strings.Contains(out, "on failure restart") {
		t.Fatalf("describe crashy:\n%s", out)
	}
}
