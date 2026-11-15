package ingress_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/builtin/kic/caddy"
	"kevaso.com/core/builtin/kic/kong"
	"kevaso.com/core/builtin/kic/nginx"
	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/internal/ingress/ingresstest"
	"kevaso.com/core/sdk/kic"
)

// §0.8 (2026-11-14): a held ingress class holds back only the broken Ingress. Driven through the
// driver interface for every built-in driver, with a pretend proxy whose config test (or admin
// API) refuses whatever carries a poisoned host name, with or without saying where.

// rig is one driver's pretend proxy.
type rig struct {
	name   string
	driver kic.Driver
	px     *ingresstest.Proxy
	served func() string // what the proxy runs now
	calls  int
	blame  bool   // the proxy's refusal says where
	live   []byte // what an admin-API proxy runs
	exec   ingress.Exec
	call   ingress.Caller
}

const poison = "poison"

// poisonLine is the 1-based line a proxy's error names for the first poisoned Ingress in cfg: the
// first line from its host on that lies in an Ingress's marked section (a real proxy names the
// directive it can't take, inside the Ingress's part; the host line itself is outside it).
func poisonLine(cfg []byte) int {
	lines := strings.Split(string(cfg), "\n")
	for i, l := range lines {
		if !strings.Contains(l, poison) {
			continue
		}
		for n := i + 1; n <= len(lines); n++ {
			if len(kic.MarkedBlame(cfg, n)) > 0 {
				return n
			}
		}
		return i + 1
	}
	return 0
}

func rigs(blame bool) []*rig {
	var out []*rig
	for _, d := range []kic.Driver{nginx.Driver{}, caddy.Driver{}, kong.Driver{}} {
		r := &rig{name: d.Info().Name, driver: d, px: ingresstest.New(), blame: blame}
		switch r.name {
		case "nginx":
			r.px.CheckCmd, r.px.ReloadCmd = []string{"nginx", "-t"}, []string{"nginx", "-s", "reload"}
			r.px.Check = func(cfg []byte, _ map[string][]byte) string {
				if n := poisonLine(cfg); n > 0 {
					if blame {
						return fmt.Sprintf("nginx: [emerg] host not found in %s:%d", nginx.ConfigPath, n)
					}
					return "nginx: [emerg] configuration refused"
				}
				return ""
			}
			r.served = func() string { f, _, _ := r.px.Snapshot(); return string(f[nginx.ConfigPath]) }
		case "caddy":
			r.px.CheckCmd, r.px.ReloadCmd = []string{"caddy", "validate"}, []string{"caddy", "reload"}
			r.px.Check = func(cfg []byte, _ map[string][]byte) string {
				if n := poisonLine(cfg); n > 0 {
					if blame {
						return fmt.Sprintf("Error: adapting config using caddyfile: Caddyfile:%d: unrecognized", n)
					}
					return "Error: refused"
				}
				return ""
			}
			r.px.Reset(map[string][]byte{caddy.ConfigPath: []byte(ingresstest.CaddyImageConfig)})
			r.served = func() string { f, _, _ := r.px.Snapshot(); return string(f[caddy.ConfigPath]) }
		case "kong":
			r.call = func(_ context.Context, c kic.Call) (int, string, error) {
				if c.Method == "GET" && c.Path == "/status" { // what Kong runs (kic.Reader)
					return 200, kongStatus(r.live), nil
				}
				r.calls++
				if !bytes.Contains(c.Body, []byte(poison)) {
					r.live = c.Body
					return 201, "", nil
				}
				if !blame {
					return 400, `{"message":"declarative config is invalid"}`, nil
				}
				var d struct {
					Services []struct {
						Name   string          `json:"name"`
						Routes json.RawMessage `json:"routes"`
					} `json:"services"`
				}
				_ = json.Unmarshal(c.Body, &d)
				var names []string
				for _, s := range d.Services {
					if bytes.Contains(s.Routes, []byte(poison)) {
						names = append(names, fmt.Sprintf("%q", s.Name))
					}
				}
				return 400, `{"flattened_errors":[` + strings.Join(names, ",") + `]}`, nil
			}
			r.served = func() string { return string(r.live) }
		}
		px := r.px
		r.exec = func(_ context.Context, argv []string, stdin []byte) (int, string, error) {
			out, code := px.Handle(argv, stdin)
			return code, out, nil
		}
		out = append(out, r)
	}
	return out
}

// kongStatus is Kong's GET /status for the declarative config it runs (none: all zeros).
func kongStatus(live []byte) string {
	h := strings.Repeat("0", 32)
	if len(live) > 0 {
		sum := md5.Sum(live)
		h = hex.EncodeToString(sum[:])
	}
	return `{"database":{"reachable":true},"server":{"connections_active":1},"configuration_hash":"` + h + `"}`
}

func route(ing, host string, port int) kic.Route {
	return kic.Route{Ingress: ing, Host: host, Path: "/", Backend: kic.Backend{Address: "10.64.0.5", Port: port}}
}

func want(routes ...kic.Route) ingress.Desired {
	return ingress.Desired{Class: "public", State: kic.State{Class: "public", Routes: routes,
		Challenges: []kic.Challenge{{Token: "tok", KeyAuthorization: "tok.thumb"}}}}
}

func TestOneBrokenIngressHoldsBackOnlyItself(t *testing.T) {
	for _, blame := range []bool{true, false} {
		for _, r := range rigs(blame) {
			t.Run(fmt.Sprintf("%s/blame=%v", r.name, blame), func(t *testing.T) {
				ctx := context.Background()
				m := &ingress.Memory{}
				// A good start.
				w1 := want(route("shop/a", "a.example.com", 80), route("shop/b", "b.example.com", 81))
				res, err := ingress.ApplyEach(ctx, r.exec, r.call, r.driver, w1, nil, "", m, 0)
				if err != nil || res.Rejected != "" || res.Held != "" || len(res.LeftOut) != 0 {
					t.Fatalf("first apply: %+v %v", res, err)
				}
				good := res.Served
				last := res.Hash
				// A broken Ingress and a new good one arrive together.
				w2 := want(route("shop/a", "a.example.com", 80), route("shop/b", "b.example.com", 81),
					route("shop/bad", poison+".example.com", 82), route("shop/new", "new.example.com", 83))
				res, err = ingress.ApplyEach(ctx, r.exec, r.call, r.driver, w2, &good, last, m, 0)
				if err != nil {
					t.Fatal(err)
				}
				if res.Held != "" || res.Rejected != "" {
					t.Fatalf("the class was held: %+v", res)
				}
				if got := slices.Sorted(maps.Keys(res.LeftOut)); !slices.Equal(got, []string{"shop/bad"}) {
					t.Fatalf("left out %v, want only shop/bad (%v)", got, res.LeftOut)
				}
				served := r.served()
				for _, h := range []string{"a.example.com", "b.example.com", "new.example.com", "tok.thumb"} {
					if !strings.Contains(served, h) {
						t.Errorf("%s isn't served:\n%s", h, served)
					}
				}
				if strings.Contains(served, poison) {
					t.Errorf("the broken Ingress is served")
				}
				if res.Tests > ingress.DefaultTests {
					t.Errorf("%d test runs for one change", res.Tests)
				}
				// The same state again: nothing at all runs.
				before, checks, calls := len(r.px.Commands()), r.px.Checks, r.calls
				good, last = res.Served, res.Hash
				res2, err := ingress.ApplyEach(ctx, r.exec, r.call, r.driver, w2, &good, last, m, 0)
				if err != nil || res2.Tests != 0 || len(r.px.Commands()) != before || r.px.Checks != checks || r.calls != calls || res2.LeftOut["shop/bad"] == "" {
					t.Errorf("an unchanged state cost %d tests (%d commands): %+v %v", res2.Tests, len(r.px.Commands())-before, res2, err)
				}
				// Another change elsewhere: the broken one isn't tested again (its verdict is kept:
				// the proxy refused it alone). An admin-API driver can't test an Ingress alone, so
				// its verdict holds only while nothing in the class changes (K-063): it is found
				// again, within the bound.
				w3 := w2
				w3.State.Routes = append(slices.Clone(w2.State.Routes), route("shop/c", "c.example.com", 84))
				checks, calls = r.px.Checks, r.calls
				res3, err := ingress.ApplyEach(ctx, r.exec, r.call, r.driver, w3, &good, last, m, 0)
				if err != nil || res3.Held != "" || res3.Rejected != "" || !strings.Contains(r.served(), "c.example.com") {
					t.Fatalf("a later change: %+v %v", res3, err)
				}
				if n := r.px.Checks - checks + r.calls - calls; (r.name != "kong" && n != 1) || n > ingress.DefaultTests {
					t.Errorf("a later change cost %d proxy tests, want 1 (the apply)", n)
				}
				// The Ingress's own status gets its own reason.
				msg := ingress.LeftOutMessage(res3.LeftOut)
				if !strings.HasPrefix(msg, "ingress shop/bad: ") || strings.ContainsAny(msg, "\n") {
					t.Errorf("message %q", msg)
				}
			})
		}
	}
}

// The class is held only when even the configuration with no user Ingress is refused.
func TestTheClassIsHeldOnlyWhenItsOwnPartFails(t *testing.T) {
	for _, r := range rigs(false) {
		t.Run(r.name, func(t *testing.T) {
			ctx := context.Background()
			w := want(route("shop/a", "a.example.com", 80))
			w.State.Challenges = []kic.Challenge{{Token: poison, KeyAuthorization: poison + ".x"}} // breaks the base itself
			res, err := ingress.ApplyEach(ctx, r.exec, r.call, r.driver, w, nil, "", &ingress.Memory{}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if res.Held == "" || res.Changed {
				t.Fatalf("not held: %+v", res)
			}
			if strings.Contains(r.served(), poison) {
				t.Error("a refused configuration is served")
			}
		})
	}
}

// Many changed Ingresses, several broken, no blame: found by bisecting, within the bound; an
// Ingress the bound didn't reach is left out "not checked yet", never served unchecked, and is
// tested on the next pass.
func TestBisectingIsBounded(t *testing.T) {
	for _, r := range rigs(false) {
		if r.name == "kong" {
			continue // no config test: an admin-API driver falls back instead (below)
		}
		t.Run(r.name, func(t *testing.T) {
			ctx := context.Background()
			var routes []kic.Route
			for i := 0; i < 16; i++ {
				h := fmt.Sprintf("h%02d.example.com", i)
				if i == 3 || i == 11 {
					h = fmt.Sprintf("%s%02d.example.com", poison, i)
				}
				routes = append(routes, route(fmt.Sprintf("shop/i%02d", i), h, 80+i))
			}
			m := &ingress.Memory{}
			res, err := ingress.ApplyEach(ctx, r.exec, r.call, r.driver, want(routes...), nil, "", m, 0)
			if err != nil || res.Held != "" || res.Rejected != "" {
				t.Fatalf("%+v %v", res, err)
			}
			if res.Tests > ingress.DefaultTests {
				t.Fatalf("%d tests, bound %d", res.Tests, ingress.DefaultTests)
			}
			for w, why := range res.LeftOut {
				if w != "shop/i03" && w != "shop/i11" && !strings.HasPrefix(why, "not checked yet") {
					t.Errorf("%s left out: %s", w, why)
				}
			}
			for _, w := range []string{"shop/i03", "shop/i11"} {
				if res.LeftOut[w] == "" {
					t.Errorf("%s served", w)
				}
			}
			if strings.Contains(r.served(), poison) {
				t.Error("a broken Ingress is served")
			}
			// Passes later converge: everything good is served.
			good, last := res.Served, res.Hash
			for i := 0; i < 4 && len(res.LeftOut) > 2; i++ {
				w := want(routes...)
				w.State.Challenges[0].KeyAuthorization = fmt.Sprintf("tok.thumb%d", i) // a new pass with a change
				if res, err = ingress.ApplyEach(ctx, r.exec, r.call, r.driver, w, &good, last, m, 0); err != nil {
					t.Fatal(err)
				}
				good, last = res.Served, res.Hash
			}
			if len(res.LeftOut) != 2 {
				t.Errorf("after more passes, still left out: %v", res.LeftOut)
			}
		})
	}
}

// An admin-API driver whose proxy can't say which Ingress it refuses: the Ingresses served
// before stay served, the changed ones are left out, nothing that worked is dropped.
func TestAnAdminAPIDriverWithoutBlameKeepsWhatWorked(t *testing.T) {
	for _, r := range rigs(false) {
		if r.name != "kong" {
			continue
		}
		ctx := context.Background()
		m := &ingress.Memory{}
		w1 := want(route("shop/a", "a.example.com", 80))
		res, err := ingress.ApplyEach(ctx, r.exec, r.call, r.driver, w1, nil, "", m, 0)
		if err != nil || res.Rejected != "" {
			t.Fatal(res, err)
		}
		good := res.Served
		w2 := want(route("shop/a", "a.example.com", 80), route("shop/bad", poison+".example.com", 81))
		res, err = ingress.ApplyEach(ctx, r.exec, r.call, r.driver, w2, &good, res.Hash, m, 0)
		if err != nil || res.Held != "" || res.Rejected != "" || res.LeftOut["shop/bad"] == "" || res.LeftOut["shop/a"] != "" {
			t.Fatalf("%+v %v", res, err)
		}
		if !strings.Contains(r.served(), "a.example.com") {
			t.Error("a route that worked was dropped")
		}
	}
}

// Refused (an Ingress's own status) gives that Ingress's own reason from the controller's report.
func TestLeftOutMessageSegments(t *testing.T) {
	msg := ingress.LeftOutMessage(map[string]string{"a/x": "bad one; really", "b/y": "other\nline"})
	if msg != "ingress a/x: bad one; really; ingress b/y: other line" {
		t.Fatalf("%q", msg)
	}
}

// An edit breaks an Ingress that was served: its last good version keeps being served (only the
// change is held back), and a new Ingress that arrives meanwhile is served too. Also when the
// driver itself refuses the edit (Desire leaves it out of the state, as for a bad annotation).
func TestABrokenEditKeepsTheLastGoodVersion(t *testing.T) {
	for _, blame := range []bool{true, false} {
		for _, r := range rigs(blame) {
			t.Run(fmt.Sprintf("%s/blame=%v", r.name, blame), func(t *testing.T) {
				ctx := context.Background()
				m := &ingress.Memory{}
				w1 := want(route("shop/a", "a.example.com", 80), route("shop/b", "b.example.com", 81))
				res, err := ingress.ApplyEach(ctx, r.exec, r.call, r.driver, w1, nil, "", m, 0)
				if err != nil || res.Rejected != "" {
					t.Fatal(res, err)
				}
				good, last := res.Served, res.Hash
				w2 := want(route("shop/a", poison+".example.com", 80), route("shop/b", "b.example.com", 81), route("shop/new", "new.example.com", 82))
				res, err = ingress.ApplyEach(ctx, r.exec, r.call, r.driver, w2, &good, last, m, 0)
				if err != nil || res.Held != "" || res.Rejected != "" {
					t.Fatalf("%+v %v", res, err)
				}
				served := r.served()
				if !strings.Contains(served, "a.example.com") || strings.Contains(served, poison) || !strings.Contains(served, "new.example.com") {
					t.Fatalf("want a's last good version and the new one served:\n%s", served)
				}
				if why := res.LeftOut["shop/a"]; !strings.Contains(why, "last good version is still served") {
					t.Errorf("shop/a: %q", why)
				}
				// Refused by the driver before any proxy (Desire leaves it out of the state).
				good, last = res.Served, res.Hash
				w3 := want(route("shop/b", "b.example.com", 81), route("shop/new", "new.example.com", 82))
				w3.Refused = map[string]string{"shop/a": "unknown annotation " + r.name + "/x"}
				res, err = ingress.ApplyEach(ctx, r.exec, r.call, r.driver, w3, &good, last, m, 0)
				if err != nil || res.Rejected != "" || !strings.Contains(r.served(), "a.example.com") || !strings.Contains(res.LeftOut["shop/a"], "unknown annotation") {
					t.Fatalf("a driver-refused edit: %+v %v\n%s", res, err, r.served())
				}
			})
		}
	}
}
