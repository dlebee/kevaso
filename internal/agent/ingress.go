package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	kicdrivers "kevaso.com/core/builtin/kic"
	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/sdk/kic"
	"kevaso.com/core/sdk/kri"
)

// Ingress controllers, driven from outside (design §7.3). For every silo on this host that runs an
// IngressClass's proxy, the agent gets the class's desired state from the control plane, renders it
// with the class's driver and applies it to the proxy (internal/ingress: write, check, only then
// reload), then says how it went in the class's status. The proxy is the vendor's image: it never
// calls Kevaso, and nothing of Kevaso's is put in it but its configuration and certificates.

// DefaultIngressEvery is how often the agent looks at its ingress controllers again (ACME HTTP-01
// challenges must be served soon after they appear).
const DefaultIngressEvery = 3 * time.Second

// IngressDrivers are the drivers the agent renders with.
var IngressDrivers = kicdrivers.Builtin()

// ingressLoop is the agent's ingress side: what it last applied to each controller silo.
type ingressLoop struct {
	a       *Agent
	classes *informer.Informer
	applied map[string]string // silo uid → the plan in effect ("?": unknown, the last try failed midway)
	// lastGood is the state last applied in full to each controller silo. While the class is held
	// (an Ingress refused), it's what keeps serving, with the current ACME challenges in it.
	lastGood map[string]kic.State
	kick     chan struct{}
}

func (a *Agent) runIngress(ctx context.Context) {
	l := &ingressLoop{a: a, classes: informer.New(a.Client, "IngressClass"), applied: map[string]string{}, lastGood: map[string]kic.State{}, kick: make(chan struct{}, 1)}
	l.classes.AddHandler(func(informer.Key) { l.poke() })
	go l.classes.Run(ctx)
	if !l.classes.WaitSynced(ctx) || !a.silos.WaitSynced(ctx) {
		return
	}
	every := a.IngressEvery
	if every <= 0 {
		every = DefaultIngressEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		l.once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-l.kick:
		}
	}
}

func (l *ingressLoop) poke() {
	select {
	case l.kick <- struct{}{}:
	default:
	}
}

// once looks at every controller silo on this host.
func (l *ingressLoop) once(ctx context.Context) {
	a := l.a
	if a.ControlPlaneHeld() {
		return // §0.7: the routes stay as they are
	}
	var classes []*v1.IngressClass
	for _, o := range l.classes.List() {
		classes = append(classes, o.(*v1.IngressClass))
	}
	seen := map[string]bool{}
	for _, o := range a.silos.List() {
		s := o.(*v1.Silo)
		if s.Status.Host != a.HostName || s.DeletionTimestamp != nil || s.Status.Phase != PhaseRunning {
			continue
		}
		var mine []*v1.IngressClass
		for _, c := range classes {
			if c.Spec.Controller.Runs(s) {
				mine = append(mine, c)
			}
		}
		if len(mine) == 0 {
			continue
		}
		seen[s.UID] = true
		if err := l.apply(ctx, s, mine); err != nil {
			a.log("ingress controller %s/%s: %v", s.Namespace, s.Name, err)
		}
	}
	for uid := range l.applied {
		if !seen[uid] {
			delete(l.applied, uid) // not a controller here any more: a new one starts from what's there
			delete(l.lastGood, uid)
		}
	}
}

func (l *ingressLoop) apply(ctx context.Context, s *v1.Silo, classes []*v1.IngressClass) error {
	a := l.a
	rt, ok := a.Runtimes[s.Spec.Runtime]
	if !ok {
		return nil
	}
	var d ingress.Desired
	q := url.Values{"namespace": {s.Namespace}, "name": {s.Name}}
	if err := a.Client.Call(ctx, http.MethodGet, client.PathAgentIngress+"?"+q.Encode(), nil, &d); err != nil {
		return fmt.Errorf("desired state: %w", err)
	}
	report := ingressReport{silo: s, class: d.Class}
	drv, err := IngressDrivers.Get(d.Driver)
	switch {
	case d.Problem != "": // the class itself can't be served (an unknown driver, an option it refuses)
		report.rejected = d.Problem
	case err != nil:
		report.rejected = err.Error()
	default:
		// Per Ingress (design §0.8): a broken one is held back alone, at its last good version,
		// and every other one, new ones and the current ACME challenges included, goes out; the
		// class is held only when even its own part (options, challenges) is refused.
		id := idOf(s)
		exec := func(ctx context.Context, argv []string, stdin []byte) (int, string, error) {
			var out bytes.Buffer
			req := kri.ExecRequest{Command: argv, Stdout: &out, Stderr: &out}
			if stdin != nil {
				req.Stdin = bytes.NewReader(stdin)
			}
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			code, err := rt.Exec(cctx, id, req)
			return code, out.String(), err
		}
		call := func(ctx context.Context, c kic.Call) (int, string, error) {
			st, err := rt.Status(ctx, id)
			if err != nil {
				return 0, "", err
			}
			if st.Address == "" {
				return 0, "", fmt.Errorf("no address to reach its admin API on")
			}
			return adminCall(ctx, st.Address, c)
		}
		var lastGood *kic.State
		if lg, ok := l.lastGood[s.UID]; ok {
			lastGood = &lg
		}
		res, err := ingress.ApplyEach(ctx, exec, call, drv, d, lastGood, l.applied[s.UID], ingress.MemoryOf(s.UID), 0)
		if err != nil {
			l.applied[s.UID] = "?" // it may be half done: never take what's there as applied
			return err
		}
		l.applied[s.UID] = res.Hash
		report.applied = res.Hash
		report.blamed = slices.Sorted(maps.Keys(res.LeftOut))
		switch {
		case res.Held != "":
			report.rejected = "held (the last good configuration stays): the proxy refuses even the class's own part: " + res.Held
		case res.Rejected != "":
			report.rejected = res.Rejected
		default:
			l.lastGood[s.UID] = res.Served
			report.rejected = ingress.LeftOutMessage(res.LeftOut)
		}
		switch {
		case res.Changed:
			a.log("ingress controller %s/%s: class %s applied (%s: %d routes, %d certificates, %d challenges; %d Ingresses held back, %d test runs)",
				s.Namespace, s.Name, d.Class, d.Driver, len(res.Served.Routes), len(res.Served.Certificates), len(res.Served.Challenges), len(res.LeftOut), res.Tests)
		case res.Held != "":
			a.log("ingress controller %s/%s: class %s held (keeping the last good configuration): %s", s.Namespace, s.Name, d.Class, res.Held)
		}
	}
	for _, c := range classes {
		if c.Name != d.Class {
			continue
		}
		if err := l.report(ctx, c, report); err != nil {
			return fmt.Errorf("status of class %s: %w", c.Name, err)
		}
	}
	return nil
}

// adminCall is an HTTP call to a proxy's admin API on its silo IP.
func adminCall(ctx context.Context, address string, c kic.Call) (int, string, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	u := "http://" + net.JoinHostPort(address, strconv.Itoa(c.Port)) + c.Path
	req, err := http.NewRequestWithContext(cctx, c.Method, u, bytes.NewReader(c.Body))
	if err != nil {
		return 0, "", err
	}
	if c.ContentType != "" {
		req.Header.Set("Content-Type", c.ContentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(body), nil
}

type ingressReport struct {
	silo     *v1.Silo
	class    string
	applied  string
	rejected string
	blamed   []string
}

// report puts how applying went in the class's status: this silo's entry, and the Applied
// condition over every entry. Written only when it changes.
func (l *ingressLoop) report(ctx context.Context, c *v1.IngressClass, r ingressReport) error {
	a := l.a
	for attempt := 0; attempt < 3; attempt++ {
		var cur v1.IngressClass
		if err := a.Client.Get(ctx, "IngressClass", "", c.Name, &cur); err != nil {
			return client.IgnoreNotFound(err)
		}
		before, _ := json.Marshal(cur.Status)
		entry := v1.IngressControllerStatus{Silo: r.silo.Name, Host: a.HostName}
		i := slices.IndexFunc(cur.Status.Controllers, func(e v1.IngressControllerStatus) bool { return e.Silo == r.silo.Name })
		if i >= 0 {
			entry = cur.Status.Controllers[i]
		}
		entry.Host = a.HostName
		if r.applied != "" && r.applied != "?" && r.applied != entry.Applied {
			now := a.now()
			entry.Applied, entry.AppliedAt = r.applied, &now
		}
		entry.Rejected, entry.Blamed = r.rejected, r.blamed
		if i >= 0 {
			cur.Status.Controllers[i] = entry
		} else {
			cur.Status.Controllers = append(cur.Status.Controllers, entry)
			slices.SortFunc(cur.Status.Controllers, func(x, y v1.IngressControllerStatus) int {
				if x.Silo < y.Silo {
					return -1
				}
				if x.Silo > y.Silo {
					return 1
				}
				return 0
			})
		}
		status, reason, msg := meta.ConditionTrue, "Applied", "every controller serves the latest configuration"
		for _, e := range cur.Status.Controllers {
			switch {
			case e.Rejected != "":
				status, reason, msg = meta.ConditionFalse, "Rejected", e.Silo+": "+e.Rejected
			case e.Applied == "" && status == meta.ConditionTrue:
				status, reason, msg = meta.ConditionFalse, "Pending", e.Silo+": nothing applied yet"
			}
		}
		meta.SetCondition(&cur.Status.Conditions, meta.Condition{Type: "Applied", Status: status, Reason: reason, Message: msg, ObservedGeneration: cur.Generation}, a.now())
		after, _ := json.Marshal(cur.Status)
		if bytes.Equal(before, after) {
			return nil
		}
		err := a.Client.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return err
	}
	return nil
}
