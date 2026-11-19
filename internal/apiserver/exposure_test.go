package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

func TestExposureLoosenedIsDirectional(t *testing.T) {
	base := exposedSilo()
	next := func(edit func(*v1.Silo)) *v1.Silo {
		t.Helper()
		s := cloneOf(t, base)
		edit(s)
		return s
	}
	web := func(s *v1.Silo) *v1.ServicePort { return &s.Spec.Service.Ports[0] }
	debug := func(s *v1.Silo) *v1.ServicePort { return &s.Spec.Service.Ports[1] }
	cases := []struct {
		name string
		next *v1.Silo
		want bool
	}{
		{"unchanged", cloneOf(t, base), false},
		{"narrower sources", next(func(s *v1.Silo) { web(s).Sources = []string{"10.1.0.0/16"} }), false},
		{"drop a host network", next(func(s *v1.Silo) { web(s).HostPort = nil }), false},
		{"remove an outside port", next(func(s *v1.Silo) {
			s.Spec.Service.Ports = s.Spec.Service.Ports[:1]
		}), false},
		{"add a lease", next(func(s *v1.Silo) { web(s).Lease = &v1.PortLease{} }), false},
		{"an unparseable source is not a widening", next(func(s *v1.Silo) { web(s).Sources = []string{"not-an-ip"} }), false},
		{"clear sources", next(func(s *v1.Silo) { web(s).Sources = nil }), true},
		{"the world", next(func(s *v1.Silo) { web(s).Sources = []string{"0.0.0.0/0"} }), true},
		{"a source outside the old ones", next(func(s *v1.Silo) { web(s).Sources = []string{"10.0.0.0/8", "11.0.0.0/8"} }), true},
		{"a new host network", next(func(s *v1.Silo) { web(s).HostPort = []string{v1.NetworkExternal, v1.NetworkInternal} }), true},
		{"a new number", next(func(s *v1.Silo) { web(s).As = 8443 }), true},
		{"a new protocol", next(func(s *v1.Silo) { s.Spec.Ports[0].Protocol = "UDP" }), true},
		{"a new outside port", next(func(s *v1.Silo) {
			s.Spec.Ports = append(s.Spec.Ports, v1.SiloPort{Name: "metrics", Port: 9090})
			s.Spec.Service.Ports = append(s.Spec.Service.Ports, v1.ServicePort{Port: "metrics", HostPort: []string{v1.NetworkExternal}})
		}), true},
		{"a lease removed", next(func(s *v1.Silo) { debug(s).Lease = nil }), true},
		{"approval no longer required", next(func(s *v1.Silo) { debug(s).Lease = &v1.PortLease{} }), true},
		{"a load balancer added", next(func(s *v1.Silo) { web(s).LoadBalancer = true }), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := exposureLoosened(base, c.next, nil, nil, nil); got != c.want {
				t.Fatalf("loosened %v, want %v", got, c.want)
			}
		})
	}

	classed := cloneOf(t, base)
	web(classed).LoadBalancer = true
	changed := cloneOf(t, classed)
	changed.Spec.Service.LoadBalancer.Class = "other"
	if !exposureLoosened(classed, changed, nil, nil, nil) {
		t.Fatal("a changed load-balancer class is a loosening")
	}
	dropped := cloneOf(t, classed)
	web(dropped).LoadBalancer = false
	if exposureLoosened(classed, dropped, nil, nil, nil) {
		t.Fatal("dropping a load balancer needs no extra permission")
	}

	open := cloneOf(t, base)
	web(open).Sources = nil
	narrowed := cloneOf(t, open)
	web(narrowed).Sources = []string{"10.0.0.0/8"}
	if exposureLoosened(open, narrowed, nil, nil, nil) {
		t.Fatal("adding sources where there were none is a tightening")
	}

	set := &v1.SiloSet{ObjectMeta: meta.ObjectMeta{Name: "set", Namespace: "d"}, Spec: v1.SiloSetSpec{Template: v1.SiloTemplate{SiloSpec: base.Spec}}}
	setNext := cloneOf(t, set)
	setNext.Spec.Template.Ports = append(setNext.Spec.Template.Ports, v1.SiloPort{Name: "metrics", Port: 9090})
	setNext.Spec.Template.Service.Ports = append(setNext.Spec.Template.Service.Ports, v1.ServicePort{Port: "metrics", HostPort: []string{v1.NetworkExternal}})
	if !exposureLoosened(set, setNext, nil, nil, nil) {
		t.Fatal("a SiloSet template is judged the same way")
	}
	if a, b := exposureFacts(base), exposureFacts(base); a != b || a == "" {
		t.Fatalf("facts %q", a)
	}
	if exposureFacts(base) == exposureFacts(next(func(s *v1.Silo) { web(s).Sources = nil })) {
		t.Fatal("clearing sources did not change what a policy may widen")
	}
}

func TestASelectorOrIngressBackendCanLoosen(t *testing.T) {
	pay := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "pay", Namespace: "d", Labels: map[string]string{"app": "pay"}}}
	web := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "d", Labels: map[string]string{"app": "web"}},
		Spec: v1.SiloSpec{Ports: []v1.SiloPort{{Name: "debug", Port: 9229}},
			Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "debug", HostPort: []string{v1.NetworkExternal}, Lease: &v1.PortLease{}}}}}}
	lb := &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "edge", Namespace: "d"},
		Spec: v1.ServiceSpec{Type: v1.ServiceLoadBalancer, LoadBalancerClass: "linode-nodebalancer",
			Selector: map[string]string{"app": "pay"}, Ports: []v1.ServicePortSpec{{Name: "http", Port: 80, TargetPort: "debug"}}}}
	silos := []*v1.Silo{pay, web}
	svcs := []*v1.Service{lb}

	joined := cloneOf(t, web)
	joined.Labels = map[string]string{"app": "pay"}
	if !exposureLoosened(web, joined, silos, svcs, nil) {
		t.Fatal("labels that newly match a load balancer are a loosening")
	}
	left := cloneOf(t, pay)
	left.Labels = map[string]string{"app": "other"}
	if exposureLoosened(pay, left, silos, svcs, nil) {
		t.Fatal("leaving a load balancer needs no extra permission")
	}
	if !exposureLoosened(nil, joined, silos, svcs, nil) {
		t.Fatal("creating a silo a load balancer already selects is a loosening")
	}

	if !exposureLoosened(nil, lb, silos, nil, nil) {
		t.Fatal("a new load balancer needs the permission")
	}
	cluster := cloneOf(t, lb)
	cluster.Spec.Type = v1.ServiceClusterIP
	cluster.Spec.LoadBalancerClass = ""
	retargeted := cloneOf(t, cluster)
	retargeted.Spec.Selector = map[string]string{"app": "web"}
	if exposureLoosened(cluster, retargeted, silos, nil, nil) {
		t.Fatal("a ClusterIP service never needs expose-public")
	}
	wider := cloneOf(t, lb)
	wider.Spec.Selector = map[string]string{"app": "web"}
	if !exposureLoosened(lb, wider, silos, svcs, nil) {
		t.Fatal("a selector that matches a new silo is a loosening")
	}
	narrower := cloneOf(t, lb)
	narrower.Spec.Selector = map[string]string{"app": "pay", "tier": "a"}
	if exposureLoosened(lb, narrower, silos, svcs, nil) {
		t.Fatal("a selector that matches no new silo needs no extra permission")
	}
	ported := cloneOf(t, lb)
	ported.Spec.Ports[0].Port = 81
	if !exposureLoosened(lb, ported, silos, svcs, nil) {
		t.Fatal("a changed port number is a loosening")
	}
	reclassed := cloneOf(t, lb)
	reclassed.Spec.LoadBalancerClass = "other"
	if !exposureLoosened(lb, reclassed, silos, svcs, nil) {
		t.Fatal("a changed class is a loosening")
	}
	shorter := cloneOf(t, lb)
	shorter.Spec.Ports = append(shorter.Spec.Ports, v1.ServicePortSpec{Name: "extra", Port: 9})
	back := cloneOf(t, shorter)
	back.Spec.Ports = back.Spec.Ports[:1]
	if exposureLoosened(shorter, back, silos, svcs, nil) {
		t.Fatal("removing a port needs no extra permission")
	}

	ing := &v1.Ingress{ObjectMeta: meta.ObjectMeta{Name: "in", Namespace: "d"},
		Spec: v1.IngressSpec{Rules: []v1.IngressRule{{Path: "/", Service: v1.IngressTarget{Name: "web", Port: "debug"}}}}}
	if !exposureLoosened(nil, ing, silos, svcs, nil) {
		t.Fatal("an Ingress on a leased port needs the permission")
	}
	pathed := cloneOf(t, ing)
	pathed.Spec.Rules[0].Path = "/x"
	if exposureLoosened(ing, pathed, silos, svcs, nil) {
		t.Fatal("a path change needs no extra permission")
	}
	plain := cloneOf(t, ing)
	plain.Spec.Rules[0].Service.Port = "http"
	if exposureLoosened(nil, plain, silos, svcs, nil) {
		t.Fatal("a backend that is not leased needs no extra permission from this check")
	}
	matching := cloneOf(t, lb)
	matching.Spec.Selector = map[string]string{"app": "web"}
	via := cloneOf(t, ing)
	via.Spec.Rules[0].Service = v1.IngressTarget{Name: "edge", Port: "http"}
	if !exposureLoosened(nil, via, silos, []*v1.Service{matching}, nil) {
		t.Fatal("a standalone service's target port is leased when the silo it selects leases it")
	}

	set := &v1.SiloSet{ObjectMeta: meta.ObjectMeta{Name: "pool", Namespace: "d"},
		Spec: v1.SiloSetSpec{Template: v1.SiloTemplate{Labels: map[string]string{"app": "web"}}}}
	joinedSet := cloneOf(t, set)
	joinedSet.Spec.Template.Labels = map[string]string{"app": "pay"}
	if !exposureLoosened(set, joinedSet, nil, svcs, nil) {
		t.Fatal("a SiloSet whose template labels newly match a load balancer is a loosening")
	}
	ownLabels := cloneOf(t, set)
	ownLabels.Labels = map[string]string{"app": "pay"}
	if exposureLoosened(set, ownLabels, nil, svcs, nil) {
		t.Fatal("a SiloSet's own labels are not what a load balancer selects")
	}

	early := &v1.Ingress{ObjectMeta: meta.ObjectMeta{Name: "early", Namespace: "d"},
		Spec: v1.IngressSpec{Rules: []v1.IngressRule{{Path: "/", Service: v1.IngressTarget{Name: "edge", Port: "http"}}}}}
	opened := &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "edge", Namespace: "d"},
		Spec: v1.ServiceSpec{Type: v1.ServiceClusterIP, Selector: map[string]string{"app": "web"},
			Ports: []v1.ServicePortSpec{{Name: "http", Port: 80, TargetPort: "debug"}}}}
	if !exposureLoosened(nil, opened, silos, nil, []*v1.Ingress{early}) {
		t.Fatal("creating a service an Ingress already names, on a leased port, is a loosening")
	}
	quiet := cloneOf(t, opened)
	quiet.Spec.Selector = map[string]string{"app": "other"}
	if exposureLoosened(nil, quiet, silos, nil, []*v1.Ingress{early}) {
		t.Fatal("a service that selects no leased port needs no extra permission from the Ingress")
	}
	if !exposureLoosened(quiet, opened, silos, []*v1.Service{quiet}, []*v1.Ingress{early}) {
		t.Fatal("a selector change onto a leased port an Ingress names is a loosening")
	}
	retargetedPort := cloneOf(t, opened)
	retargetedPort.Spec.Ports[0].Port = 81
	if exposureLoosened(opened, retargetedPort, silos, []*v1.Service{opened}, []*v1.Ingress{early}) {
		t.Fatal("a service whose selector is unchanged is not judged again for the Ingress")
	}

	bySet := cloneOf(t, lb)
	bySet.Spec.Selector = map[string]string{v1.LabelSiloSet: "pool"}
	named := &v1.SiloSet{ObjectMeta: meta.ObjectMeta{Name: "pool", Namespace: "d"},
		Spec: v1.SiloSetSpec{Template: v1.SiloTemplate{Labels: map[string]string{"app": "web"}}}}
	if !exposureLoosened(nil, named, nil, []*v1.Service{bySet}, nil) {
		t.Fatal("a SiloSet whose name a load balancer selects is a loosening")
	}
	otherSet := cloneOf(t, named)
	otherSet.Name = "other"
	if exposureLoosened(nil, otherSet, nil, []*v1.Service{bySet}, nil) {
		t.Fatal("a SiloSet a load balancer does not name needs no extra permission")
	}

	plainSvc := &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "d"},
		Spec: v1.ServiceSpec{Type: v1.ServiceClusterIP, Selector: map[string]string{"app": "pay"},
			Ports: []v1.ServicePortSpec{{Name: "http", Port: 80, TargetPort: "debug"}}}}
	namedIng := &v1.Ingress{ObjectMeta: meta.ObjectMeta{Name: "named", Namespace: "d"},
		Spec: v1.IngressSpec{Rules: []v1.IngressRule{{Path: "/", Service: v1.IngressTarget{Name: "api", Port: "http"}}}}}
	if !exposureLoosened(web, joined, silos, []*v1.Service{plainSvc}, []*v1.Ingress{namedIng}) {
		t.Fatal("labels that newly join a service an Ingress names, on a leased port, are a loosening")
	}
	if exposureLoosened(web, joined, silos, []*v1.Service{plainSvc}, nil) {
		t.Fatal("joining a ClusterIP service an Ingress does not name needs no extra permission")
	}
}

func TestAnEditorNeedsExposePublicToLoosenOutsideReach(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(0)
	srv, err := NewWithAuth(st, clock.Real{}, &Auth{CA: ca, Tokens: &jointoken.Issuer{Store: st, Clock: clock.Real{}}})
	if err != nil {
		t.Fatal(err)
	}
	comp, done := srv.InProcess()
	defer done()
	ed, doneEd := srv.InProcessAs(pki.Identity{Type: "user", Name: "ed", Role: "member"})
	defer doneEd()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must(comp.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "web3"}}))
	must(comp.Create(ctx, &v1.RoleBinding{TypeMeta: tm("RoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "ed", Namespace: "web3"},
		RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "editor"}, Subjects: []v1.Subject{{Kind: "User", Name: "ed"}}}))
	api := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "web3"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Ports: []v1.SiloPort{{Name: "web", Port: 8080}, {Name: "debug", Port: 9229}},
			Service: &v1.SiloService{Ports: []v1.ServicePort{
				{Port: "web", HostPort: []string{v1.NetworkExternal}, As: 8080, Sources: []string{"10.0.0.0/8"}},
				{Port: "debug", HostPort: []string{v1.NetworkExternal}, Lease: &v1.PortLease{}},
			}}}}
	must(comp.Create(ctx, api))
	pay := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "pay", Namespace: "web3", Labels: map[string]string{"app": "pay"}},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}
	web := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "web3", Labels: map[string]string{"app": "web"}},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}
	shop := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "shop", Namespace: "web3", Labels: map[string]string{"app": "shop"}},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}
	must(comp.Create(ctx, pay))
	must(comp.Create(ctx, web))
	must(comp.Create(ctx, shop))
	must(comp.Create(ctx, &v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "edge", Namespace: "web3"},
		Spec: v1.ServiceSpec{Type: v1.ServiceLoadBalancer, LoadBalancerClass: "linode-nodebalancer",
			Selector: map[string]string{"app": "pay"}, Ports: []v1.ServicePortSpec{{Name: "http", Port: 80}}}}))
	must(comp.Create(ctx, &v1.IngressClass{TypeMeta: tm("IngressClass"), ObjectMeta: meta.ObjectMeta{Name: "office"},
		Spec: v1.IngressClassSpec{Controller: v1.IngressController{Driver: "nginx", Namespace: "web3", Silo: "edge"},
			Hosts: []v1.HostAssignment{{Host: "app.example.com", Namespaces: []string{"web3"}}}}}))
	must(comp.Create(ctx, &v1.Ingress{TypeMeta: tm("Ingress"), ObjectMeta: meta.ObjectMeta{Name: "in", Namespace: "web3"},
		Spec: v1.IngressSpec{IngressClass: "office", Hosts: []string{"app.example.com"}, TLS: v1.IngressTLS{None: true},
			Rules: []v1.IngressRule{{Path: "/", Service: v1.IngressTarget{Name: "api", Port: "web"}}}}}))

	var cur v1.Silo
	must(ed.Get(ctx, "Silo", "web3", "api", &cur))
	cur.Spec.Resources.Memory = "2Gi"
	if err := ed.Update(ctx, &cur); err != nil {
		t.Fatalf("an editor changes memory: %v", err)
	}
	must(ed.Get(ctx, "Silo", "web3", "api", &cur))
	cur.Spec.Service.Ports[0].Sources = nil
	if err := ed.Update(ctx, &cur); codeOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "expose-public") {
		t.Fatalf("clearing sources: %v, want 403", err)
	}
	must(ed.Get(ctx, "Silo", "web3", "api", &cur))
	cur.Spec.Service.Ports[0].Sources = []string{"10.1.0.0/16"}
	if err := ed.Update(ctx, &cur); err != nil {
		t.Fatalf("narrowing sources: %v", err)
	}
	must(ed.Get(ctx, "Silo", "web3", "api", &cur))
	cur.Spec.Ports = append(cur.Spec.Ports, v1.SiloPort{Name: "metrics", Port: 9090})
	cur.Spec.Service.Ports = append(cur.Spec.Service.Ports, v1.ServicePort{Port: "metrics", HostPort: []string{v1.NetworkExternal}})
	if err := ed.Update(ctx, &cur); codeOf(err) != http.StatusForbidden {
		t.Fatalf("a new host port: %v, want 403", err)
	}

	var webSilo v1.Silo
	must(ed.Get(ctx, "Silo", "web3", "web", &webSilo))
	webSilo.Labels = map[string]string{"app": "other"}
	if err := ed.Update(ctx, &webSilo); err != nil {
		t.Fatalf("labels that still match no load balancer: %v", err)
	}
	must(ed.Get(ctx, "Silo", "web3", "web", &webSilo))
	webSilo.Labels = map[string]string{"app": "pay"}
	if err := ed.Update(ctx, &webSilo); codeOf(err) != http.StatusForbidden {
		t.Fatalf("labels newly selected by a load balancer: %v, want 403", err)
	}

	var svc v1.Service
	must(ed.Get(ctx, "Service", "web3", "edge", &svc))
	svc.Spec.Selector = map[string]string{"app": "pay", "tier": "a"}
	if err := ed.Update(ctx, &svc); err != nil {
		t.Fatalf("a selector that matches no new silo: %v", err)
	}
	must(ed.Get(ctx, "Service", "web3", "edge", &svc))
	svc.Spec.Selector = map[string]string{"app": "shop"}
	if err := ed.Update(ctx, &svc); codeOf(err) != http.StatusForbidden {
		t.Fatalf("a selector that matches a new silo: %v, want 403", err)
	}

	var ing v1.Ingress
	must(ed.Get(ctx, "Ingress", "web3", "in", &ing))
	ing.Spec.Rules[0].Path = "/x"
	if err := ed.Update(ctx, &ing); err != nil {
		t.Fatalf("a path change: %v", err)
	}
	must(ed.Get(ctx, "Ingress", "web3", "in", &ing))
	ing.Spec.Rules[0].Service.Port = "debug"
	if err := ed.Update(ctx, &ing); codeOf(err) != http.StatusForbidden {
		t.Fatalf("an Ingress backend on a leased port: %v, want 403", err)
	}

	must(comp.Create(ctx, &v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "pool-edge", Namespace: "web3"},
		Spec: v1.ServiceSpec{Type: v1.ServiceLoadBalancer, LoadBalancerClass: "linode-nodebalancer",
			Selector: map[string]string{"app": "pool"}, Ports: []v1.ServicePortSpec{{Name: "http", Port: 80}}}}))
	pool := &v1.SiloSet{TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "pool", Namespace: "web3"},
		Spec: v1.SiloSetSpec{Instances: 1, Template: v1.SiloTemplate{
			Labels:   map[string]string{"app": "web"},
			SiloSpec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}},
		}}}
	must(comp.Create(ctx, pool))
	var gotSet v1.SiloSet
	must(ed.Get(ctx, "SiloSet", "web3", "pool", &gotSet))
	gotSet.Spec.Template.Labels = map[string]string{"app": "other"}
	if err := ed.Update(ctx, &gotSet); err != nil {
		t.Fatalf("template labels that still match no load balancer: %v", err)
	}
	must(ed.Get(ctx, "SiloSet", "web3", "pool", &gotSet))
	gotSet.Spec.Template.Labels = map[string]string{"app": "pool"}
	if err := ed.Update(ctx, &gotSet); codeOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "expose-public") {
		t.Fatalf("template labels newly selected by a load balancer: %v, want 403", err)
	}

	// The Ingress names a service that does not exist yet, so nothing leased is selected.
	// Creating that service, selecting a silo whose port is leased, is the loosening.
	must(comp.Create(ctx, &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "hook", Namespace: "web3", Labels: map[string]string{"app": "hook"}},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Ports:   []v1.SiloPort{{Name: "debug", Port: 9229}},
			Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "debug", HostPort: []string{v1.NetworkExternal}, Lease: &v1.PortLease{}}}}}}))
	must(comp.Create(ctx, &v1.Ingress{TypeMeta: tm("Ingress"), ObjectMeta: meta.ObjectMeta{Name: "early", Namespace: "web3"},
		Spec: v1.IngressSpec{IngressClass: "office", Hosts: []string{"app.example.com"}, TLS: v1.IngressTLS{None: true},
			Rules: []v1.IngressRule{{Path: "/early", Service: v1.IngressTarget{Name: "later", Port: "http"}}}}}))
	later := &v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "later", Namespace: "web3"},
		Spec: v1.ServiceSpec{Type: v1.ServiceClusterIP, Selector: map[string]string{"app": "hook"},
			Ports: []v1.ServicePortSpec{{Name: "http", Port: 80, TargetPort: "debug"}}}}
	if err := ed.Create(ctx, later); codeOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "expose-public") {
		t.Fatalf("a service an Ingress already names, on a leased port: %v, want 403", err)
	}
	later.Spec.Selector = map[string]string{"app": "other"}
	must(comp.Create(ctx, later))
	var gotSvc v1.Service
	must(ed.Get(ctx, "Service", "web3", "later", &gotSvc))
	gotSvc.Spec.Ports[0].Port = 81
	if err := ed.Update(ctx, &gotSvc); err != nil {
		t.Fatalf("a port change that leaves the selector: %v", err)
	}
	must(ed.Get(ctx, "Service", "web3", "later", &gotSvc))
	gotSvc.Spec.Selector = map[string]string{"app": "hook"}
	if err := ed.Update(ctx, &gotSvc); codeOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "expose-public") {
		t.Fatalf("a selector change onto a leased port an Ingress names: %v, want 403", err)
	}

	must(comp.Create(ctx, &v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "by-set", Namespace: "web3"},
		Spec: v1.ServiceSpec{Type: v1.ServiceLoadBalancer, LoadBalancerClass: "linode-nodebalancer",
			Selector: map[string]string{v1.LabelSiloSet: "byname"}, Ports: []v1.ServicePortSpec{{Name: "http", Port: 80}}}}))
	byName := &v1.SiloSet{TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "byname", Namespace: "web3"},
		Spec: v1.SiloSetSpec{Instances: 1, Template: v1.SiloTemplate{
			Labels:   map[string]string{"app": "web"},
			SiloSpec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}},
		}}}
	if err := ed.Create(ctx, byName); codeOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "expose-public") {
		t.Fatalf("a SiloSet whose name a load balancer selects: %v, want 403", err)
	}

	must(comp.Create(ctx, &v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "plain", Namespace: "web3"},
		Spec: v1.ServiceSpec{Type: v1.ServiceClusterIP, Selector: map[string]string{"app": "joined"},
			Ports: []v1.ServicePortSpec{{Name: "http", Port: 80, TargetPort: "debug"}}}}))
	must(comp.Create(ctx, &v1.Ingress{TypeMeta: tm("Ingress"), ObjectMeta: meta.ObjectMeta{Name: "plain-in", Namespace: "web3"},
		Spec: v1.IngressSpec{IngressClass: "office", Hosts: []string{"app.example.com"}, TLS: v1.IngressTLS{None: true},
			Rules: []v1.IngressRule{{Path: "/plain", Service: v1.IngressTarget{Name: "plain", Port: "http"}}}}}))
	var hook v1.Silo
	must(ed.Get(ctx, "Silo", "web3", "hook", &hook))
	hook.Labels = map[string]string{"app": "joined"}
	if err := ed.Update(ctx, &hook); codeOf(err) != http.StatusForbidden || !strings.Contains(err.Error(), "expose-public") {
		t.Fatalf("labels that newly join a service an Ingress names: %v, want 403", err)
	}
}

func exposedSilo() *v1.Silo {
	return &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "d"},
		Spec: v1.SiloSpec{
			Ports: []v1.SiloPort{{Name: "web", Port: 8080}, {Name: "debug", Port: 9229}},
			Service: &v1.SiloService{LoadBalancer: &v1.LoadBalancerSpec{Class: v1.LBIPPool}, Ports: []v1.ServicePort{
				{Port: "web", HostPort: []string{v1.NetworkExternal}, As: 8080, Sources: []string{"10.0.0.0/8"}},
				{Port: "debug", HostPort: []string{v1.NetworkExternal}, Lease: &v1.PortLease{Approval: &v1.ApprovalRule{Required: true}}},
			}},
		}}
}

func cloneOf[T any](t *testing.T, in *T) *T {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}
