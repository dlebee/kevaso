package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

func setup(t *testing.T) (*client.Client, context.Context) {
	t.Helper()
	srv, err := apiserver.New(store.NewMemory(0), clock.NewFake(time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c := client.New(ts.URL)
	ns := &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	return c, ctx
}

func newSilo(name string) *v1.Silo {
	return &v1.Silo{
		TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"},
		ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
		Spec:       v1.SiloSpec{Runtime: "cloud-hypervisor", VM: &v1.VMSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 2, Memory: "4Gi"}},
	}
}

func TestCreateFillsSystemFields(t *testing.T) {
	c, ctx := setup(t)
	s := newSilo("hello")
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	if s.UID == "" || s.ResourceVersion == "" || s.Generation != 1 || s.CreationTimestamp == nil {
		t.Fatalf("system fields not filled: %+v", s.ObjectMeta)
	}
	var got v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "hello", &got); err != nil {
		t.Fatal(err)
	}
	if got.UID != s.UID || got.Spec.Runtime != "cloud-hypervisor" {
		t.Fatalf("get returned %+v", got)
	}
	if err := c.Create(ctx, newSilo("hello")); !client.IsAlreadyExists(err) {
		t.Fatalf("second create: want AlreadyExists, got %v", err)
	}
}

func TestStaleUpdateIsAConflict(t *testing.T) {
	c, ctx := setup(t)
	s := newSilo("hello")
	_ = c.Create(ctx, s)
	a, b := *s, *s // two clients read the same version
	a.Spec.VM = &v1.VMSource{Image: "ubuntu-26.04"}
	if err := c.Update(ctx, &a); err != nil {
		t.Fatal(err)
	}
	b.Spec.Resources.CPU = 8
	if err := c.Update(ctx, &b); !client.IsConflict(err) {
		t.Fatalf("stale update: want Conflict, got %v", err)
	}
	b.ResourceVersion = ""
	if err := c.Update(ctx, &b); err == nil || !strings.Contains(err.Error(), "resourceVersion is required") {
		t.Fatalf("update without resourceVersion: got %v", err)
	}
}

func TestGenerationMovesOnlyWithSpec(t *testing.T) {
	c, ctx := setup(t)
	s := newSilo("hello")
	_ = c.Create(ctx, s)
	s.Labels = map[string]string{"team": "payments"} // metadata only
	_ = c.Update(ctx, s)
	if s.Generation != 1 {
		t.Fatalf("label change bumped generation to %d", s.Generation)
	}
	s.Spec.Resources.CPU = 4
	_ = c.Update(ctx, s)
	if s.Generation != 2 {
		t.Fatalf("spec change: generation %d, want 2", s.Generation)
	}
}

func TestStatusIsASubresource(t *testing.T) {
	c, ctx := setup(t)
	s := newSilo("hello")
	_ = c.Create(ctx, s)
	// A controller writes status; the spec it sends is ignored.
	s.Status = v1.SiloStatus{Phase: "Scheduled", Host: "hv1"}
	s.Spec.VM = &v1.VMSource{Image: "sneaky"}
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	if s.Status.Host != "hv1" || s.Spec.From() != "ubuntu-24.04" || s.Generation != 1 {
		t.Fatalf("after status update: spec %+v status %+v gen %d", s.Spec, s.Status, s.Generation)
	}
	// A user writes spec; the status they send is ignored.
	s.Status = v1.SiloStatus{Phase: "Bogus"}
	s.Spec.Resources.CPU = 4
	if err := c.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
	if s.Status.Phase != "Scheduled" || s.Spec.Resources.CPU != 4 {
		t.Fatalf("after spec update: spec %+v status %+v", s.Spec, s.Status)
	}
}

func TestValidation(t *testing.T) {
	c, ctx := setup(t)
	for name, mutate := range map[string]func(*v1.Silo){
		"unknown runtime":        func(s *v1.Silo) { s.Spec.Runtime = "kubernetes" },
		"negative cpu":           func(s *v1.Silo) { s.Spec.Resources.CPU = -1 },
		"toleration without key": func(s *v1.Silo) { s.Spec.Tolerations = []v1.Toleration{{Value: "x"}} },
		"NoExecute toleration":   func(s *v1.Silo) { s.Spec.Tolerations = []v1.Toleration{{Key: "k", Effect: "NoExecute"}} },
		"bad name":               func(s *v1.Silo) { s.Name = "Hello_World" },
		"init step without run":  func(s *v1.Silo) { s.Spec.Init = &v1.Init{Steps: []v1.InitStep{{Name: "x"}}} },
		"init without steps":     func(s *v1.Silo) { s.Spec.Init = &v1.Init{} },
		"duplicate init step names": func(s *v1.Silo) {
			s.Spec.Init = &v1.Init{Steps: []v1.InitStep{{Name: "x", Run: "true"}, {Name: "x", Run: "false"}}}
		},
		"init when typo": func(s *v1.Silo) {
			s.Spec.Init = &v1.Init{When: "always", Steps: []v1.InitStep{{Name: "x", Run: "true"}}}
		},
	} {
		s := newSilo("ok")
		mutate(s)
		if err := c.Create(ctx, s); !client.IsInvalid(err) {
			t.Errorf("%s: want Invalid, got %v", name, err)
		}
	}
	host := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{ExternalIP: "203.0.113.10"}}
	if err := c.Create(ctx, host); !client.IsInvalid(err) || !strings.Contains(err.Error(), "at least one component") {
		t.Errorf("host without components: got %v", err)
	}
	host.Spec.Components.Worker = &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "cloud-hypervisor"}},
		Taints: []v1.Taint{{Key: "pool", Value: "quarantine", Effect: v1.NoSchedule}}}
	if err := c.Create(ctx, host); err != nil {
		t.Errorf("valid host: %v", err)
	}
}

func TestStrictDecodingAndPaths(t *testing.T) {
	c, ctx := setup(t)
	post := func(path, body string) int {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	silo := `{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"x"},"spec":{"runtime":"docker"%s}}`
	for name, tc := range map[string]struct {
		path, body string
		want       int
	}{
		"unknown field (typo)":    {"/apis/kevaso/v1/namespaces/dev/silos", strings.Replace(silo, "%s", `,"runtim":"x"`, 1), 422},
		"kind doesn't match path": {"/apis/kevaso/v1/namespaces/dev/hosts", strings.Replace(silo, "%s", "", 1), 404},
		"namespace missing":       {"/apis/kevaso/v1/namespaces/nope/silos", strings.Replace(silo, "%s", "", 1), 404},
		"namespaced kind, no ns":  {"/apis/kevaso/v1/silos", strings.Replace(silo, "%s", "", 1), 400},
		"unknown resource":        {"/apis/kevaso/v1/pods", `{}`, 404},
		"wrong apiVersion":        {"/apis/kevaso/v1/namespaces/dev/silos", `{"apiVersion":"v1","kind":"Silo"}`, 400},
		"ok":                      {"/apis/kevaso/v1/namespaces/dev/silos", strings.Replace(silo, "%s", "", 1), 201},
	} {
		if got := post(tc.path, tc.body); got != tc.want {
			t.Errorf("%s: status %d, want %d", name, got, tc.want)
		}
	}
}

func TestListAndWatchResume(t *testing.T) {
	c, ctx := setup(t)
	_ = c.Create(ctx, newSilo("a"))
	l, err := c.List(ctx, "Silo", "dev")
	if err != nil || len(l.Items) != 1 {
		t.Fatalf("list: %v, %d items", err, len(l.Items))
	}
	ch, err := c.Watch(ctx, "Silo", "dev", l.Metadata.ResourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	b := newSilo("b")
	_ = c.Create(ctx, b)
	b.Spec.Resources.CPU = 8
	_ = c.Update(ctx, b)
	_ = c.Delete(ctx, "Silo", "dev", "b")
	for _, want := range []string{"ADDED", "MODIFIED", "DELETED"} {
		select {
		case ev := <-ch:
			obj, _, err := v1.Decode(ev.Object)
			if err != nil || ev.Type != want || obj.GetObjectMeta().Name != "b" {
				t.Fatalf("event %s %v, want %s of b", ev.Type, err, want)
			}
			if obj.GetObjectMeta().ResourceVersion == "" {
				t.Fatal("watched object has no resourceVersion")
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s event", want)
		}
	}
	// All namespaces: the namespaced kind's cluster-wide list.
	all, _ := c.List(ctx, "Silo", "")
	if len(all.Items) != 1 {
		t.Fatalf("all-namespaces list: %d items, want 1", len(all.Items))
	}
}

func TestFinalizersHoldDeletion(t *testing.T) {
	c, ctx := setup(t)
	s := newSilo("hello")
	s.Finalizers = []string{"kevaso.com/disk"}
	_ = c.Create(ctx, s)
	if err := c.Delete(ctx, "Silo", "dev", "hello"); err != nil {
		t.Fatal(err)
	}
	var got v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "hello", &got); err != nil || got.DeletionTimestamp == nil {
		t.Fatalf("with a finalizer, delete must only mark it: %v %+v", err, got.ObjectMeta)
	}
	// While deleting, finalizers can only be removed.
	got.Finalizers = append(got.Finalizers, "kevaso.com/new")
	if err := c.Update(ctx, &got); !client.IsInvalid(err) {
		t.Fatalf("adding a finalizer while deleting: want Invalid, got %v", err)
	}
	_ = c.Get(ctx, "Silo", "dev", "hello", &got)
	got.Finalizers = nil // the disk controller is done
	if err := c.Update(ctx, &got); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Silo", "dev", "hello", &got); !client.IsNotFound(err) {
		t.Fatalf("after the last finalizer: want NotFound, got %v", err)
	}
}

func TestRBACObjectsAreValidated(t *testing.T) {
	c, ctx := setup(t)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	good := &v1.RoleBinding{TypeMeta: tm("RoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "bob", Namespace: "dev"},
		RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "editor"}, Subjects: []v1.Subject{{Kind: "User", Name: "bob"}}}
	if err := c.Create(ctx, good); err != nil {
		t.Fatal(err)
	}
	for name, obj := range map[string]meta.Object{
		"bad verb": &v1.Role{TypeMeta: tm("Role"), ObjectMeta: meta.ObjectMeta{Name: "r", Namespace: "dev"},
			Rules: []v1.PolicyRule{{Verbs: []string{"exec"}, Resources: []string{"silos"}}}},
		"no resources": &v1.ClusterRole{TypeMeta: tm("ClusterRole"), ObjectMeta: meta.ObjectMeta{Name: "r"},
			Rules: []v1.PolicyRule{{Verbs: []string{"get"}}}},
		"no subjects": &v1.RoleBinding{TypeMeta: tm("RoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "b", Namespace: "dev"},
			RoleRef: v1.RoleRef{Kind: "Role", Name: "r"}},
		"bad subject kind": &v1.RoleBinding{TypeMeta: tm("RoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "b", Namespace: "dev"},
			RoleRef: v1.RoleRef{Kind: "Role", Name: "r"}, Subjects: []v1.Subject{{Kind: "Robot", Name: "x"}}},
		"cluster binding to a Role": &v1.ClusterRoleBinding{TypeMeta: tm("ClusterRoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "b"},
			RoleRef: v1.RoleRef{Kind: "Role", Name: "r"}, Subjects: []v1.Subject{{Kind: "User", Name: "x"}}},
	} {
		if err := c.Create(ctx, obj); !client.IsInvalid(err) {
			t.Errorf("%s: want Invalid, got %v", name, err)
		}
	}
}

func TestServiceAndAddressValidation(t *testing.T) {
	c, ctx := setup(t)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	svc := func(f func(*v1.Silo)) *v1.Silo {
		s := newSilo("p2p")
		s.Spec.Ports = []v1.SiloPort{{Name: "p2p", Port: 30303}, {Name: "disc", Port: 30303, Protocol: "UDP"}}
		s.Spec.Services = []v1.SiloService{{Ports: []v1.ServicePort{{Port: "p2p"}, {Port: "disc"}}}}
		f(s)
		return s
	}
	good := svc(func(s *v1.Silo) {
		srcs := []string{"203.0.113.0/24", "198.51.100.7"}
		s.Spec.Services = []v1.SiloService{{Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "eth"}, Ports: []v1.ServicePort{
			{Port: "p2p", Sources: srcs, AllowFrom: []string{"ops/grafana"}},
			{Port: "disc", Sources: srcs},
		}}}
		s.Spec.Network.Egress.Source = &v1.EgressSource{IP: "eth"}
	})
	if err := c.Create(ctx, good); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]*v1.Silo{
		"unknown worker network": svc(func(s *v1.Silo) {
			s.Spec.Services[0].Type, s.Spec.Services[0].HostPort = v1.ServiceHostPort, &v1.HostPortSource{Worker: "public"}
		}),
		"port 0":               svc(func(s *v1.Silo) { s.Spec.Ports[0].Port = 0 }),
		"SCTP":                 svc(func(s *v1.Silo) { s.Spec.Ports[0].Protocol = "SCTP" }),
		"duplicate port names": svc(func(s *v1.Silo) { s.Spec.Ports[1].Name = "p2p" }),
		"sources on Internal":  svc(func(s *v1.Silo) { s.Spec.Services[0].Ports[0].Sources = []string{"10.0.0.0/8"} }),
		"service port a ghost": svc(func(s *v1.Silo) { s.Spec.Services[0].Ports[0].Port = "rpc" }),
		"bad CIDR": svc(func(s *v1.Silo) {
			s.Spec.Services[0].Type = v1.ServiceHostPort
			s.Spec.Services[0].Ports[0].Sources = []string{"10.0.0.0/33"}
		}),
		"provider with bad characters": svc(func(s *v1.Silo) {
			s.Spec.Services[0].Type, s.Spec.Services[0].LoadBalancer = v1.ServiceLoadBalancer, &v1.LoadBalancerSpec{Provider: "Linode_NB"}
		}),
		"own on a single silo": svc(func(s *v1.Silo) { s.Spec.Network.Egress.Source = &v1.EgressSource{Own: true} }),
		"two ways in one service": svc(func(s *v1.Silo) {
			s.Spec.Services[0].Type, s.Spec.Services[0].HostPort = v1.ServiceHostPort, &v1.HostPortSource{Worker: "external", IP: "eth"}
		}),
		"allowFrom a/b/c": svc(func(s *v1.Silo) { s.Spec.Services[0].Ports[0].AllowFrom = []string{"a/b/c"} }),
	} {
		s.Name = "bad"
		if err := c.Create(ctx, s); !client.IsInvalid(err) {
			t.Errorf("%s: want Invalid, got %v", name, err)
		}
	}
	// IPs: an explicit type and only its fields.
	mkIP := func(name string, sp v1.IPSpec) *v1.IP {
		return &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"}, Spec: sp}
	}
	for name, x := range map[string]*v1.IP{
		"no type":             mkIP("x", v1.IPSpec{HostAddress: "mail"}),
		"Host with a region":  mkIP("x", v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail", Region: "us-ord"}),
		"Provider, no region": mkIP("x", v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode"}),
	} {
		if err := c.Create(ctx, x); !client.IsInvalid(err) {
			t.Errorf("IP %s: want Invalid, got %v", name, err)
		}
	}
	// A host's extra addresses: named, one IPv4 address each, names unique in the cluster.
	host := func(name, ext string, a ...v1.HostAddress) *v1.Host {
		return &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{ExternalIP: ext, Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}, Addresses: a}}
	}
	for name, a := range map[string]v1.HostAddress{
		"garbage":      {Name: "x", Kind: "external", Address: "nope"},
		"IPv6 for now": {Name: "x", Kind: "external", Address: "2001:db8:42::1"},
		"a range":      {Name: "x", Kind: "external", Address: "198.51.100.0/30"},
		"no kind":      {Name: "x", Address: "198.51.100.20"},
	} {
		if err := c.Create(ctx, host("addr", "198.51.100.9", a)); !client.IsInvalid(err) {
			t.Errorf("host address %s: want Invalid, got %v", name, err)
		}
	}
	if err := c.Create(ctx, host("metal-1", "198.51.100.9", v1.HostAddress{Name: "eth", Kind: "external", Address: "198.51.100.21"},
		v1.HostAddress{Name: "mail", Kind: "external", Address: "198.51.100.22"})); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, host("metal-2", "198.51.100.10", v1.HostAddress{Name: "eth", Kind: "external", Address: "198.51.100.31"})); !client.IsConflict(err) ||
		!strings.Contains(err.Error(), "address name eth is metal-1's already") {
		t.Errorf("a second host's eth: %v, want 409 naming metal-1", err)
	}
	if err := c.Create(ctx, host("metal-2", "198.51.100.10", v1.HostAddress{Name: "web", Kind: "external", Address: "198.51.100.21"})); !client.IsConflict(err) ||
		!strings.Contains(err.Error(), "is metal-1 (eth) already") {
		t.Errorf("metal-1's address on metal-2: %v, want 409", err)
	}
	if err := c.Create(ctx, host("metal-2", "198.51.100.10", v1.HostAddress{Name: "web", Kind: "external", Address: "198.51.100.31"})); err != nil {
		t.Fatal(err)
	}
	// Two Host IPs no host has together.
	for _, x := range []*v1.IP{
		mkIP("eth", v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "eth"}),
		mkIP("mail", v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail"}),
		mkIP("web", v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "web"}),
		mkIP("edge", v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "us-ord"}),
	} {
		if err := c.Create(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	apart := svc(func(s *v1.Silo) {
		s.Name = "apart"
		s.Spec.Services = []v1.SiloService{{Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "eth"}, Ports: []v1.ServicePort{{Port: "p2p"}, {Port: "disc"}}}}
		s.Spec.Network.Egress.Source = &v1.EgressSource{IP: "web"}
	})
	if err := c.Create(ctx, apart); !client.IsInvalid(err) || !strings.Contains(err.Error(), "no host has both") {
		t.Errorf("IPs of metal-1 and metal-2 on one silo: %v, want Invalid", err)
	}
	together := svc(func(s *v1.Silo) {
		s.Name = "together"
		s.Spec.Services = []v1.SiloService{{Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "eth"}, Ports: []v1.ServicePort{{Port: "p2p"}, {Port: "disc"}}}}
		s.Spec.Network.Egress.Source = &v1.EgressSource{IP: "mail"}
	})
	if err := c.Create(ctx, together); err != nil {
		t.Errorf("two IPs of metal-1: %v", err)
	}
	// A balancer's kept IP is a Provider IP of the balancer's provider.
	balanced := func(name, provider, ip string) *v1.Silo {
		return svc(func(s *v1.Silo) {
			s.Name = name
			s.Spec.Services = []v1.SiloService{{Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: provider, IP: ip}, Ports: []v1.ServicePort{{Port: "p2p"}}}}
		})
	}
	if err := c.Create(ctx, balanced("lb-host", "linode", "eth")); !client.IsInvalid(err) || !strings.Contains(err.Error(), "a balancer is the provider's") {
		t.Errorf("a balancer on a host's address: %v, want Invalid", err)
	}
	if err := c.Create(ctx, balanced("lb-other", "azure", "edge")); !client.IsInvalid(err) || !strings.Contains(err.Error(), "edge is linode's, and the balancer is azure's") {
		t.Errorf("a balancer on another provider's IP: %v, want Invalid", err)
	}
	if err := c.Create(ctx, balanced("lb", "linode", "edge")); err != nil {
		t.Errorf("a balancer on its provider's IP: %v", err)
	}
	if err := c.Create(ctx, balanced("lb-later", "linode", "not-yet")); err != nil {
		t.Errorf("an IP not made yet could work later: %v", err)
	}
	// A Service is never a HostPort; a SiloSet's template never names one IP.
	hp := &v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "group", Namespace: "dev"},
		Spec: v1.ServiceSpec{Type: v1.ServiceHostPort, Selector: map[string]string{"app": "p2p"}, Ports: []v1.ServicePortSpec{{Name: "p2p", Port: 30303}}}}
	if err := c.Create(ctx, hp); !client.IsInvalid(err) || !strings.Contains(err.Error(), "a Service of several can't be one") {
		t.Errorf("a HostPort Service: %v, want Invalid", err)
	}
	set := &v1.SiloSet{TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "pool", Namespace: "dev"},
		Spec: v1.SiloSetSpec{Instances: 1, Template: v1.SiloTemplate{SiloSpec: good.Spec}}}
	if err := c.Create(ctx, set); !client.IsInvalid(err) || !strings.Contains(err.Error(), "one IP can't serve many instances") {
		t.Errorf("a template naming an IP: %v, want Invalid", err)
	}
	set.Spec.IPs = "pool-ips"
	set.Spec.Template.Services[0].HostPort = &v1.HostPortSource{Own: true}
	set.Spec.Template.Network.Egress.Source = &v1.EgressSource{Own: true}
	if err := c.Create(ctx, set); err != nil {
		t.Errorf("a template on own with ips: %v", err)
	}
}
