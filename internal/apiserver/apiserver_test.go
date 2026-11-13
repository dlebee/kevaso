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
		Spec:       v1.SiloSpec{Runtime: "cloud-hypervisor", Image: "ubuntu-24.04", Resources: v1.Resources{CPU: 2, Memory: "4Gi"}},
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
	a.Spec.Image = "ubuntu-26.04"
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
	s.Spec.Image = "sneaky"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	if s.Status.Host != "hv1" || s.Spec.Image != "ubuntu-24.04" || s.Generation != 1 {
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
		Spec: v1.HostSpec{Address: "203.0.113.10"}}
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

func TestServiceAndPoolValidation(t *testing.T) {
	c, ctx := setup(t)
	svc := func(f func(*v1.Silo)) *v1.Silo {
		s := newSilo("p2p")
		s.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Name: "p2p", Port: 30303}, {Name: "disc", Port: 30303, Protocol: "UDP"}}}
		f(s)
		return s
	}
	good := svc(func(s *v1.Silo) {
		s.Spec.Service.Expose = "hostPort"
		s.Spec.Service.HostPort = &v1.HostPortSpec{Ports: []string{"p2p", "disc"}, AllowFrom: []string{"203.0.113.0/24", "198.51.100.7"}}
		s.Spec.Network.Egress.Source = "sameAsService"
		s.Spec.AllowFrom = []v1.AllowFrom{{Silo: "ops/grafana", Ports: []string{"p2p"}}}
	})
	if err := c.Create(ctx, good); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]*v1.Silo{
		"unknown expose":          svc(func(s *v1.Silo) { s.Spec.Service.Expose = "public" }),
		"port 0":                  svc(func(s *v1.Silo) { s.Spec.Service.Ports[0].Port = 0 }),
		"SCTP":                    svc(func(s *v1.Silo) { s.Spec.Service.Ports[0].Protocol = "SCTP" }),
		"duplicate port names":    svc(func(s *v1.Silo) { s.Spec.Service.Ports[1].Name = "p2p" }),
		"hostPort without expose": svc(func(s *v1.Silo) { s.Spec.Service.HostPort = &v1.HostPortSpec{} }),
		"hostPort names a ghost": svc(func(s *v1.Silo) {
			s.Spec.Service.Expose = "hostPort"
			s.Spec.Service.HostPort = &v1.HostPortSpec{Ports: []string{"rpc"}}
		}),
		"bad CIDR": svc(func(s *v1.Silo) {
			s.Spec.Service.Expose = "hostPort"
			s.Spec.Service.HostPort = &v1.HostPortSpec{AllowFrom: []string{"10.0.0.0/33"}}
		}),
		"LB class with bad characters": svc(func(s *v1.Silo) {
			s.Spec.Service.Expose = "loadBalancer"
			s.Spec.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: "Linode_NB"}
		}),
		"address on worker-ip": svc(func(s *v1.Silo) {
			s.Spec.Service.Expose = "loadBalancer"
			s.Spec.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: "worker-ip", Address: "203.0.113.9"}
		}),
		"ip-pool without a pool": svc(func(s *v1.Silo) {
			s.Spec.Service.Expose = "loadBalancer"
			s.Spec.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: "ip-pool"}
		}),
		"sameAsService, private":   svc(func(s *v1.Silo) { s.Spec.Network.Egress.Source = "sameAsService" }),
		"egress pool without pool": svc(func(s *v1.Silo) { s.Spec.Network.Egress.Source = "pool" }),
		"allowFrom a/b/c":          svc(func(s *v1.Silo) { s.Spec.AllowFrom = []v1.AllowFrom{{Silo: "a/b/c"}} }),
	} {
		s.Name = "bad"
		if err := c.Create(ctx, s); !client.IsInvalid(err) {
			t.Errorf("%s: want Invalid, got %v", name, err)
		}
	}
	pool := func(addrs ...string) *v1.IPPool {
		return &v1.IPPool{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IPPool"}, ObjectMeta: meta.ObjectMeta{Name: "extra"},
			Spec: v1.IPPoolSpec{Host: "metal-1", Addresses: addrs}}
	}
	for name, p := range map[string]*v1.IPPool{"empty": pool(), "garbage": pool("nope"), "IPv6 for now": pool("2001:db8:42::/64")} {
		if err := c.Create(ctx, p); !client.IsInvalid(err) {
			t.Errorf("pool %s: want Invalid, got %v", name, err)
		}
	}
	if err := c.Create(ctx, pool("198.51.100.16/29", "198.51.100.30")); err != nil {
		t.Fatal(err)
	}
}
