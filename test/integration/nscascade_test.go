package integration

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	nscontroller "kevaso.com/core/internal/controllers/namespace"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/nsdelete"
	"kevaso.com/core/internal/store"
)

// deleteLog is a store that records every delete, in order, and can refuse one key's.
type deleteLog struct {
	store.Store
	mu      sync.Mutex
	deleted []store.Key
	fail    func(store.Key) bool
}

func (s *deleteLog) Delete(ctx context.Context, k store.Key, rev int64) (store.Object, error) {
	s.mu.Lock()
	f := s.fail
	s.mu.Unlock()
	if f != nil && f(k) {
		return store.Object{}, errors.New("disk on fire")
	}
	o, err := s.Store.Delete(ctx, k, rev)
	if err == nil {
		s.mu.Lock()
		s.deleted = append(s.deleted, k)
		s.mu.Unlock()
	}
	return o, err
}

func (s *deleteLog) setFail(f func(store.Key) bool) {
	s.mu.Lock()
	s.fail = f
	s.mu.Unlock()
}

func (s *deleteLog) log() []store.Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.Key(nil), s.deleted...)
}

// cascadeRig is a cluster with kevasod's namespace controller, and namespace web3 holding two
// silos (one with a disk), a service, a secret and a role.
func cascadeRig(t *testing.T) (*cluster, *deleteLog) {
	t.Helper()
	st := &deleteLog{Store: store.NewMemory(0)}
	c := newClusterOn(t, st)
	ctx, stop := context.WithCancel(c.ctx)
	namespaces := informer.New(c.admin, "Namespace")
	e := engine.New(clock.Real{})
	e.Register(&nscontroller.Controller{Client: c.admin, Clock: clock.Real{}, Wait: 20 * time.Millisecond}, engine.Options{})
	namespaces.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Namespace", Name: k.Name}) })
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); namespaces.Run(ctx) }()
	go func() { defer wg.Done(); e.Run(ctx) }()
	t.Cleanup(func() { stop(); wg.Wait() }) // registered after the cluster's: runs before its folders go
	if err := c.admin.Create(c.ctx, ns("web3")); err != nil {
		t.Fatal(err)
	}
	withDisk := silo("db", "web3")
	withDisk.Spec.Volumes = []v1.Volume{{Name: "data", MountPath: "/data", Size: "1Gi"}}
	for _, o := range []meta.Object{
		withDisk, silo("rpc", "web3"),
		&v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "web3"},
			Spec: v1.ServiceSpec{Selector: map[string]string{"app": "rpc"}, Ports: []v1.ServicePortSpec{{Name: "rpc", Port: 8545}}}},
		secretObj("db-password", nil, "pw"),
		&v1.Role{TypeMeta: tm("Role"), ObjectMeta: meta.ObjectMeta{Name: "ops", Namespace: "web3"},
			Rules: []v1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"silos"}}}},
	} {
		if err := c.admin.Create(c.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	return c, st
}

// gone waits for namespace name to be deleted.
func gone(t *testing.T, c *cluster, name string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n v1.Namespace
		err := c.admin.Get(c.ctx, "Namespace", "", name, &n)
		if client.IsNotFound(err) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("namespace %s is still there: %v %v", name, n.Finalizers, n.Annotations)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Deleting a namespace with what is in it: silos first, then the service, the secret and the
// role last, then the namespace, each step after the one before is gone.
func TestNamespaceCascadeStopsSilosFirst(t *testing.T) {
	c, st := cascadeRig(t)
	p, err := c.admin.PlanNamespaceDelete(c.ctx, "web3")
	if err != nil {
		t.Fatal(err)
	}
	if p.Summary != "2 silos (1 with disks), 1 service, 1 secret, 1 role" {
		t.Fatalf("plan: %q", p.Summary)
	}
	if err := c.admin.DeleteNamespace(c.ctx, "web3", client.DeleteOptions{Cascade: true, Plan: p.ID}); err != nil {
		t.Fatal(err)
	}
	gone(t, c, "web3")
	var kinds []string
	last := -1
	for _, k := range st.log() {
		if _, api := v1.Lookup(k.Kind); !api || (k.Namespace != "web3" && k.Kind != "Namespace") {
			continue // the store's own records (a secret's sealed value) go with their object
		}
		kinds = append(kinds, k.Kind)
		if k.Kind == "Namespace" {
			continue
		}
		stage, _ := nsdelete.StageOf(k.Kind)
		if stage < last {
			t.Fatalf("%s deleted after a later step had begun: %v", k, kinds)
		}
		last = stage
	}
	want := []string{"Silo", "Silo", "Service", "Secret", "Role", "Namespace"}
	if strings.Join(kinds, " ") != strings.Join(want, " ") {
		t.Fatalf("deleted %v, want %v", kinds, want)
	}
}

// A step that fails leaves the namespace Terminating, saying what is left and why; nothing of a
// later step goes; a raw delete is refused and names where it stopped; the same delete again
// resumes it.
func TestNamespaceCascadeStopsOnAFailedStepAndResumes(t *testing.T) {
	c, st := cascadeRig(t)
	st.setFail(func(k store.Key) bool { return k.Kind == "Service" })
	if err := c.admin.DeleteNamespace(c.ctx, "web3", client.DeleteOptions{Cascade: true}); err != nil {
		t.Fatal(err)
	}
	var n v1.Namespace
	deadline := time.Now().Add(10 * time.Second)
	for n.Annotations[client.AnnotationCascadeFailed] == "" {
		if time.Now().After(deadline) {
			t.Fatalf("no failure recorded: %v", n.Annotations)
		}
		time.Sleep(20 * time.Millisecond)
		if err := c.admin.Get(c.ctx, "Namespace", "", "web3", &n); err != nil {
			t.Fatal(err)
		}
	}
	failed := n.Annotations[client.AnnotationCascadeFailed]
	if n.Status.Phase != "Terminating" || !strings.Contains(failed, "step 2/5, remove load balancers: service rpc:") ||
		!strings.Contains(failed, "Left: 1 service (rpc), 1 secret (db-password), 1 role (ops)") {
		t.Fatalf("phase %q, failure %q", n.Status.Phase, failed)
	}
	for _, k := range st.log() {
		if k.Kind == "Secret" || k.Kind == "Role" {
			t.Fatalf("%s went after the step before it failed", k)
		}
	}
	err := c.admin.Delete(c.ctx, "Namespace", "", "web3")
	if err == nil || !strings.Contains(err.Error(), "being deleted with what is in it (stopped: step 2/5") {
		t.Fatalf("raw delete while stopped: %v", err)
	}
	if err := c.admin.Create(c.ctx, silo("late", "web3")); err == nil {
		t.Fatal("a silo was made in a namespace being deleted")
	}

	st.setFail(nil)
	if err := c.admin.DeleteNamespace(c.ctx, "web3", client.DeleteOptions{Cascade: true}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	gone(t, c, "web3")
}

// The cascade deletes only what the caller may delete: anything else is named in the refusal,
// and nothing is deleted.
func TestNamespaceCascadeRBAC(t *testing.T) {
	c, st := cascadeRig(t)
	for _, o := range []meta.Object{
		&v1.ClusterRole{TypeMeta: tm("ClusterRole"), ObjectMeta: meta.ObjectMeta{Name: "ns-deleter"},
			Rules: []v1.PolicyRule{{Verbs: []string{"get", "delete"}, Resources: []string{"namespaces"}}}},
		clusterBind("ana-ns", "ns-deleter", v1.Subject{Kind: "User", Name: "ana"}),
		&v1.Role{TypeMeta: tm("Role"), ObjectMeta: meta.ObjectMeta{Name: "silo-deleter", Namespace: "web3"},
			Rules: []v1.PolicyRule{{Verbs: []string{"get", "list", "delete"}, Resources: []string{"silos", "services"}}}},
	} {
		if err := c.admin.Create(c.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	c.bind(t, "ana", "Role", "silo-deleter")
	ana := c.as(t, "ana")
	before := len(st.log())

	_, err := ana.PlanNamespaceDelete(c.ctx, "web3")
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Code != http.StatusForbidden ||
		!strings.HasPrefix(ce.Message, "user:ana may not delete 1 secret (db-password), 1 role binding (ana), 2 roles (ops, silo-deleter) in namespace web3 (no role lets ana delete") {
		t.Fatalf("plan as ana: %v", err)
	}
	if !strings.Contains(ce.Message, "nothing was deleted") {
		t.Fatalf("refusal: %s", ce.Message)
	}
	err = ana.DeleteNamespace(c.ctx, "web3", client.DeleteOptions{Cascade: true})
	if !errors.As(err, &ce) || ce.Code != http.StatusForbidden {
		t.Fatalf("cascade as ana: %v", err)
	}
	var n v1.Namespace
	if err := c.admin.Get(c.ctx, "Namespace", "", "web3", &n); err != nil || n.Status.Phase == "Terminating" || len(n.Finalizers) != 0 {
		t.Fatalf("after the refusal: %v phase %q finalizers %v", err, n.Status.Phase, n.Finalizers)
	}
	if len(st.log()) != before {
		t.Fatalf("deleted after a refusal: %v", st.log()[before:])
	}
	// Given the rest, she may.
	if err := c.admin.Create(c.ctx, &v1.Role{TypeMeta: tm("Role"), ObjectMeta: meta.ObjectMeta{Name: "rest", Namespace: "web3"},
		Rules: []v1.PolicyRule{{Verbs: []string{"delete"}, Resources: []string{"secrets", "roles", "rolebindings"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: tm("RoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "ana-rest", Namespace: "web3"},
		RoleRef: v1.RoleRef{Kind: "Role", Name: "rest"}, Subjects: []v1.Subject{{Kind: "User", Name: "ana"}}}); err != nil {
		t.Fatal(err)
	}
	if err := ana.DeleteNamespace(c.ctx, "web3", client.DeleteOptions{Cascade: true}); err != nil {
		t.Fatalf("cascade as ana, allowed: %v", err)
	}
	gone(t, c, "web3")
}
