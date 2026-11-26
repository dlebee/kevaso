package kvo

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	nscontroller "kevaso.com/core/internal/controllers/namespace"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/store"
)

// nsRig is an API server, kevasod's namespace controller on it, and namespace dev holding three
// silos (two with disks) and a role.
func nsRig(t *testing.T) (context.Context, *client.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	t.Setenv("KVO_SERVER", ts.URL)
	c := client.New(ts.URL)
	namespaces := informer.New(c, "Namespace")
	e := engine.New(clock.Real{})
	e.Register(&nscontroller.Controller{Client: c, Clock: clock.Real{}, Wait: 20 * time.Millisecond}, engine.Options{})
	namespaces.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Namespace", Name: k.Name}) })
	run, stop := context.WithCancel(ctx)
	done := make(chan struct{}, 2)
	go func() { namespaces.Run(run); done <- struct{}{} }()
	go func() { e.Run(run); done <- struct{}{} }()
	t.Cleanup(func() { stop(); <-done; <-done })
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"db", "cache", "web"} {
		s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}
		if i < 2 {
			s.Spec.Volumes = []v1.Volume{{Name: "data", MountPath: "/data"}}
		}
		if err := c.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Create(ctx, &v1.Role{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Role"}, ObjectMeta: meta.ObjectMeta{Name: "ops", Namespace: "dev"},
		Rules: []v1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"silos"}}}}); err != nil {
		t.Fatal(err)
	}
	return ctx, c
}

func onTerminal(t *testing.T, yes bool) {
	t.Helper()
	prev := askTerminal
	askTerminal = func(io.Reader) bool { return yes }
	t.Cleanup(func() { askTerminal = prev })
	prevEvery := followEvery
	followEvery = 10 * time.Millisecond
	t.Cleanup(func() { followEvery = prevEvery })
}

func silosIn(t *testing.T, ctx context.Context, c *client.Client, ns string) int {
	t.Helper()
	l, err := c.List(ctx, "Silo", ns)
	if err != nil {
		t.Fatal(err)
	}
	return len(l.Items)
}

const devHolds = "namespace dev still holds resources: 3 silos (2 with disks), 1 role."

func TestDeleteNamespaceAsksOnceThenCascades(t *testing.T) {
	ctx, c := nsRig(t)
	onTerminal(t, true)

	// No: nothing deleted, the namespace is as it was.
	var out, errb bytes.Buffer
	if code := Run(ctx, []string{"delete", "namespace", "dev"}, strings.NewReader("n\n"), &out, &errb); code == 0 {
		t.Fatalf("a no deleted: %s", out.String())
	}
	want := devHolds + "\nDeleting the namespace deletes all of them first (stop silos, remove load balancers, release IPs, delete the rest, delete secrets and access). Are you sure? [y/N] "
	if out.String() != want {
		t.Fatalf("the question:\n%q\nwant\n%q", out.String(), want)
	}
	var n v1.Namespace
	if err := c.Get(ctx, "Namespace", "", "dev", &n); err != nil || n.Status.Phase == "Terminating" || silosIn(t, ctx, c, "dev") != 3 {
		t.Fatalf("after a no: %v phase %q, %d silos", err, n.Status.Phase, silosIn(t, ctx, c, "dev"))
	}

	// Yes: everything, then the namespace.
	out.Reset()
	errb.Reset()
	if code := Run(ctx, []string{"delete", "namespace", "dev"}, strings.NewReader("y\n"), &out, &errb); code != 0 {
		t.Fatalf("yes: code %d\n%s\n%s", code, out.String(), errb.String())
	}
	if !strings.HasSuffix(out.String(), "namespace/dev deleted\n") {
		t.Fatalf("output:\n%s", out.String())
	}
	if err := c.Get(ctx, "Namespace", "", "dev", &n); !client.IsNotFound(err) {
		t.Fatalf("namespace after the cascade: %v", err)
	}
	if silosIn(t, ctx, c, "dev") != 0 {
		t.Fatal("silos left")
	}
}

func TestDeleteNamespaceWithoutATerminalNeedsYes(t *testing.T) {
	ctx, c := nsRig(t)
	onTerminal(t, false)
	var out, errb bytes.Buffer
	if code := Run(ctx, []string{"delete", "namespace", "dev"}, strings.NewReader("y\n"), &out, &errb); code == 0 {
		t.Fatal("deleted without a terminal or --yes")
	}
	if !strings.Contains(errb.String(), devHolds) || !strings.Contains(errb.String(), "run again with --yes") {
		t.Fatalf("refusal: %s", errb.String())
	}
	if silosIn(t, ctx, c, "dev") != 3 {
		t.Fatal("something was deleted")
	}
	out.Reset()
	errb.Reset()
	if code := Run(ctx, []string{"delete", "namespace", "dev", "--yes"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("--yes: code %d\n%s", code, errb.String())
	}
	if strings.Contains(out.String(), "Are you sure") || !strings.HasSuffix(out.String(), "namespace/dev deleted\n") {
		t.Fatalf("--yes output:\n%s", out.String())
	}
}

// A raw API delete without the cascade keeps today's refusal, and leaves the namespace Active.
func TestRawNamespaceDeleteIsStillRefused(t *testing.T) {
	ctx, c := nsRig(t)
	err := c.Delete(ctx, "Namespace", "", "dev")
	if err == nil || !strings.Contains(err.Error(), "namespace dev still holds 1 Role (ops), 3 Silo (cache, db, web)") || !strings.Contains(err.Error(), "?cascade=true") {
		t.Fatalf("raw delete: %v", err)
	}
	var n v1.Namespace
	if err := c.Get(ctx, "Namespace", "", "dev", &n); err != nil || n.Status.Phase == "Terminating" {
		t.Fatalf("after the refusal: %v %q", err, n.Status.Phase)
	}
	// A dry-run cascade plans and deletes nothing.
	p, err := c.PlanNamespaceDelete(ctx, "dev")
	if err != nil || p.Summary != "3 silos (2 with disks), 1 role" || len(p.Items) != 4 || p.Items[0].Kind != "Silo" {
		t.Fatalf("plan %+v %v", p, err)
	}
	if silosIn(t, ctx, c, "dev") != 3 {
		t.Fatal("the plan deleted something")
	}
	// The plan is for what was there: one more silo since, and the delete is refused.
	if err := c.Create(ctx, &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "late", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteNamespace(ctx, "dev", client.DeleteOptions{Cascade: true, Plan: p.ID}); err == nil || !strings.Contains(err.Error(), "holds something else now (4 silos (2 with disks), 1 role)") {
		t.Fatalf("stale plan: %v", err)
	}
	if err := c.Get(ctx, "Namespace", "", "dev", &n); err != nil || n.Status.Phase == "Terminating" || silosIn(t, ctx, c, "dev") != 4 {
		t.Fatalf("after a stale plan: %v %q", err, n.Status.Phase)
	}
}

func TestDeleteAllKeepsTheNamespace(t *testing.T) {
	ctx, c := nsRig(t)
	onTerminal(t, false)
	var out, errb bytes.Buffer
	if code := Run(ctx, []string{"delete", "all", "-n", "dev"}, strings.NewReader(""), &out, &errb); code == 0 ||
		!strings.Contains(errb.String(), "namespace dev holds resources: 3 silos (2 with disks), 1 role.") || !strings.Contains(errb.String(), "--yes") {
		t.Fatalf("without a terminal: code %d %s", code, errb.String())
	}
	onTerminal(t, true)
	out.Reset()
	errb.Reset()
	if code := Run(ctx, []string{"delete", "all", "-n", "dev"}, strings.NewReader("y\n"), &out, &errb); code != 0 {
		t.Fatalf("delete all: code %d\n%s\n%s", code, out.String(), errb.String())
	}
	if !strings.HasPrefix(out.String(), "namespace dev holds resources: 3 silos (2 with disks), 1 role.\nThis deletes all of them (stop silos, remove load balancers, release IPs, delete the rest, delete secrets and access); the namespace stays. Are you sure? [y/N] ") ||
		!strings.HasSuffix(out.String(), "deleted everything in namespace dev\n") {
		t.Fatalf("output:\n%s", out.String())
	}
	var n v1.Namespace
	if err := c.Get(ctx, "Namespace", "", "dev", &n); err != nil || n.Status.Phase == "Terminating" {
		t.Fatalf("the namespace: %v %q", err, n.Status.Phase)
	}
	l, err := c.List(ctx, "Role", "dev")
	if err != nil || len(l.Items) != 0 || silosIn(t, ctx, c, "dev") != 0 {
		t.Fatalf("left: %v %d roles", err, len(l.Items))
	}
	out.Reset()
	if code := Run(ctx, []string{"delete", "all", "-n", "dev"}, strings.NewReader(""), &out, &errb); code != 0 || out.String() != "namespace dev holds nothing\n" {
		t.Fatalf("again: %d %q", code, out.String())
	}
}
