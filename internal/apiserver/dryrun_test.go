package apiserver_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// A dry run checks and answers as a write does, and stores nothing.
func TestDryRunUpdateStoresNothing(t *testing.T) {
	c, ctx := setup(t)
	s := newSilo("web")
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	rv := s.ResourceVersion
	trial := *s
	trial.Spec.Resources.CPU = 8
	if err := c.DryRunUpdate(ctx, &trial); err != nil {
		t.Fatal(err)
	}
	if trial.Spec.Resources.CPU != 8 || trial.Generation != 2 {
		t.Errorf("dry run answer: cpu %d, generation %d", trial.Spec.Resources.CPU, trial.Generation)
	}
	var got v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "web", &got); err != nil {
		t.Fatal(err)
	}
	if got.ResourceVersion != rv || got.Spec.Resources.CPU != 2 {
		t.Errorf("stored after a dry run: rv %s→%s, cpu %d", rv, got.ResourceVersion, got.Spec.Resources.CPU)
	}
	bad := got
	bad.Spec.Runtime = "nope"
	if err := c.DryRunUpdate(ctx, &bad); !client.IsInvalid(err) {
		t.Errorf("an invalid dry run: %v", err)
	}
	stale := got
	stale.ResourceVersion = "1"
	if err := c.DryRunUpdate(ctx, &stale); code(err) != 409 {
		t.Errorf("a stale dry run: %v", err)
	}
}

// A dry-run delete is checked like a delete and stores nothing: the object stays, a finalizer
// is not marked, and a namespace that still holds something is not left Terminating.
func TestDryRunDeleteChangesNothing(t *testing.T) {
	c, ctx := setup(t)
	s := newSilo("web")
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	rv := s.ResourceVersion
	if code, err := dryDelete(ctx, c, "Silo", "dev", "web"); err != nil || code != http.StatusOK {
		t.Fatalf("dry-run delete: %d %v", code, err)
	}
	var got v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "web", &got); err != nil {
		t.Fatalf("object after a dry-run delete: %v", err)
	}
	if got.ResourceVersion != rv || got.DeletionTimestamp != nil {
		t.Fatalf("stored after a dry-run delete: rv %s→%s, deletionTimestamp %v", rv, got.ResourceVersion, got.DeletionTimestamp)
	}

	held := newSilo("held")
	held.Finalizers = []string{"kevaso.com/disk"}
	if err := c.Create(ctx, held); err != nil {
		t.Fatal(err)
	}
	if code, err := dryDelete(ctx, c, "Silo", "dev", "held"); err != nil || code != http.StatusAccepted {
		t.Fatalf("dry-run delete of an object with a finalizer: %d %v", code, err)
	}
	if err := c.Get(ctx, "Silo", "dev", "held", &got); err != nil || got.DeletionTimestamp != nil {
		t.Fatalf("finalizer marked on a dry run: %v, deletionTimestamp %v", err, got.DeletionTimestamp)
	}

	var ns v1.Namespace
	if err := c.Get(ctx, "Namespace", "", "dev", &ns); err != nil {
		t.Fatal(err)
	}
	nsRV := ns.ResourceVersion
	if code, err := dryDelete(ctx, c, "Namespace", "", "dev"); code != http.StatusConflict {
		t.Fatalf("dry-run delete of a namespace that holds silos: %d %v", code, err)
	}
	if err := c.Get(ctx, "Namespace", "", "dev", &ns); err != nil {
		t.Fatal(err)
	}
	if ns.ResourceVersion != nsRV || ns.Status.Phase == "Terminating" {
		t.Fatalf("namespace after a dry-run delete: rv %s→%s, phase %q", nsRV, ns.ResourceVersion, ns.Status.Phase)
	}

	empty := &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "empty"}}
	if err := c.Create(ctx, empty); err != nil {
		t.Fatal(err)
	}
	if code, err := dryDelete(ctx, c, "Namespace", "", "empty"); err != nil || code != http.StatusOK {
		t.Fatalf("dry-run delete of an empty namespace: %d %v", code, err)
	}
	if err := c.Get(ctx, "Namespace", "", "empty", &ns); err != nil {
		t.Fatalf("empty namespace after a dry-run delete: %v", err)
	}
}

func dryDelete(ctx context.Context, c *client.Client, kind, namespace, name string) (int, error) {
	p, err := client.Path(kind, namespace, name)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+p+"?dryRun=All", nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		e := &client.Error{Code: resp.StatusCode}
		_ = json.Unmarshal(b, e)
		return resp.StatusCode, e
	}
	return resp.StatusCode, nil
}
