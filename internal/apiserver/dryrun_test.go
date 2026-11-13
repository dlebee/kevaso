package apiserver_test

import (
	"testing"

	"kevaso.com/core/api/client"
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
