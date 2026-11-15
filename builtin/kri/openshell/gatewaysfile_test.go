package openshell

import (
	"context"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// K-105's shape in the gateways' ports: with the gateways file unreadable, a new gateway could be
// given a port one of them listens on, and the file written over would forget them all. Nothing
// is readied until it is readable, and the file is left as it is.
func TestAnUnreadableGatewaysFileGivesOutNoPort(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, ScopeSilo)
	started(t, r, siloA)
	broken := []byte(`{"dev/a": {"port": `)
	f.files[gatewaysFile] = broken
	err := r.Create(ctx, kri.Spec{ID: siloB, Image: "ubuntu-24.04"})
	if err == nil || !strings.Contains(err.Error(), gatewaysFile) {
		t.Fatalf("Create with %s unreadable: %v, want a refusal naming it", gatewaysFile, err)
	}
	if string(f.files[gatewaysFile]) != string(broken) {
		t.Fatalf("the gateways file was written over: %s", f.files[gatewaysFile])
	}
}
