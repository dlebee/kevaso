package container

import (
	"context"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// Both engines keep their silos' state in the same Dir: each runtime must only ever take its own.
// Found on the metal machine: deleting a podman silo went through the docker runtime (which
// listed it too), removed its state and left podman's containers running.
func TestEachEngineOnlySeesItsOwnSilos(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	docker := runtime(t, f)
	podman := runtime(t, f)
	podman.Engine = "podman"
	if err := podman.Create(ctx, kri.Spec{ID: silo, Image: "ghcr.io/x/app:1"}); err != nil {
		t.Fatal(err)
	}
	if ids, _ := docker.List(ctx); len(ids) != 0 {
		t.Fatalf("docker lists podman's silo: %v", ids)
	}
	if ids, _ := podman.List(ctx); !slices.Equal(ids, []kri.ID{silo}) {
		t.Fatalf("podman's list: %v", ids)
	}
	if st, _ := docker.Status(ctx, silo); st.State != kri.Absent {
		t.Fatalf("docker sees podman's silo: %+v", st)
	}
	before := len(f.cmds)
	if err := docker.Delete(ctx, silo); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.cmds[before:] {
		if strings.HasPrefix(c, "docker rm") || strings.HasPrefix(c, "podman rm") {
			t.Errorf("docker's Delete touched podman's silo: %s", c)
		}
	}
	if _, ok := podman.load(silo); !ok {
		t.Fatal("docker's Delete removed podman's state")
	}
	if err := podman.Delete(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(f.cmds[before:], func(c string) bool { return strings.HasPrefix(c, "podman rm -f kv-") }) {
		t.Errorf("podman's Delete didn't remove its containers: %v", f.cmds[before:])
	}
}

func TestAStateWithoutAnEngineIsDockers(t *testing.T) {
	f := newFake()
	docker, podman := runtime(t, f), runtime(t, f)
	podman.Engine = "podman"
	f.files[statePath(silo)] = []byte(`{"id": {"namespace": "shop", "name": "api", "uid": "u1"}, "ip": "10.64.0.3"}`)
	if _, ok := docker.load(silo); !ok {
		t.Error("docker doesn't take a state with no engine")
	}
	if _, ok := podman.load(silo); ok {
		t.Error("podman takes a state with no engine")
	}
}
