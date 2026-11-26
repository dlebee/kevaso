package apiserver

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func TestMacSiloProblems(t *testing.T) {
	ok := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "ios", Namespace: "dev"}, Spec: v1.SiloSpec{Runtime: "tart", Container: &v1.ContainerSource{Image: "ghcr.io/cirruslabs/macos-tahoe-base:latest"}}}
	if p := macSiloProblems(ok); len(p) != 0 {
		t.Fatalf("a plain macOS silo: %v", p)
	}
	bad := *ok
	bad.Spec.Grants = []string{"github"}
	bad.Spec.Services = []v1.SiloService{{}}
	p := strings.Join(macSiloProblems(&bad), "|")
	if !strings.Contains(p, "grants") || !strings.Contains(p, "cluster address") {
		t.Fatalf("%q", p)
	}
}
