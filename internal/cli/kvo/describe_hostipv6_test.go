package kvo

import (
	"bytes"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// A host's worker finds its IPv6 address. A host with no worker (a control plane only) never
// looked, so describe says that, not "no global IPv6 address": it may well have one.
func TestDescribeHostIPv6WithNoWorker(t *testing.T) {
	cases := []struct {
		name string
		h    *v1.Host
		want string
	}{
		{"control plane only", &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "cp1"},
			Spec: v1.HostSpec{ExternalIP: "203.0.113.10", Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{}}}},
			"not detected: this host runs no worker"},
		{"a worker that found none", &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "w1"},
			Spec: v1.HostSpec{ExternalIP: "203.0.113.11", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}},
			"none: IPv4 only (no global IPv6 address"},
		{"a control plane with spec.externalIPv6", &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "cp2"},
			Spec: v1.HostSpec{ExternalIP: "203.0.113.12", ExternalIPv6: "2001:db8::12", Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{}}}},
			"2001:db8::12"},
	}
	for _, c := range cases {
		var b bytes.Buffer
		if err := describeObject(&b, c.h); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		line := ""
		for _, l := range strings.Split(b.String(), "\n") {
			if strings.HasPrefix(l, "External IPv6:") {
				line = l
			}
		}
		if !strings.Contains(line, c.want) {
			t.Errorf("%s: External IPv6 line %q, want %q in it", c.name, line, c.want)
		}
	}
}
