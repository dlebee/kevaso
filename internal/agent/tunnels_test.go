package agent_test

import (
	"reflect"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
)

func TestTunnelTargets(t *testing.T) {
	cp := func(name, url string, stateOnly bool) v1.Host {
		h := v1.Host{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: v1.HostSpec{Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{StateOnly: stateOnly}}}}
		if url != "" {
			h.Status.ControlPlane = &v1.ControlPlaneStatus{APIURL: url}
		}
		return h
	}
	hosts := []v1.Host{
		cp("cp-2", "https://10.0.0.2:6443", false),
		cp("cp-1", "https://10.0.0.1:6443", false),
		cp("vps", "", true),   // light node: no API
		cp("cp-3", "", false), // not reporting yet
		{ObjectMeta: meta.ObjectMeta{Name: "w1"}, Spec: v1.HostSpec{Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}},
			Status: v1.HostStatus{ControlPlane: &v1.ControlPlaneStatus{APIURL: "https://stale:6443"}}}, // no longer a system node
	}
	got := agent.TunnelTargets(hosts)
	if want := []string{"https://10.0.0.1:6443", "https://10.0.0.2:6443"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("%v, want %v", got, want)
	}
}
