package v1

import (
	"testing"

	"kevaso.com/core/api/meta"
)

func TestReservedHostPorts(t *testing.T) {
	for _, n := range []int{22, 53, 2379, 2380, 6443, 51820, 51821, 15001} {
		if ReservedHostPort(n) == "" {
			t.Errorf("port %d is not reserved", n)
		}
	}
	for _, n := range []int{80, 443, 8080, 2222, 51822} {
		if why := ReservedHostPort(n); why != "" {
			t.Errorf("port %d is reserved (%s); 80 and 443 stay available, and a host's own listener is extra", n, why)
		}
	}
}

func TestExtraReservedPorts(t *testing.T) {
	h := &Host{
		ObjectMeta: meta.ObjectMeta{Name: "hv", Annotations: map[string]string{AnnotationSSH: "root@10.0.0.5:2222"}},
		Spec:       HostSpec{Network: HostNetwork{ListenPort: 51822}},
	}
	h.Status.ControlPlane = &ControlPlaneStatus{APIURL: "https://10.0.0.1:8443", PeerURL: "https://10.0.0.1:2381"}
	got := h.ExtraReservedPorts()
	want := map[int]string{51822: "the mesh", 2222: "the SSH port", 8443: "the API", 2381: "etcd"}
	for n, why := range want {
		if got[n] != why {
			t.Errorf("port %d: got %q, want %q (all %+v)", n, got[n], why, got)
		}
	}
	h.Annotations[AnnotationSSH] = "root@[2001:db8::1]:2222"
	if SSHPort(h) != 2222 {
		t.Fatalf("SSH port %d", SSHPort(h))
	}
	h.Spec.Network.ListenPort = 51820
	h.Annotations[AnnotationSSH] = "root@10.0.0.5:22"
	h.Status.ControlPlane.APIURL = "https://10.0.0.1:6443"
	h.Status.ControlPlane.PeerURL = "https://10.0.0.1:2380"
	if extra := h.ExtraReservedPorts(); len(extra) != 0 {
		t.Fatalf("numbers the fixed set already names: %+v", extra)
	}
}
