package kvoadm

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func TestRepointWorkerUnit(t *testing.T) {
	unit := WorkerUnit(HostAddOptions{InitOptions: InitOptions{Name: "hv2"}, Runtimes: []string{"docker"}}, "https://203.0.113.10:6443")
	got, changed, err := RepointWorkerUnit(unit, "https://198.51.100.7:6443")
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	if !strings.Contains(got, "worker --name hv2 --server https://198.51.100.7:6443 --runtime docker") || strings.Contains(got, "203.0.113.10") {
		t.Fatalf("unit:\n%s", got)
	}
	if strings.Count(got, "\n") != strings.Count(unit, "\n") {
		t.Error("lines added or lost")
	}
	if _, changed, _ := RepointWorkerUnit(got, "https://198.51.100.7:6443"); changed {
		t.Error("already pointing there, but changed")
	}
	if unitFlag(got, "--name") != "hv2" || unitFlag(got, "--server") != "https://198.51.100.7:6443" {
		t.Error("unitFlag")
	}
	if _, _, err := RepointWorkerUnit(Unit(InitOptions{Name: "cp", Address: "10.0.0.1", Cluster: "c"}), "https://x:6443"); err == nil {
		t.Error("repointed a control-plane unit")
	}
	if _, _, err := RepointWorkerUnit("[Service]\nExecStart=/bin/true\n", "https://x:6443"); err == nil {
		t.Error("repointed something that isn't kevasod")
	}
}

func TestSSHTarget(t *testing.T) {
	h := &v1.Host{ObjectMeta: meta.ObjectMeta{Annotations: map[string]string{AnnotationSSH: "ubuntu@[2001:db8::5]:2222"}}}
	if u, a, p, ok := sshTarget(h); !ok || u != "ubuntu" || a != "2001:db8::5" || p != 2222 {
		t.Fatal(u, a, p, ok)
	}
	for _, v := range []string{"", "root@host", "@1.2.3.4:22", "root@1.2.3.4:x"} {
		if _, _, _, ok := sshTarget(&v1.Host{ObjectMeta: meta.ObjectMeta{Annotations: map[string]string{AnnotationSSH: v}}}); ok {
			t.Errorf("%q accepted", v)
		}
	}
}
