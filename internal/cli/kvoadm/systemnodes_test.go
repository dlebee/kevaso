package kvoadm_test

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvoadm"
)

var now = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

// sys is a system node as its Host shows it: member role, heartbeat age (<0: none).
func sys(name, member string, stateOnly bool, age time.Duration) v1.Host {
	h := v1.Host{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: v1.HostSpec{InternalIP: "10.0.0." + name[len(name)-1:],
		Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{StateOnly: stateOnly}}},
		Status: v1.HostStatus{ControlPlane: &v1.ControlPlaneStatus{Store: "etcd", PeerURL: "https://x:2380", Member: member}}}
	if age >= 0 {
		t := now.Add(-age)
		h.Status.LastHeartbeat = &t
	}
	return h
}

func TestJoinReady(t *testing.T) {
	ok := []v1.Host{sys("cp1", "voter", false, 0)}
	if err := kvoadm.JoinReady(ok); err != nil {
		t.Fatal(err)
	}
	sqlite := []v1.Host{sys("cp1", "", false, 0)}
	sqlite[0].Status.ControlPlane.Store, sqlite[0].Status.ControlPlane.PeerURL = "sqlite", ""
	if err := kvoadm.JoinReady(sqlite); err == nil || !strings.Contains(err.Error(), "kvoadm store migrate") {
		t.Fatalf("SQLite: %v", err)
	}
	nopeers := []v1.Host{sys("cp1", "voter", false, 0)}
	nopeers[0].Status.ControlPlane.PeerURL = ""
	if err := kvoadm.JoinReady(nopeers); err == nil || !strings.Contains(err.Error(), "peer") {
		t.Fatalf("no peers: %v", err)
	}
	joining := []v1.Host{sys("cp1", "voter", false, 0), sys("cp2", "learner", false, -1)}
	if err := kvoadm.JoinReady(joining); err == nil || !strings.Contains(err.Error(), "one system node joins at a time") {
		t.Fatalf("mid-join: %v", err)
	}
}

func TestRemovalCheck(t *testing.T) {
	fresh, stale := 2*time.Second, 5*time.Minute
	worker := v1.Host{ObjectMeta: meta.ObjectMeta{Name: "w1"}, Spec: v1.HostSpec{Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
	cases := []struct {
		name   string
		hosts  []v1.Host
		remove string
		want   string // "" = allowed
	}{
		{"three healthy: one may go", []v1.Host{sys("cp1", "voter", false, fresh), sys("cp2", "voter", false, fresh), sys("cp3", "voter", false, fresh)}, "cp2", ""},
		{"three, one down: removing a healthy one leaves 1 of 2", []v1.Host{sys("cp1", "voter", false, fresh), sys("cp2", "voter", false, fresh), sys("cp3", "voter", false, stale)}, "cp2", "majority"},
		{"three, one down: the down one may go", []v1.Host{sys("cp1", "voter", false, fresh), sys("cp2", "voter", false, fresh), sys("cp3", "voter", false, stale)}, "cp3", ""},
		{"the last full node, a light node left", []v1.Host{sys("cp1", "voter", false, fresh), sys("vps", "voter", true, fresh)}, "cp1", "last system node serving the API"},
		{"the light node of three", []v1.Host{sys("cp1", "voter", false, fresh), sys("cp2", "voter", false, fresh), sys("vps", "voter", true, fresh)}, "vps", ""},
		{"two voters, one down: no majority to change anything", []v1.Host{sys("cp1", "voter", false, fresh), sys("cp2", "voter", false, stale)}, "cp2", "majority"},
		{"a learner mid-join goes first", []v1.Host{sys("cp1", "voter", false, fresh), sys("cp2", "voter", false, fresh), sys("cp3", "voter", false, fresh), sys("cp4", "learner", false, -1)}, "cp2", "comes first"},
		{"not a system node", []v1.Host{sys("cp1", "voter", false, fresh), worker}, "w1", "isn't a system node"},
		{"declared, never joined", []v1.Host{sys("cp1", "voter", false, fresh), sys("cp2", "", false, -1)}, "cp2", ""},
	}
	for _, c := range cases {
		err := kvoadm.RemovalCheck(c.hosts, c.remove, now, 40*time.Second)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

func TestSystemNodeUnit(t *testing.T) {
	o := kvoadm.HostAddOptions{InitOptions: kvoadm.InitOptions{Name: "hv2", Cluster: "home", ExternalIP: "198.51.100.7"}}
	u := kvoadm.SystemNodeUnit(o, []string{"https://203.0.113.10:6443"}, false, false)
	for _, want := range []string{"control-plane --name hv2 --external-ip 198.51.100.7", "--store etcd --etcd-peer-listen 198.51.100.7:2380", "--join https://203.0.113.10:6443"} {
		if !strings.Contains(u, want) {
			t.Fatalf("unit lacks %q:\n%s", want, u)
		}
	}
	if strings.Contains(u, "--state-only") || strings.Contains(u, "--worker") {
		t.Fatal(u)
	}
	light := kvoadm.SystemNodeUnit(o, []string{"https://a:6443", "https://b:6443"}, true, true)
	if !strings.Contains(light, "--state-only") || strings.Contains(light, "--worker") || !strings.Contains(light, "--join https://a:6443,https://b:6443") {
		t.Fatal(light)
	}
	both := kvoadm.SystemNodeUnit(o, []string{"https://a:6443"}, false, true)
	if !strings.Contains(both, "--worker --runtime cloud-hypervisor") {
		t.Fatal(both)
	}
}

func TestWithEtcd(t *testing.T) {
	unit := "[Service]\nExecStart=/usr/local/bin/kevasod control-plane --name hv1 --address 203.0.113.10 --store sqlite --worker\nRestart=always\n"
	got, changed, err := kvoadm.WithEtcd(unit, "203.0.113.10:2380")
	if err != nil || !changed {
		t.Fatal(err)
	}
	if !strings.Contains(got, "--name hv1 --address 203.0.113.10 --worker --store etcd --etcd-peer-listen 203.0.113.10:2380\n") || strings.Contains(got, "sqlite") {
		t.Fatal(got)
	}
	again, changed, err := kvoadm.WithEtcd(got, "203.0.113.10:2380")
	if err != nil || changed || again != got {
		t.Fatalf("not idempotent: %v %v\n%s", changed, err, again)
	}
	if _, _, err := kvoadm.WithEtcd("ExecStart=/usr/local/bin/kevasod worker --name w", "x:2380"); err == nil {
		t.Fatal("rewrote a worker unit")
	}
}

func TestBinaryVersionAndNodes(t *testing.T) {
	if v := kvoadm.BinaryVersion("-s -w -X kevaso.com/core/internal/version.Version=v0.5.0"); v != "v0.5.0" {
		t.Fatal(v)
	}
	if v := kvoadm.BinaryVersion("-s -w"); v != "" {
		t.Fatal(v)
	}
	h := sys("cp1", "voter", true, 0)
	h.Status.Version = "v0.4.0"
	h.Status.ControlPlane.Leader = true
	n := kvoadm.UpgradeNodes([]v1.Host{h})[0]
	if !n.System || !n.StateOnly || !n.Leader || n.Version != "v0.4.0" || n.Worker {
		t.Fatalf("%+v", n)
	}
}
