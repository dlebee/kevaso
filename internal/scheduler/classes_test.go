package scheduler

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

func provider(name, region string) hostOpt {
	return func(h *v1.Host) { h.Status.Provider = &v1.HostProvider{Name: name, ID: "1", Region: region} }
}

// lb declares ports and opens each on a load balancer of class.
func lb(class string, ports ...v1.SiloPort) siloOpt {
	return func(s *v1.Silo) {
		s.Spec.Ports = ports
		s.Spec.Service = &v1.SiloService{LoadBalancer: &v1.LoadBalancerSpec{Class: class}}
		for _, p := range ports {
			s.Spec.Service.Ports = append(s.Spec.Service.Ports, v1.ServicePort{Port: p.Name, LoadBalancer: true})
		}
	}
}

func volume(class string) siloOpt {
	return func(s *v1.Silo) {
		s.Spec.Volumes = append(s.Spec.Volumes, v1.Volume{Name: "data", Class: class, Size: "10Gi", MountPath: "/data"})
	}
}

var linodeClasses = map[string]Class{
	"linode-nodebalancer": {Plugin: "linode", OwnHostsOnly: true, NodePorts: true},
	"linode-block":        {Plugin: "linode", OwnHostsOnly: true},
	"juicefs":             {Plugin: "juicefs", Topology: "global", Mount: true},
}

func mounts(classes ...string) hostOpt {
	return func(h *v1.Host) { h.Status.MountClasses = classes }
}

func TestPluginClasses(t *testing.T) {
	// The silo holds the namespace's shared IP for its class: it must be on it before it's placed.
	env := Env{Classes: linodeClasses, IPs: []*v1.IP{ipObj(v1.DefaultIPName("linode-nodebalancer"), "linode-nodebalancer", func(x *v1.IP) { x.Status.BoundTo = []v1.IPHolder{{Holder: "silo/a", UID: "uid-a"}} })}}
	for _, tc := range []struct {
		name  string
		silo  *v1.Silo
		hosts []*v1.Host
		want  string
		why   string // in the decision's message, when nothing fits
	}{
		{"a volume goes to the plugin's machine", silo("a", volume("linode-block")),
			hosts(host("home", mem("64Gi")), host("tor", provider("linode", "ca-central"))), "tor", ""},
		{"a load balancer too", silo("a", lb("linode-nodebalancer", v1.SiloPort{Name: "web", Port: 80}), func(s *v1.Silo) { s.UID = "uid-a" }),
			hosts(host("home", mem("64Gi")), host("tor", provider("linode", "ca-central"))), "tor", ""},
		{"another provider's machine won't do", silo("a", volume("linode-block")),
			hosts(host("fra", provider("hetzner", "fsn1"))), "", "fra: class linode-block needs a linode machine"},
		{"a class no plugin serves", silo("a", volume("ebs")),
			hosts(host("tor", provider("linode", "ca-central"))), "", "class ebs: no plugin serves it"},
		{"an existing volume keeps the silo in its region", silo("a", volume("linode-block"), func(s *v1.Silo) {
			s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: "linode-block", Handle: "9", Region: "us-ord"}}
		}), hosts(host("tor", provider("linode", "ca-central")), host("chi", provider("linode", "us-ord"))), "chi", ""},
		{"local volumes need nothing", silo("a", volume("local")), hosts(host("home")), "home", ""},
		{"a mount class needs its node side on the host, any provider or none", silo("a", volume("juicefs")),
			hosts(host("tor", provider("linode", "ca-central"), mem("64Gi")), host("home", mounts("juicefs"))), "home", ""},
		{"no node side anywhere: nothing fits, saying why", silo("a", volume("juicefs")),
			hosts(host("home", mounts("other"))), "", "home: class juicefs needs the juicefs plugin's node side on the host"},
		{"a global volume holds no region", silo("a", volume("juicefs"), func(s *v1.Silo) {
			s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: "juicefs", Handle: "volumes/u/data"}}
		}), hosts(host("fra", provider("hetzner", "fsn1"), mounts("juicefs"))), "fra", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ScheduleIn(tc.silo, tc.hosts, nil, env)
			if err != nil {
				t.Fatal(err)
			}
			if d.Host != tc.want {
				t.Fatalf("got %q, want %q (%s)", d.Host, tc.want, d.Message())
			}
			if tc.why != "" && !strings.Contains(d.Message(), tc.why) {
				t.Fatalf("message %q lacks %q", d.Message(), tc.why)
			}
		})
	}
}

func TestNodePorts(t *testing.T) {
	ports := []v1.SiloPort{{Name: "web", Port: 80}, {Name: "rpc", Port: 8545}}
	a := silo("a", lb("linode-nodebalancer", ports...), on("tor"))
	got, err := NodePorts(a, "tor", nil)
	if err != nil || len(got) != 2 || got[0].NodePort != 30000 || got[1].NodePort != 30001 || got[1].Port != 8545 {
		t.Fatalf("first silo: %+v %v", got, err)
	}
	a.Status.Service.NodePorts = got
	// Another silo on the same host gets the next ones; on another host, the same ones.
	b := silo("b", lb("linode-nodebalancer", ports[0]))
	if got, _ := NodePorts(b, "tor", placed(a)); got[0].NodePort != 30002 {
		t.Fatalf("second silo on tor: %+v", got)
	}
	if got, _ := NodePorts(b, "chi", placed(a)); got[0].NodePort != 30000 {
		t.Fatalf("on chi: %+v", got)
	}
	// A silo keeps its own, even when lower ones are free now.
	a.Status.Service.NodePorts = []v1.NodePort{{Name: "web", Port: 80, NodePort: 30010}, {Name: "rpc", Port: 8545, NodePort: 30011}}
	if got, _ := NodePorts(a, "tor", nil); got[0].NodePort != 30010 || got[1].NodePort != 30011 {
		t.Fatalf("kept: %+v", got)
	}
	// …and they're through ServiceStatus, with the plugin's address kept.
	a.Status.Service.LoadBalancerIP = "198.51.100.40"
	a.UID = "uid-a"
	held := ipObj(v1.DefaultIPName("linode-nodebalancer"), "linode-nodebalancer", func(x *v1.IP) { x.Status.BoundTo = []v1.IPHolder{{Holder: "silo/a", UID: "uid-a"}} })
	st, err := ServiceStatus(a, host("tor", provider("linode", "ca-central")), nil, Env{Classes: linodeClasses, IPs: []*v1.IP{held}})
	if err != nil || st.LoadBalancerIP != "198.51.100.40" || len(st.NodePorts) != 2 || st.NodePorts[0].NodePort != 30010 {
		t.Fatalf("service status: %+v %v", st, err)
	}
}
