package kvo

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Golden files for what people read and scripts parse: kvo get (and -o wide) and kvo describe, for
// every kind, from the repo's example manifests plus objects with a lived-in status. A change in
// what kvo prints shows up as a diff in testdata/golden; when it's meant, regenerate:
//
//	go test ./internal/cli/kvo -run TestGolden -args -update
var update = flag.Bool("update", false, "rewrite the golden files")

// ages are relative times ("3m ago", SINCE 3m): kept to their shape, since they move with the clock.
// Absolute times are local and move too. Ages stay the same width (the fixtures are minutes
// old), so the columns still line up as they would.
var (
	ages  = regexp.MustCompile(`\b\d+[smhd]\b( ago)?`)
	times = regexp.MustCompile(`\d{4}-\d\d-\d\d \d\d:\d\d:\d\d`)
)

func golden(t *testing.T, name, got string) {
	t.Helper()
	got = ages.ReplaceAllString(times.ReplaceAllString(got, "YYYY-MM-DD hh:mm:ss"), "<age>$1")
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != got {
		t.Errorf("%s changed (run with -update if that's meant):\n--- want\n%s\n--- got\n%s", name, want, got)
	}
}

// exampleObjects are the objects in examples/*.yaml, by kind.
func exampleObjects(t *testing.T) map[string][]meta.Object {
	t.Helper()
	files, _ := filepath.Glob("../../../examples/*.yaml")
	more, _ := filepath.Glob("../../../examples/*/*.yaml")
	out := map[string][]meta.Object{}
	for _, f := range append(files, more...) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		docs, err := readDocs(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, d := range docs {
			obj, k, err := v1.DecodeStrict(d)
			if err != nil {
				continue // a PluginPackage, or a defined kind's instance
			}
			if _, ok := obj.(*v1.Unstructured); ok {
				continue
			}
			out[k.Kind] = append(out[k.Kind], obj)
		}
	}
	return out
}

func livedIn() map[string][]meta.Object {
	created := time.Now().Add(-3 * time.Minute)
	h := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "hv1", CreationTimestamp: &created},
		Spec: v1.HostSpec{InternalIP: "10.0.0.5", ExternalIP: "203.0.113.10", Region: "ca-central",
			Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{},
				Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "cloud-hypervisor"}, {Name: "docker"}}, Taints: []v1.Taint{{Key: "gpu", Value: "yes", Effect: v1.NoSchedule}}}}},
		Status: v1.HostStatus{Allocatable: v1.Resources{CPU: 3, Memory: "4886Mi"}, LastHeartbeat: &created,
			Conditions: []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp", LastTransitionTime: created}},
			Runtimes:   map[string]v1.RuntimeStatus{"cloud-hypervisor": {State: "Ready", Version: "v54.1"}, "docker": {State: "Installing", Message: "3/5 engine"}}}}
	h.Status.Network.MeshIP = "10.63.0.2"
	h.Spec.ExternalIPv6 = "2001:db8:10::5" // the IPv6 effort: both families at the edge
	h.Status.Network.SiloSubnet, h.Status.Network.SiloSubnetIPv6 = "10.64.2.0/24", "fd12:3456:789a:2::/64"
	s := silo()
	s.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 8080}, {Name: "metrics", Port: 9090}}
	s.Spec.Services = []v1.SiloService{
		{Name: "api", Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "http", As: 443, Sources: []string{"192.0.2.0/24"}}}},
		{Name: "api-metrics", Ports: []v1.ServicePort{{Port: "metrics", AllowFrom: []string{"prom"}}}},
	}
	s.Spec.Availability = v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop, After: "5m"}
	s.Status.SiloIP, s.Status.SiloIPv6 = "10.64.2.7", "fd12:3456:789a:2::7"
	s.Status.Service.EgressIPv6 = "2001:db8:10::5"
	net := netObjects(created)
	for k, l := range map[string][]meta.Object{"Host": {h}, "Silo": {s}} {
		net[k] = append(l, net[k]...)
	}
	return net
}

// netObjects are networking v2's lived-in objects: a host with extra addresses, a Host IP held
// by a silo, a Provider IP, a Static and a Dynamic IP set, and silos with every way in.
func netObjects(created time.Time) map[string][]meta.Object {
	om := func(name, ns string, labels map[string]string) meta.ObjectMeta {
		return meta.ObjectMeta{Name: name, Namespace: ns, Labels: labels, CreationTimestamp: &created}
	}
	h := &v1.Host{ObjectMeta: om("baremetal-1", "", nil),
		Spec: v1.HostSpec{InternalIP: "10.0.0.6", ExternalIP: "203.0.113.20", Region: "ca-central",
			Addresses: []v1.HostAddress{{Name: "mail", Kind: v1.NetworkExternal, Address: "203.0.113.21"}, {Name: "spare", Kind: v1.NetworkInternal, Address: "10.0.0.66"},
				{Name: "mail6", Kind: v1.NetworkExternal, Address: "2001:db8:20::21"}},
			Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "cloud-hypervisor"}}}}}}
	mail := &v1.IP{ObjectMeta: om("mail", "mail", nil), Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail"},
		Status: v1.IPStatus{Address: "203.0.113.21", Where: "host baremetal-1", Host: "baremetal-1",
			Holder: &v1.IPHolder{Holder: "silo/smtp", UID: "u-smtp", Ports: []string{"25/TCP"}}}}
	mail6 := &v1.IP{ObjectMeta: om("mail6", "mail", nil), Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail6", Family: v1.FamilyIPv6},
		Status: v1.IPStatus{Address: "2001:db8:20::21", Where: "host baremetal-1", Host: "baremetal-1"}}
	edge := &v1.IP{ObjectMeta: om("api-edge", "mail", nil), Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "us-ord"},
		Status: v1.IPStatus{Address: "172.232.0.9", Where: "linode us-ord", Region: "us-ord",
			Waiting: []v1.IPWaiting{{Holder: "silo/web2", UID: "u-web2", Reason: "held by silo/web"}}}}
	member := &v1.IP{ObjectMeta: om("relay-1", "mail", map[string]string{v1.LabelIPSet: "relays", v1.LabelIPSetOrdinal: "1"}),
		Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "us-ord"}}
	static := &v1.IPSet{ObjectMeta: om("relays", "mail", nil),
		Spec:   v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{{HostAddress: "spare"}, {IP: "relay-1"}}},
		Status: v1.IPSetStatus{Members: []v1.IPSetMemberStatus{{Ordinal: 0, IP: "relays-0", Address: "10.0.0.66", UsedBy: "relay-0"}}}}
	dynamic := &v1.IPSet{ObjectMeta: om("edge", "mail", nil),
		Spec:   v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "linode", Region: "us-ord", Max: 3},
		Status: v1.IPSetStatus{Members: []v1.IPSetMemberStatus{{Ordinal: 0, IP: "edge-0", Address: "172.232.0.20", UsedBy: "edge-0"}, {Ordinal: 1, IP: "edge-1"}}}}
	smtpPorts := []v1.SiloPort{{Name: "smtp", Port: 25}, {Name: "https", Port: 8443}, {Name: "metrics", Port: 9090}}
	smtp := &v1.Silo{ObjectMeta: om("smtp", "mail", nil),
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Ports: smtpPorts, Services: []v1.SiloService{
			{Name: "smtp", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "mail"}, Ports: []v1.ServicePort{{Port: "smtp"}}},
			{Name: "webmail", Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "https", As: 443}}},
			{Name: "smtp-metrics", Ports: []v1.ServicePort{{Port: "metrics", AllowFrom: []string{"monitoring/prometheus"}}}},
		}, Network: v1.SiloNetwork{Egress: v1.Egress{Source: &v1.EgressSource{IP: "mail"}}}},
		Status: v1.SiloStatus{Phase: "Running", Host: "baremetal-1", SiloIP: "10.64.3.4", Movable: "no: pinned to baremetal-1 (IP mail is that host's address)",
			Service: v1.SiloServiceStatus{EgressIP: "203.0.113.21", Ports: []v1.ServicePortStatus{{Port: "https", External: "203.0.113.20:443"}}}}}
	web := &v1.Silo{ObjectMeta: om("web", "mail", nil),
		Spec: v1.SiloSpec{Runtime: "docker", Ports: []v1.SiloPort{{Name: "https", Port: 8443}}, Services: []v1.SiloService{
			{Name: "api", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "api-edge"}, Ports: []v1.ServicePort{{Port: "https", As: 443}}},
			{Name: "shop", Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "linode"}, Ports: []v1.ServicePort{{Port: "https", As: 443}}},
		}}}
	far := &v1.Silo{ObjectMeta: om("far", "mail", nil),
		Spec: v1.SiloSpec{Runtime: "docker", Ports: []v1.SiloPort{{Name: "smtp", Port: 25}, {Name: "https", Port: 8443}}, Services: []v1.SiloService{
			{Name: "far-smtp", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "mail"}, Ports: []v1.ServicePort{{Port: "smtp"}}},
			{Name: "far-api", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "nope"}, Ports: []v1.ServicePort{{Port: "https"}}},
		}}}
	set := &v1.SiloSet{ObjectMeta: om("relay", "mail", nil), Spec: v1.SiloSetSpec{Instances: 2, IPs: "relays",
		Template: v1.SiloTemplate{SiloSpec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "relay:v1"}}}}}
	return map[string][]meta.Object{"Host": {h}, "IP": {mail, mail6, edge, member}, "IPSet": {static, dynamic}, "Silo": {smtp, web, far}, "SiloSet": {set}}
}

// envOf is what describe would read for these objects, from the objects themselves.
func envOf(objs map[string][]meta.Object) *netEnv {
	e := &netEnv{}
	for _, o := range objs["IP"] {
		e.ips = append(e.ips, o.(*v1.IP))
	}
	for _, o := range objs["IPSet"] {
		e.ipsets = append(e.ipsets, o.(*v1.IPSet))
	}
	for _, o := range objs["Host"] {
		e.hosts = append(e.hosts, o.(*v1.Host))
	}
	for _, o := range objs["Silo"] {
		e.silos = append(e.silos, o.(*v1.Silo))
	}
	for _, o := range objs["SiloSet"] {
		e.silosets = append(e.silosets, o.(*v1.SiloSet))
	}
	return e
}

func TestGoldenGetAndDescribe(t *testing.T) {
	objs := exampleObjects(t)
	for k, l := range livedIn() {
		objs[k] = append(objs[k], l...)
	}
	kinds := make([]string, 0, len(objs))
	for k := range objs {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	env := envOf(objs)
	if len(kinds) < 8 {
		t.Fatalf("only %v: the examples weren't found", kinds)
	}
	for _, kind := range kinds {
		k, _ := v1.Lookup(kind)
		var b bytes.Buffer
		for _, wide := range []bool{false, true} {
			if err := printTable(&b, k, objs[kind], true, wide); err != nil {
				t.Fatalf("%s: %v", kind, err)
			}
			b.WriteString("\n")
		}
		for _, o := range objs[kind] {
			if err := describeWith(&b, o, env); err != nil {
				t.Fatalf("describe %s: %v", kind, err)
			}
			b.WriteString("---\n")
		}
		golden(t, strings.ToLower(kind)+".txt", b.String())
	}
}
