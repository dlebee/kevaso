package scheduler

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

type hostOpt func(*v1.Host)

func host(name string, opts ...hostOpt) *v1.Host {
	h := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: name}}
	h.Spec.Components.Worker = &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "cloud-hypervisor"}}}
	h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue}}
	h.Status.Runtimes = map[string]v1.RuntimeStatus{"cloud-hypervisor": {State: "Ready"}}
	h.Status.Allocatable = v1.Resources{CPU: 8, Memory: "16Gi"}
	for _, o := range opts {
		o(h)
	}
	return h
}

func labels(kv ...string) hostOpt {
	return func(h *v1.Host) {
		h.Spec.Components.Worker.Labels = map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			h.Spec.Components.Worker.Labels[kv[i]] = kv[i+1]
		}
	}
}
func taint(k, v string, e v1.TaintEffect) hostOpt {
	return func(h *v1.Host) {
		h.Spec.Components.Worker.Taints = append(h.Spec.Components.Worker.Taints, v1.Taint{Key: k, Value: v, Effect: e})
	}
}
func mem(m string) hostOpt { return func(h *v1.Host) { h.Status.Allocatable.Memory = m } }
func notReady() hostOpt {
	return func(h *v1.Host) { h.Status.Conditions[0].Status = meta.ConditionFalse }
}
func runtimeState(state string) hostOpt {
	return func(h *v1.Host) { h.Status.Runtimes["cloud-hypervisor"] = v1.RuntimeStatus{State: state} }
}
func noRuntime() hostOpt {
	return func(h *v1.Host) {
		h.Spec.Components.Worker.Runtimes = []v1.RuntimeSpec{{Name: "docker"}}
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
	}
}
func controlPlaneOnly() hostOpt {
	return func(h *v1.Host) {
		h.Spec.Components.Worker = nil
		h.Spec.Components.ControlPlane = &v1.ControlPlaneSpec{}
	}
}

type siloOpt func(*v1.Silo)

func silo(name string, opts ...siloOpt) *v1.Silo {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Resources: v1.Resources{CPU: 2, Memory: "4Gi"}}}
	for _, o := range opts {
		o(s)
	}
	return s
}
func selector(k, v string) siloOpt {
	return func(s *v1.Silo) { s.Spec.Placement.HostSelector = map[string]string{k: v} }
}
func tolerate(k, v string, e v1.TaintEffect) siloOpt {
	return func(s *v1.Silo) {
		s.Spec.Tolerations = append(s.Spec.Tolerations, v1.Toleration{Key: k, Value: v, Effect: e})
	}
}
func on(h string) siloOpt { return func(s *v1.Silo) { s.Status.Host = h } }
func size(cpu int, m string) siloOpt {
	return func(s *v1.Silo) { s.Spec.Resources = v1.Resources{CPU: cpu, Memory: m} }
}
func withRuntime(r string) siloOpt     { return func(s *v1.Silo) { s.Spec.Runtime = r } }
func hosts(hs ...*v1.Host) []*v1.Host  { return hs }
func placed(ss ...*v1.Silo) []*v1.Silo { return ss }

func TestSchedule(t *testing.T) {
	for _, tc := range []struct {
		name     string
		silo     *v1.Silo
		hosts    []*v1.Host
		placed   []*v1.Silo
		want     string
		excluded map[string]string // host → substring of the reason
	}{
		{name: "one fitting host", silo: silo("a"), hosts: hosts(host("hv1")), want: "hv1"},
		{name: "control-plane-only hosts aren't candidates", silo: silo("a"),
			hosts: hosts(host("cp", controlPlaneOnly()), host("hv1")), want: "hv1"},
		{name: "not Ready", silo: silo("a"), hosts: hosts(host("hv1", notReady())),
			excluded: map[string]string{"hv1": "not Ready"}},
		{name: "runtime not installed", silo: silo("a"), hosts: hosts(host("hv1", noRuntime())),
			excluded: map[string]string{"hv1": "cloud-hypervisor not installed"}},
		{name: "runtime installing", silo: silo("a"), hosts: hosts(host("hv1", runtimeState("Installing"))),
			excluded: map[string]string{"hv1": "cloud-hypervisor not Ready"}},
		{name: "container silo goes where docker is", silo: silo("a", withRuntime("docker")),
			hosts: hosts(host("metal"), host("lin", noRuntime())), want: "lin"},
		{name: "hostSelector", silo: silo("a", selector("region", "home")),
			hosts: hosts(host("tor", labels("region", "ca-central")), host("home", labels("region", "home"))), want: "home"},
		{name: "region", silo: silo("a", func(s *v1.Silo) { s.Spec.Placement.Region = "eu-central" }),
			hosts: hosts(host("tor", where("ca-central", "tor")), host("fra", where("eu-central", "fra"))), want: "fra"},
		{name: "zone", silo: silo("a", func(s *v1.Silo) { s.Spec.Placement.Zone = "tor" }),
			hosts:    hosts(host("fra", where("eu-central", "fra")), host("nowhere")),
			excluded: map[string]string{"fra": "in zone fra, not tor", "nowhere": "in zone (none), not tor"}},
		{name: "cordoned host", silo: silo("a"), hosts: hosts(host("hv1", func(h *v1.Host) { h.Spec.Unschedulable = true }), host("hv2")), want: "hv2"},
		{name: "hostSelector matches nothing", silo: silo("a", selector("gpu", "true")), hosts: hosts(host("hv1")),
			excluded: map[string]string{"hv1": "label gpu=true missing"}},
		{name: "NoSchedule taint repels", silo: silo("a"),
			hosts: hosts(host("q", taint("pool", "quarantine", v1.NoSchedule))), excluded: map[string]string{"q": "taint"}},
		{name: "toleration lets it in", silo: silo("a", tolerate("pool", "quarantine", v1.NoSchedule)),
			hosts: hosts(host("q", taint("pool", "quarantine", v1.NoSchedule))), want: "q"},
		{name: "toleration for another value doesn't", silo: silo("a", tolerate("pool", "gpu", v1.NoSchedule)),
			hosts: hosts(host("q", taint("pool", "quarantine", v1.NoSchedule))), excluded: map[string]string{"q": "taint"}},
		{name: "PreferNoSchedule is avoided when another host fits", silo: silo("a"),
			hosts: hosts(host("home", taint("intermittent", "true", v1.PreferNoSchedule), mem("64Gi")), host("tor")), want: "tor"},
		{name: "PreferNoSchedule is used when nothing else fits", silo: silo("a"),
			hosts: hosts(host("home", taint("intermittent", "true", v1.PreferNoSchedule))), want: "home"},
		{name: "memory full", silo: silo("big", size(2, "12Gi")), hosts: hosts(host("hv1")),
			placed: placed(silo("x", on("hv1"), size(1, "8Gi"))), excluded: map[string]string{"hv1": "not enough memory"}},
		{name: "cpu full", silo: silo("a", size(4, "1Gi")), hosts: hosts(host("hv1")),
			placed: placed(silo("x", on("hv1"), size(6, "1Gi"))), excluded: map[string]string{"hv1": "not enough CPU"}},
		{name: "spreads to the host with more free memory", silo: silo("a"),
			hosts: hosts(host("hv1"), host("hv2")), placed: placed(silo("x", on("hv1"), size(1, "8Gi"))), want: "hv2"},
		{name: "rescheduling itself doesn't count its own usage", silo: silo("a", on("hv1"), size(2, "16Gi")),
			hosts: hosts(host("hv1")), placed: placed(silo("a", on("hv1"), size(2, "16Gi"))), want: "hv1"},
		{name: "ties break by name", silo: silo("a"), hosts: hosts(host("hv2"), host("hv1")), want: "hv1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Schedule(tc.silo, tc.hosts, tc.placed)
			if err != nil {
				t.Fatal(err)
			}
			if d.Host != tc.want {
				t.Fatalf("host %q, want %q (%s)", d.Host, tc.want, d.Message())
			}
			for h, sub := range tc.excluded {
				if !strings.Contains(d.Excluded[h], sub) {
					t.Errorf("%s excluded for %q, want it to mention %q", h, d.Excluded[h], sub)
				}
			}
		})
	}
}

func TestMessageExplainsEveryHost(t *testing.T) {
	d, _ := Schedule(silo("a", selector("gpu", "true")), hosts(host("hv1"), host("hv2", notReady())), nil)
	msg := d.Message()
	if !strings.Contains(msg, "hv1: label gpu=true missing") || !strings.Contains(msg, "hv2: host not Ready") {
		t.Fatalf("message %q", msg)
	}
	if (Decision{}).Message() != "no hosts with a worker component" {
		t.Fatal("empty cluster message")
	}
}

func TestBadMemoryIsAnError(t *testing.T) {
	if _, err := Schedule(silo("a", size(1, "lots")), hosts(host("hv1")), nil); err == nil {
		t.Fatal("unparseable memory accepted")
	}
}

func where(region, zone string) hostOpt {
	return func(h *v1.Host) { h.Spec.Region, h.Spec.Zone = region, zone }
}
