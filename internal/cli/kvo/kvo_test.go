package kvo

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func TestKindNames(t *testing.T) {
	for in, want := range map[string]string{"ns": "Namespace", "namespace": "Namespace", "NS": "Namespace", "silo": "Silo", "silos": "Silo", "Host": "Host", "hosts": "Host"} {
		if k, err := kindOf(in); err != nil || k.Kind != want {
			t.Errorf("%q: %v, %v", in, k.Kind, err)
		}
	}
	if _, err := kindOf("pods"); err == nil {
		t.Error("pods accepted")
	}
}

func silo() *v1.Silo {
	created := time.Now().Add(-3 * time.Minute)
	zero := 0
	return &v1.Silo{
		ObjectMeta: meta.ObjectMeta{Name: "hello", Namespace: "demo", CreationTimestamp: &created, Labels: map[string]string{"b": "2", "a": "1"}},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Image: "ubuntu-24.04", Resources: v1.Resources{CPU: 1, Memory: "1Gi"}, Disk: v1.Disk{Size: "10Gi"},
			Init: &v1.Init{Steps: []v1.InitStep{{Name: "one", Run: "x"}, {Name: "two", Run: "y"}, {Name: "three", Run: "z"}}}},
		Status: v1.SiloStatus{Phase: "Starting", Host: "hv1",
			Init:       []v1.StepStatus{{Name: "one", State: "Done", ExitCode: &zero, Duration: "27s"}, {Name: "two", State: "Running"}},
			Conditions: []meta.Condition{{Type: "Ready", Status: meta.ConditionFalse, Reason: "Initializing", Message: "init step two", LastTransitionTime: created}}},
	}
}

func TestSummary(t *testing.T) {
	if got := summary(silo()); got != "phase=Starting  host=hv1  init=1/3  Ready: init step two" {
		t.Fatalf("silo: %q", got)
	}
	h := &v1.Host{Status: v1.HostStatus{Runtimes: map[string]v1.RuntimeStatus{
		"cloud-hypervisor": {State: "Installing", Message: "5/7 image (Ubuntu 24.04, ~600 MB, first time only)"},
		"docker":           {State: "Ready", Message: "ignored once Ready"},
	}}}
	if got := summary(h); got != "cloud-hypervisor=Installing (5/7 image (Ubuntu 24.04, ~600 MB, first time only))  docker=Ready" {
		t.Fatalf("host: %q", got)
	}
}

func TestDescribeSilo(t *testing.T) {
	var b bytes.Buffer
	if err := describeObject(&b, silo()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Name:", "hello", "Namespace:", "demo", "a=1, b=2", "(3m ago)",
		"1 CPU, 1Gi memory", "10Gi", "Phase:", "Starting",
		"Init steps:", "one    Done     0     27s", "two    Running  -     -", "three  Pending  -     -",
		"Conditions:", "Ready  False   Initializing  3m     init step two",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestDescribeHost(t *testing.T) {
	h := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{Address: "203.0.113.10", Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{},
			Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "cloud-hypervisor"}}, Taints: []v1.Taint{{Key: "gpu", Value: "yes", Effect: v1.NoSchedule}}}}},
		Status: v1.HostStatus{Allocatable: v1.Resources{CPU: 3, Memory: "4886Mi"},
			Runtimes: map[string]v1.RuntimeStatus{"cloud-hypervisor": {State: "Failed", Version: "v54.1", Message: "install image: checksum mismatch"}}}}
	var b bytes.Buffer
	_ = describeObject(&b, h)
	for _, want := range []string{"control-plane, worker", "gpu=yes:NoSchedule", "3 CPU, 4886Mi memory", "cloud-hypervisor  Failed  v54.1    install image: checksum mismatch"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
}
