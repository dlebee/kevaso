package kvo

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"
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

func TestApprovalColumns(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	a := &v1.Approval{Spec: v1.ApprovalSpec{Silo: "claude-1", Secret: "gh-admin", Use: v1.ApprovalForInject, For: "30m0s", ExpiresAt: now.Add(5 * time.Minute)},
		Status: v1.ApprovalStatus{Phase: v1.ApprovalPending}}
	if got := strings.Join(approvalColumns(a, now), "|"); got != "claude-1|gh-admin|inject|30m0s|Pending|expires in 5m0s|-" {
		t.Fatalf("pending: %s", got)
	}
	if got := approvalColumns(a, now.Add(5*time.Minute)); got[4] != v1.ApprovalExpired {
		t.Fatalf("pending past its time shows %s", got[4])
	}
	until := now.Add(30 * time.Minute)
	a.Status = v1.ApprovalStatus{Phase: v1.ApprovalApproved, AnsweredBy: "alice", AccessUntil: &until}
	if got := approvalColumns(a, now); got[4] != v1.ApprovalApproved || got[6] != "alice" || !strings.HasPrefix(got[5], "until ") {
		t.Fatalf("approved: %v", got)
	}
	if got := approvalColumns(a, until); got[4] != "Used" {
		t.Fatalf("after access: %v", got)
	}
}

// A silo's text never reaches the terminal as escapes or direction overrides.
func TestPlainStripsEscapes(t *testing.T) {
	got := plain("ok\x1b[2J\x1b]0;pwned\x07 \u202emoc.live\nnext\u0085", 0)
	if strings.ContainsAny(got, "\x1b\x07\u202e\u0085\n") || !strings.Contains(got, "ok") || !strings.Contains(got, "next") {
		t.Fatalf("plain = %q", got)
	}
	if got := plain(strings.Repeat("x", 50), 10); got != strings.Repeat("x", 10)+"…" {
		t.Fatalf("cut = %q", got)
	}
}

func TestPaneLine(t *testing.T) {
	p, at := 0.57, time.Now().Add(-2*time.Minute)
	pane := &v1.Pane{ObjectMeta: meta.ObjectMeta{Namespace: "agents"}, Spec: v1.PaneReport{Silo: "claude-1", Pane: "overview", Kind: "status",
		State: "needs-you", Progress: &p, Title: "refactor", Message: "Keep legacy rounding?", TTL: "60s"}, Status: v1.PaneState{UpdatedAt: &at}}
	got := paneLine(pane, time.Now())
	for _, want := range []string{"agents/claude-1", "[overview]", "(stale)", "needs-you", "57%", "Keep legacy rounding?"} {
		if !strings.Contains(got, want) {
			t.Errorf("line %q is missing %q", got, want)
		}
	}
}

// kvo get KIND -o json|yaml is an array (a sequence) however many there are (E2E: a script
// reading leases broke when there was just one, printed as a bare object; -o yaml printed nothing
// for none and a stream of documents for several); kvo get KIND NAME is the object.
func TestStructuredOutputShape(t *testing.T) {
	for _, tc := range []struct {
		objs []meta.Object
		list bool
		n    int // items, or -1: one object
	}{
		{nil, true, 0}, {[]meta.Object{silo()}, true, 1}, {[]meta.Object{silo(), silo()}, true, 2}, {[]meta.Object{silo()}, false, -1},
	} {
		var j, y bytes.Buffer
		if err := printJSON(&j, tc.objs, tc.list); err != nil {
			t.Fatal(err)
		}
		if err := printYAML(&y, tc.objs, tc.list); err != nil {
			t.Fatal(err)
		}
		var fromJSON, fromYAML any
		if err := json.Unmarshal(j.Bytes(), &fromJSON); err != nil {
			t.Fatalf("json: %v\n%s", err, j.String())
		}
		if strings.Contains(y.String(), "\n---") {
			t.Errorf("%d objects, list %v: yaml is several documents:\n%s", len(tc.objs), tc.list, y.String())
		}
		if err := yaml.Unmarshal(y.Bytes(), &fromYAML); err != nil {
			t.Fatalf("yaml: %v\n%s", err, y.String())
		}
		for name, v := range map[string]any{"json": fromJSON, "yaml": fromYAML} {
			switch x := v.(type) {
			case []any:
				if tc.n != len(x) {
					t.Errorf("%s, %d objects, list %v: an array of %d", name, len(tc.objs), tc.list, len(x))
				}
			case map[string]any:
				if tc.n != -1 {
					t.Errorf("%s, %d objects, list %v: an object", name, len(tc.objs), tc.list)
				}
			default:
				t.Errorf("%s, %d objects, list %v: %T", name, len(tc.objs), tc.list, v)
			}
		}
	}
	for _, out := range []string{"json", "yaml"} {
		var b bytes.Buffer
		if err := printList[string](&b, out, nil); err != nil || strings.TrimSpace(b.String()) != "[]" {
			t.Errorf("printList %s of none: %q %v", out, b.String(), err)
		}
	}
}
