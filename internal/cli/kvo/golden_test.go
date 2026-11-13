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
			Runtimes: map[string]v1.RuntimeStatus{"cloud-hypervisor": {State: "Ready", Version: "v54.1"}, "docker": {State: "Installing", Message: "3/5 engine"}}}}
	h.Status.Network.MeshIP = "10.63.0.2"
	s := silo()
	s.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 8080}, {Name: "metrics", Port: 9090}}
	s.Spec.Service = &v1.SiloService{Name: "api", Ports: []v1.ServicePort{{Port: "http", HostPort: []string{"external"}, As: 443, Sources: []string{"192.0.2.0/24"}}, {Port: "metrics", AllowFrom: []string{"prom"}}}}
	s.Status.SiloIP = "10.64.2.7"
	return map[string][]meta.Object{"Host": {h}, "Silo": {s}}
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
			if err := describeObject(&b, o); err != nil {
				t.Fatalf("describe %s: %v", kind, err)
			}
			b.WriteString("---\n")
		}
		golden(t, strings.ToLower(kind)+".txt", b.String())
	}
}
