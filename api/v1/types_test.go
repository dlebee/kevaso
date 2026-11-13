package v1

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
)

// The YAML in examples/ is the contract: this is examples/01-one-host.yaml's silo, as JSON.
const siloJSON = `{
  "apiVersion": "kevaso/v1", "kind": "Silo",
  "metadata": {"name": "hello", "namespace": "demo", "labels": {"app": "hello"}},
  "spec": {
    "runtime": "cloud-hypervisor", "vm": {"image": "ubuntu-24.04"},
    "resources": {"cpu": 2, "memory": "4Gi"},
    "placement": {"hostSelector": {"region": "ca-central"}},
    "tolerations": [{"key": "pool", "value": "quarantine", "effect": "NoSchedule"}]
  }
}`

func TestDecodeSilo(t *testing.T) {
	obj, k, err := Decode([]byte(siloJSON))
	if err != nil {
		t.Fatal(err)
	}
	s, ok := obj.(*Silo)
	if !ok || k.Kind != "Silo" || k.Scope != Namespaced {
		t.Fatalf("decoded %T as %+v", obj, k)
	}
	if s.Name != "hello" || s.Namespace != "demo" || s.Spec.Runtime != "cloud-hypervisor" || s.Spec.VM == nil || s.Spec.From() != "ubuntu-24.04" ||
		s.Spec.Resources.CPU != 2 || s.Spec.Placement.HostSelector["region"] != "ca-central" ||
		len(s.Spec.Tolerations) != 1 {
		t.Fatalf("decoded silo %+v", s)
	}
}

func TestDecodeRejects(t *testing.T) {
	for name, in := range map[string]string{
		"not json":       `{`,
		"wrong version":  `{"apiVersion":"kevaso/v2","kind":"Silo"}`,
		"unknown kind":   `{"apiVersion":"kevaso/v1","kind":"Pod"}`,
		"no kind":        `{"apiVersion":"kevaso/v1"}`,
		"bad field type": `{"apiVersion":"kevaso/v1","kind":"Silo","spec":{"resources":{"cpu":"two"}}}`,
	} {
		if _, _, err := Decode([]byte(in)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestRoundTripKeepsEverything(t *testing.T) {
	obj, _, _ := Decode([]byte(siloJSON))
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := json.Marshal(obj)
	b2, _ := json.Marshal(again)
	if string(b1) != string(b2) {
		t.Fatalf("round trip changed the object:\n%s\n%s", b1, b2)
	}
	if !strings.Contains(string(out), `"kind":"Silo"`) {
		t.Fatalf("kind lost on encode: %s", out)
	}
}

func TestCloneIsDeep(t *testing.T) {
	obj, _, _ := Decode([]byte(siloJSON))
	s := obj.(*Silo)
	c, err := Clone(s)
	if err != nil {
		t.Fatal(err)
	}
	c.Labels["app"] = "changed"
	c.Spec.Tolerations[0].Key = "changed"
	if s.Labels["app"] != "hello" || s.Spec.Tolerations[0].Key != "pool" {
		t.Fatal("changing the clone changed the original")
	}
}

func TestLookup(t *testing.T) {
	for _, name := range []string{"Silo", "silos"} {
		if k, ok := Lookup(name); !ok || k.Kind != "Silo" {
			t.Errorf("Lookup(%q) = %+v, %v", name, k, ok)
		}
	}
	if _, ok := Lookup("pods"); ok {
		t.Error("Lookup(pods) found something")
	}
	if got := len(Kinds()); got != 25 {
		t.Errorf("%d kinds, want 25", got)
	}
}

func TestTolerations(t *testing.T) {
	taint := Taint{Key: "pool", Value: "quarantine", Effect: NoSchedule}
	for _, tc := range []struct {
		tol  Toleration
		want bool
	}{
		{Toleration{Key: "pool", Value: "quarantine", Effect: NoSchedule}, true},
		{Toleration{Key: "pool"}, true},                                          // any value, any effect
		{Toleration{Key: "pool", Value: "other"}, false},                         // wrong value
		{Toleration{Key: "pool", Effect: PreferNoSchedule}, false},               // wrong effect
		{Toleration{Key: "gpu", Value: "quarantine", Effect: NoSchedule}, false}, // wrong key
	} {
		if got := tc.tol.Tolerates(taint); got != tc.want {
			t.Errorf("%+v tolerates %+v = %v, want %v", tc.tol, taint, got, tc.want)
		}
	}
}

func TestSetCondition(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)
	var conds []meta.Condition
	if !meta.SetCondition(&conds, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: "Booting"}, t0) {
		t.Fatal("adding a condition reported no change")
	}
	if meta.SetCondition(&conds, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: "Booting"}, t1) {
		t.Fatal("same condition reported a change")
	}
	// A new reason with the same status keeps the transition time.
	meta.SetCondition(&conds, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: "Init"}, t1)
	if c := meta.FindCondition(conds, "Ready"); c.LastTransitionTime != t0 || c.Reason != "Init" {
		t.Fatalf("reason change: %+v", c)
	}
	// A status change moves it.
	meta.SetCondition(&conds, meta.Condition{Type: "Ready", Status: meta.ConditionTrue}, t1)
	if c := meta.FindCondition(conds, "Ready"); c.LastTransitionTime != t1 || !meta.IsTrue(conds, "Ready") {
		t.Fatalf("status change: %+v", c)
	}
	if meta.IsTrue(conds, "InitFailed") {
		t.Fatal("missing condition reported True")
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"a", "hello", "eth-node-1", strings.Repeat("a", 63)} {
		if err := meta.ValidateName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Hello", "-a", "a-", "a_b", "a.b", strings.Repeat("a", 64)} {
		if meta.ValidateName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseBytes(t *testing.T) {
	for in, want := range map[string]int64{"": 0, "0": 0, "1024": 1024, "4Gi": 4 << 30, "512Mi": 512 << 20, "10G": 10e9, "2Ti": 2 << 40} {
		if got, err := ParseBytes(in); err != nil || got != want {
			t.Errorf("ParseBytes(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"4GB", "-1Gi", "1.5Gi", "Gi", "lots", "99999999999Ti"} {
		if _, err := ParseBytes(bad); err == nil {
			t.Errorf("ParseBytes(%q) accepted", bad)
		}
	}
}

func TestResolveImage(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	img := &VMImage{ObjectMeta: meta.ObjectMeta{Name: "geth", Namespace: "web3"}, Spec: VMImageSpec{Versions: []VMImageVersion{
		{Name: "v1", Disk: &VMDisk{URL: "https://x/geth-1.img", SHA256: sum}},
		{Name: "v2", Disk: &VMDisk{URL: "https://x/geth-2.img", SHA256: sum}},
	}}}
	empty := &VMImage{ObjectMeta: meta.ObjectMeta{Name: "empty", Namespace: "web3"}}
	ch := func(src VMSource) SiloSpec { return SiloSpec{Runtime: "cloud-hypervisor", VM: &src} }
	ctr := func(rt, image string) SiloSpec {
		return SiloSpec{Runtime: rt, Container: &ContainerSource{Image: image}}
	}
	digest := "ghcr.io/acme/api@sha256:" + strings.Repeat("0", 64)
	for _, tc := range []struct {
		name      string
		spec      SiloSpec
		want, err string
	}{
		// container.image: as it is, never looked up (a VMImage of the same name doesn't matter)
		{"container tag", ctr("docker", "nginx:1.27"), "nginx:1.27", ""},
		{"container named like a VMImage", ctr("docker", "geth:v1"), "geth:v1", ""},
		{"container with a registry port", ctr("podman", "registry:5000/geth"), "registry:5000/geth", ""},
		{"container by digest", ctr("openshell-container", digest), digest, ""},
		{"container built-in", ctr("docker", "ubuntu-24.04"), "ubuntu-24.04", ""},
		// vm.disk: its URL and hash, the hash lowercased
		{"vm.disk", ch(VMSource{Disk: &VMDisk{URL: "https://x/d.img", SHA256: strings.Repeat("AB", 32)}}), "https://x/d.img#sha256=" + sum, ""},
		// vm.image: a VMImage's version
		{"vm.image newest", ch(VMSource{Image: "geth"}), "https://x/geth-2.img#sha256=" + sum, ""},
		{"vm.image NAME:VERSION", ch(VMSource{Image: "geth:v1"}), "https://x/geth-1.img#sha256=" + sum, ""},
		{"vm.image built-in", ch(VMSource{Image: "ubuntu-24.04"}), "ubuntu-24.04", ""},
		{"vm.image unknown name", ch(VMSource{Image: "other"}), "", "no VMImage other"},
		{"vm.image unknown version", ch(VMSource{Image: "geth:v9"}), "", "VMImage geth has no version v9"},
		{"vm.image no versions", ch(VMSource{Image: "empty"}), "", "VMImage empty has no versions"},
		{"nothing", SiloSpec{Runtime: "cloud-hypervisor"}, "", ""},
	} {
		got, err := ResolveImage(tc.spec, []*VMImage{img, empty})
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err %v, want %q", tc.name, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: %q %v, want %q", tc.name, got, err, tc.want)
		}
	}
}

// A set rolls when what its template boots changes, an inline disk's hash included.
func TestSiloSetRevisionFollowsTheDisk(t *testing.T) {
	set := func(sum string) *SiloSet {
		return &SiloSet{ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "web3"}, Spec: SiloSetSpec{Instances: 2,
			Template: SiloTemplate{SiloSpec: SiloSpec{Runtime: "cloud-hypervisor",
				VM: &VMSource{Disk: &VMDisk{URL: "https://x/geth.img", SHA256: sum}}}}}}
	}
	a, b := set(strings.Repeat("ab", 32)), set(strings.Repeat("cd", 32))
	if a.Revision() == b.Revision() {
		t.Fatal("changing template.vm.disk.sha256 didn't change the revision: the set wouldn't roll")
	}
	if a.Revision() != set(strings.Repeat("ab", 32)).Revision() {
		t.Fatal("the same template gave two revisions")
	}
	if got := a.Instance(0, false); got.Labels[LabelRevision] != a.Revision() || got.Spec.From() != "https://x/geth.img#sha256="+strings.Repeat("ab", 32) {
		t.Fatalf("instance: %+v", got)
	}
}
