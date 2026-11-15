package apiserver_test

import (
	"net/http"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// K-035 (design §0.8): a name combination whose provider label would be cut is refused at
// creation, naming the numbers; one that fits is admitted; an update that doesn't touch the
// volumes still goes through.
func TestVolumeNamesTooLongForTheProviderLabelAreRefused(t *testing.T) {
	e := setupAccess(t)
	for _, n := range []string{"production", "dev"} {
		if err := e.admin.Create(e.ctx, ns(n)); err != nil {
			t.Fatal(err)
		}
	}
	silo := func(ns, name string, vols ...string) *v1.Silo {
		s := &v1.Silo{TypeMeta: accessTM("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "nginx:1.27"}}}
		for _, v := range vols {
			s.Spec.Volumes = append(s.Spec.Volumes, v1.Volume{Name: v, Class: "linode-block", Size: "10Gi", MountPath: "/" + v})
		}
		return s
	}
	// kvo-production-payments-db-data is 31 characters: the label keeps 26. The auditor's case.
	err := e.admin.Create(e.ctx, silo("production", "payments-db", "data", "wal"))
	if code(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "kvo-production-payments-db-data is 31 characters and the label keeps 26") {
		t.Fatalf("auditor's case: %v", err)
	}
	// Two volumes sharing a beginning: both refused in one answer.
	err = e.admin.Create(e.ctx, silo("production", "api", "cache-primary", "cache-secondary"))
	if code(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "cache-primary") || !strings.Contains(err.Error(), "cache-secondary") {
		t.Fatalf("shared beginning: %v", err)
	}
	// Exactly 26 fits, 27 doesn't. kvo-dev-api-<n> : 4+3+1+3+1 = 12, so a 14 and a 15 character volume.
	if err := e.admin.Create(e.ctx, silo("dev", "api", "abcdefghijklmn")); err != nil { // 26
		t.Fatalf("26 characters: %v", err)
	}
	if err := e.admin.Create(e.ctx, silo("dev", "api2", "abcdefghijklmno")); code(err) != http.StatusUnprocessableEntity { // 4+3+1+4+1+15 = 28
		t.Fatalf("28 characters: %v", err)
	}
	// Local volumes have no provider label: any name that is valid.
	local := silo("production", "payments-db", "data", "wal")
	for i := range local.Spec.Volumes {
		local.Spec.Volumes[i].Class, local.Spec.Volumes[i].Size = "local", ""
	}
	if err := e.admin.Create(e.ctx, local); err != nil {
		t.Fatalf("local volumes: %v", err)
	}
	// An update leaving the volumes alone passes; adding a volume with a too-long label doesn't.
	var cur v1.Silo
	if err := e.admin.Get(e.ctx, "Silo", "dev", "api", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Labels = map[string]string{"a": "b"}
	if err := e.admin.Update(e.ctx, &cur); err != nil {
		t.Fatalf("update without touching volumes: %v", err)
	}
	cur.Spec.Volumes = append(cur.Spec.Volumes, v1.Volume{Name: "second-volume-long", Class: "linode-block", Size: "1Gi", MountPath: "/s"})
	if err := e.admin.Update(e.ctx, &cur); code(err) != http.StatusUnprocessableEntity {
		t.Fatalf("adding a long one: %v", err)
	}
	// A SiloSet is checked with its longest instance name.
	set := &v1.SiloSet{TypeMeta: accessTM("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "pool", Namespace: "dev"},
		Spec: v1.SiloSetSpec{Instances: 12, Template: v1.SiloTemplate{SiloSpec: silo("dev", "t", "abcdefghijk").Spec}}} // kvo-dev-pool-12-abcdefghijk = 28
	if err := e.admin.Create(e.ctx, set); code(err) != http.StatusUnprocessableEntity {
		t.Fatalf("set: %v", err)
	}
	set.Spec.Instances = 3 // pool-3: kvo-dev-pool-3-abcdefghijk = 27: still one too many
	set.Spec.Template.Volumes[0].Name = "abcdefghij"
	set.Spec.Template.Volumes[0].MountPath = "/abcdefghij"
	if err := e.admin.Create(e.ctx, set); err != nil { // 4+3+1+6+1+10 = 25
		t.Fatalf("set that fits: %v", err)
	}
}
