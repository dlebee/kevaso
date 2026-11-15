package apiserver_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Review batch 3, item 1: what a worker may write in its own Host's status, and what bounds it.
// lastHeartbeat is stamped by the server when it receives one (a stamp far in the future would
// keep a host from ever being lost); controlPlane is the control plane's; a public key once
// published is changed only by joining again; a large step in what the host offers is recorded
// in a condition the worker can't remove.
func TestAWorkersHostStatusIsBoundedPerField(t *testing.T) {
	e := setupAuth(t)
	_ = e.admin.Create(e.ctx, host("hv2"))
	var h v1.Host
	if err := e.admin.Get(e.ctx, "Host", "", "hv2", &h); err != nil {
		t.Fatal(err)
	}
	h.Status.ControlPlane = &v1.ControlPlaneStatus{APIURL: "https://10.0.0.2:6443", DNSSuffix: "kevaso"}
	h.Status.Allocatable = v1.Resources{CPU: 8, Memory: "16Gi"}
	if err := e.admin.UpdateStatus(e.ctx, &h); err != nil {
		t.Fatal(err)
	}
	tok, _ := e.tokens.Create(e.ctx, "hv2", []string{"worker"}, time.Hour)
	cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, "hv2", "worker")
	if err != nil {
		t.Fatal(err)
	}
	worker := e.tlsClient(t, &cred)
	write := func(f func(*v1.Host)) error {
		var cur v1.Host
		if err := worker.Get(e.ctx, "Host", "", "hv2", &cur); err != nil {
			t.Fatal(err)
		}
		f(&cur)
		return worker.UpdateStatus(e.ctx, &cur)
	}
	stored := func() v1.Host {
		var cur v1.Host
		if err := e.admin.Get(e.ctx, "Host", "", "hv2", &cur); err != nil {
			t.Fatal(err)
		}
		return cur
	}

	// lastHeartbeat: the server's clock on receipt, never the body's.
	before := time.Now().Add(-time.Second)
	future := time.Now().Add(1000 * time.Hour)
	if err := write(func(x *v1.Host) { x.Status.LastHeartbeat = &future }); err != nil {
		t.Fatal(err)
	}
	if hb := stored().Status.LastHeartbeat; hb == nil || hb.After(time.Now().Add(time.Second)) || hb.Before(before.Truncate(time.Second)) {
		t.Fatalf("lastHeartbeat %v stored as written, not stamped on receipt", hb)
	}
	// controlPlane: kept.
	if err := write(func(x *v1.Host) {
		x.Status.ControlPlane = &v1.ControlPlaneStatus{APIURL: "https://evil:6443", DNSSuffix: "evil"}
	}); err != nil {
		t.Fatal(err)
	}
	if cp := stored().Status.ControlPlane; cp == nil || cp.APIURL != "https://10.0.0.2:6443" || cp.DNSSuffix != "kevaso" {
		t.Fatalf("controlPlane rewritten by a worker: %+v", cp)
	}
	// Keys: published once; a change is a re-key, refused.
	if err := write(func(x *v1.Host) { x.Status.Network.PublicKey, x.Status.Network.InnerPublicKey = "k1", "i1" }); err != nil {
		t.Fatalf("publishing its keys: %v", err)
	}
	if err := write(func(x *v1.Host) { x.Status.Network.PublicKey = "k2" }); code(err) != http.StatusForbidden || !strings.Contains(err.Error(), "join") {
		t.Fatalf("changing a published key: %v, want 403 saying to join again", err)
	}
	if err := write(func(x *v1.Host) { x.Status.Network.InnerPublicKey = "i2" }); code(err) != http.StatusForbidden {
		t.Fatalf("changing a published inner key: %v, want 403", err)
	}
	// Capacity: a large step is recorded, and the worker can't take the record away.
	if err := write(func(x *v1.Host) { x.Status.Allocatable = v1.Resources{CPU: 800, Memory: "16Gi"} }); err != nil {
		t.Fatal(err)
	}
	c := meta.FindCondition(stored().Status.Conditions, "ReportedChange")
	if c == nil || !strings.Contains(c.Message, "8 → 800") {
		t.Fatalf("a hundredfold capacity isn't recorded: %+v", c)
	}
	if err := write(func(x *v1.Host) {
		x.Status.Conditions = nil
		x.Status.MountClasses = []string{"juicefs"}
	}); err != nil {
		t.Fatal(err)
	}
	c = meta.FindCondition(stored().Status.Conditions, "ReportedChange")
	if c == nil || !strings.Contains(c.Message, "juicefs") {
		t.Fatalf("a new mount class isn't recorded, or the worker removed the record: %+v", c)
	}
}

// …and a silo placed on a host gets an address only inside the subnet the control plane
// assigned that host, or the default network of a host without the mesh (ingress routes to it).
func TestAHostsSiloIPIsInsideItsSubnet(t *testing.T) {
	e := setupAuth(t)
	_ = e.admin.Create(e.ctx, ns("dev"))
	_ = e.admin.Create(e.ctx, host("hv2"))
	var h v1.Host
	_ = e.admin.Get(e.ctx, "Host", "", "hv2", &h)
	h.Status.Network = v1.NetworkStatus{Index: 3, MeshIP: "10.63.0.3", SiloSubnet: "10.64.3.0/24", InnerIP: "10.62.0.3"}
	if err := e.admin.UpdateStatus(e.ctx, &h); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor"}}
	if err := e.admin.Create(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv2", "Starting"
	if err := e.admin.UpdateStatus(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	tok, _ := e.tokens.Create(e.ctx, "hv2", []string{"worker"}, time.Hour)
	cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, "hv2", "worker")
	if err != nil {
		t.Fatal(err)
	}
	worker := e.tlsClient(t, &cred)
	set := func(ip string) error {
		var cur v1.Silo
		_ = worker.Get(e.ctx, "Silo", "dev", "web", &cur)
		cur.Status.SiloIP, cur.Status.Phase = ip, "Running"
		return worker.UpdateStatus(e.ctx, &cur)
	}
	if err := set("10.64.3.7"); err != nil {
		t.Fatalf("an address in its subnet: %v", err)
	}
	if err := set("10.64.0.7"); err != nil {
		t.Fatalf("an address on the default network (a host without the mesh): %v", err)
	}
	if err := set("10.64.9.7"); code(err) != http.StatusForbidden {
		t.Fatalf("an address outside its subnet: %v, want 403", err)
	}
	_ = client.IsConflict
}
