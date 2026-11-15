package apiserver_test

import (
	"net/http"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
)

// A worker writes its Host's status from its own copy. Driven here in the order that left a
// system node's worker never reporting its Host: the worker reads; the control plane rewrites the
// fields it owns (the host controller puts back the addresses of the index, the provider-hosts
// controller its provider); the worker writes its copy. That write is stale: a conflict (409), to
// read again and retry, never a refusal (403) the worker can't get past. And a write from a fresh
// copy is never refused for the control plane's fields: they are kept as stored, whatever it sends.
func TestAWorkersStaleHostWriteIsAConflictAndOwnedFieldsAreKept(t *testing.T) {
	e := setupAuth(t)
	_ = e.admin.Create(e.ctx, host("hv2"))
	var h v1.Host
	if err := e.admin.Get(e.ctx, "Host", "", "hv2", &h); err != nil {
		t.Fatal(err)
	}
	h.Status.Network = v1.NetworkStatus{Index: 3, MeshIP: "10.63.0.3", SiloSubnet: "10.64.3.0/24", InnerIP: "10.62.0.3"}
	h.Status.Provider = &v1.HostProvider{Name: "linode", ID: "1", Region: "r"}
	if err := e.admin.UpdateStatus(e.ctx, &h); err != nil {
		t.Fatal(err)
	}
	tok, _ := e.tokens.Create(e.ctx, "hv2", []string{"worker"}, time.Hour)
	cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, "hv2", "worker")
	if err != nil {
		t.Fatal(err)
	}
	worker := e.tlsClient(t, &cred)

	var mine v1.Host // the worker's read
	if err := worker.Get(e.ctx, "Host", "", "hv2", &mine); err != nil {
		t.Fatal(err)
	}
	// The control plane writes in between.
	if err := e.admin.Get(e.ctx, "Host", "", "hv2", &h); err != nil {
		t.Fatal(err)
	}
	h.Status.Network.MeshIP = "10.63.0.33"
	if err := e.admin.UpdateStatus(e.ctx, &h); err != nil {
		t.Fatal(err)
	}
	// The worker's write of its stale copy: a conflict.
	mine.Status.Allocatable = v1.Resources{CPU: 3}
	if err := worker.UpdateStatus(e.ctx, &mine); code(err) != http.StatusConflict {
		t.Fatalf("a worker's stale Host write: %v, want 409 (read again), not a refusal", err)
	}
	// Read again, written: accepted.
	if err := worker.Get(e.ctx, "Host", "", "hv2", &mine); err != nil {
		t.Fatal(err)
	}
	mine.Status.Allocatable = v1.Resources{CPU: 3}
	if err := worker.UpdateStatus(e.ctx, &mine); err != nil {
		t.Fatalf("after reading again: %v", err)
	}
	// A fresh copy that changes the control plane's fields: accepted, those fields kept.
	if err := worker.Get(e.ctx, "Host", "", "hv2", &mine); err != nil {
		t.Fatal(err)
	}
	mine.Status.Network.MeshIP, mine.Status.Network.Index, mine.Status.Network.PublicKey = "10.63.0.99", 9, "k"
	mine.Status.Provider = &v1.HostProvider{Name: "linode", ID: "999"}
	mine.Status.Allocatable = v1.Resources{CPU: 2}
	if err := worker.UpdateStatus(e.ctx, &mine); err != nil {
		t.Fatalf("a write that carries other values for the control plane's fields: %v, want accepted", err)
	}
	if err := e.admin.Get(e.ctx, "Host", "", "hv2", &h); err != nil {
		t.Fatal(err)
	}
	n := h.Status.Network
	if n.MeshIP != "10.63.0.33" || n.Index != 3 || h.Status.Provider == nil || h.Status.Provider.ID != "1" {
		t.Fatalf("the control plane's fields were changed by the worker: %+v %+v", n, h.Status.Provider)
	}
	if n.PublicKey != "k" || h.Status.Allocatable.CPU != 2 {
		t.Fatalf("the worker's own fields weren't written: %+v %+v", n, h.Status.Allocatable)
	}
}
