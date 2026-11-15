package apiserver_test

import (
	"net/http"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
)

// K-037 (surface lane): a worker writes its own Host's status (heartbeats, runtimes), but
// status.provider is the control plane's provider-hosts controller's, from the plugin's
// DescribeHosts: a worker that rewrote it would name another machine for its volumes and its
// balancer backends. The control plane no longer acts on it (provider.Providers), but the API
// should refuse it too (403), as it refuses a silo's placement.
func TestK037AWorkerMayNotRewriteItsProvider(t *testing.T) {
	t.Skip("K-037: surface lane to fix (apiserver update: a worker's Host status write keeps status.provider as stored); see control-4.md")
	e := setupAuth(t)
	_ = e.admin.Create(e.ctx, host("hv2"))
	var h v1.Host
	if err := e.admin.Get(e.ctx, "Host", "", "hv2", &h); err != nil {
		t.Fatal(err)
	}
	h.Status.Provider = &v1.HostProvider{Name: "linode", ID: "1", Region: "ca-central"}
	if err := e.admin.UpdateStatus(e.ctx, &h); err != nil {
		t.Fatal(err)
	}
	tok, _ := e.tokens.Create(e.ctx, "hv2", []string{"worker"}, time.Hour)
	cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, "hv2", "worker")
	if err != nil {
		t.Fatal(err)
	}
	worker := e.tlsClient(t, &cred)
	if err := worker.Get(e.ctx, "Host", "", "hv2", &h); err != nil {
		t.Fatal(err)
	}
	h.Status.Conditions = nil // a heartbeat: allowed
	if err := worker.UpdateStatus(e.ctx, &h); err != nil {
		t.Fatalf("a worker's heartbeat: %v", err)
	}
	h.Status.Provider = &v1.HostProvider{Name: "linode", ID: "999", Region: "ca-central", PrivateAddress: "192.168.1.1"}
	if err := worker.UpdateStatus(e.ctx, &h); code(err) != http.StatusForbidden {
		t.Fatalf("a worker rewriting its status.provider: want 403, got %v", err)
	}
	if err := worker.Get(e.ctx, "Host", "", "hv2", &h); err != nil {
		t.Fatal(err)
	}
	h.Status.Provider = nil
	if err := worker.UpdateStatus(e.ctx, &h); code(err) != http.StatusForbidden {
		t.Fatalf("a worker clearing its status.provider: want 403, got %v", err)
	}
}
