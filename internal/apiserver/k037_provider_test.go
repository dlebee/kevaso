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

// K-037, next to it: the mesh addresses of a host's status.network are assigned by the host
// controller; a worker may publish its keys but not rewrite index, meshIP, siloSubnet or innerIP.
func TestK037AWorkerMayNotRewriteItsMeshAddresses(t *testing.T) {
	e := setupAuth(t)
	_ = e.admin.Create(e.ctx, host("hv2"))
	var h v1.Host
	if err := e.admin.Get(e.ctx, "Host", "", "hv2", &h); err != nil {
		t.Fatal(err)
	}
	h.Status.Network = v1.NetworkStatus{Index: 3, MeshIP: "10.63.0.3", SiloSubnet: "10.64.3.0/24", InnerIP: "10.65.0.3"}
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
	h.Status.Network.PublicKey = "k"
	if err := worker.UpdateStatus(e.ctx, &h); err != nil {
		t.Fatalf("a worker publishing its key: %v", err)
	}
	for name, mut := range map[string]func(*v1.NetworkStatus){
		"index":      func(n *v1.NetworkStatus) { n.Index = 4 },
		"meshIP":     func(n *v1.NetworkStatus) { n.MeshIP = "10.63.0.4" },
		"siloSubnet": func(n *v1.NetworkStatus) { n.SiloSubnet = "10.64.0.0/16" },
		"innerIP":    func(n *v1.NetworkStatus) { n.InnerIP = "10.65.0.4" },
	} {
		if err := worker.Get(e.ctx, "Host", "", "hv2", &h); err != nil {
			t.Fatal(err)
		}
		mut(&h.Status.Network)
		if err := worker.UpdateStatus(e.ctx, &h); code(err) != http.StatusForbidden {
			t.Fatalf("a worker rewriting network.%s: want 403, got %v", name, err)
		}
	}
}
