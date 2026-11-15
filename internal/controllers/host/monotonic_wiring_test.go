package host_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/store"
)

// The host controller records a contact with its clock's reading as it is: with the production
// clock, one that carries the monotonic reading, so Silence (what restarting a Stop silo
// elsewhere waits on) is never shortened by a wall-clock step. A reading passed through UTC,
// Truncate or Round would lose it.
func TestTheHostControllerRecordsContactsOnTheMonotonicClock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	defer cancel() // the informer first
	c := client.New(ts.URL)
	h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
	if err := c.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Truncate(time.Second).Add(-time.Hour) // the agent's clock, an hour behind
	h.Status.LastHeartbeat = &stamp
	if err := c.UpdateStatus(ctx, h); err != nil {
		t.Fatal(err)
	}
	hosts := informer.New(c, "Host")
	go hosts.Run(ctx)
	if !hosts.WaitSynced(ctx) {
		t.Fatal("never synced")
	}
	contacts := hostctl.NewContacts(clock.Real{}.Now())
	ctl := &hostctl.Controller{Client: c, Hosts: hosts, Clock: clock.Real{}, Lease: 40 * time.Second, Contacts: contacts}
	if _, err := ctl.Reconcile(ctx, engine.Key{Kind: "Host", Name: "hv1"}); err != nil {
		t.Fatal(err)
	}
	at := hostctl.ContactAt(contacts, "hv1")
	if at.IsZero() || !strings.Contains(at.String(), " m=") {
		t.Fatalf("contact recorded at %v: no monotonic reading", at)
	}
	if d := contacts.Silence("hv1", clock.Real{}.Now()); d < 0 || d > 10*time.Second {
		t.Fatalf("silence %v right after the contact (the stamp is an hour old: it must not count)", d)
	}
}
