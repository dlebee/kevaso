package kvoadm

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

func squeeze(s string) string { return strings.Join(strings.Fields(s), " ") }

// kvoadm host addresses on a real API: add, list (main addresses too, and who reserves each),
// a reserved address can't be removed (it says which IP and who uses it), a free one can.
func TestHostAddressesOnTheAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "mail"}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"baremetal-1", "baremetal-2"} {
		if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{InternalIP: "10.0.0.6", ExternalIP: "203.0.113.20", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	run := func(host, op string, args ...string) error {
		out.Reset()
		return editHostAddresses(ctx, c, host, op, args, &out)
	}
	if err := run("baremetal-1", "list"); err != nil || !strings.Contains(out.String(), "(no extra addresses: kvoadm host addresses baremetal-1 add NAME ADDRESS --external)") {
		t.Fatalf("empty list: %v\n%s", err, out.String())
	}
	if err := run("baremetal-1", "add", "mail", "203.0.113.21", "--external"); err != nil || !strings.Contains(out.String(), "baremetal-1's extra addresses: mail 203.0.113.21") {
		t.Fatalf("add: %v %s", err, out.String())
	}
	if err := run("baremetal-1", "add", "spare", "10.0.0.66", "--internal"); err != nil {
		t.Fatal(err)
	}
	// Names are unique in the cluster: the server refuses another host's mail, and says why.
	if err := run("baremetal-2", "add", "mail", "203.0.113.30", "--external"); err == nil || strings.Contains(err.Error(), "409") || !strings.Contains(err.Error(), "mail") {
		t.Fatalf("a second mail: %v", err)
	}

	ip := &v1.IP{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IP"}, ObjectMeta: meta.ObjectMeta{Name: "mail", Namespace: "mail"},
		Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail"}}
	if err := c.Create(ctx, ip); err != nil {
		t.Fatal(err)
	}
	ip.Status = v1.IPStatus{Address: "203.0.113.21", Host: "baremetal-1", Holder: &v1.IPHolder{Holder: "silo/smtp", UID: "u1", Ports: []string{"25/TCP"}}}
	if err := c.UpdateStatus(ctx, ip); err != nil {
		t.Fatal(err)
	}
	if err := run("baremetal-1", "list"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"NAME KIND ADDRESS RESERVED BY",
		"(main) external 203.0.113.20 the worker's (hostPort: { worker: external })",
		"(main) internal 10.0.0.6 the worker's (hostPort: { worker: internal })",
		"mail external 203.0.113.21 ip mail/mail, used by silo/smtp (25/TCP)",
		"spare internal 10.0.0.66 -",
	} {
		if !strings.Contains(squeeze(out.String()), want) {
			t.Errorf("list: no %q in\n%s", want, out.String())
		}
	}
	err = run("baremetal-1", "remove", "mail")
	if err == nil || !strings.Contains(err.Error(), "address mail is reserved by IP mail/mail (used by silo/smtp (25/TCP))") || !strings.Contains(err.Error(), "kvo delete ip mail -n mail") {
		t.Fatalf("remove a reserved address: %v", err)
	}
	if err := run("baremetal-1", "remove", "spare"); err != nil || !strings.Contains(out.String(), "extra addresses: mail 203.0.113.21") {
		t.Fatalf("remove a free address: %v %s", err, out.String())
	}
	if err := run("baremetal-1", "rename", "x"); err == nil || !strings.Contains(err.Error(), "add NAME ADDRESS --external|--internal") || !strings.Contains(err.Error(), "hostPort: { ip: IPNAME }") {
		t.Fatalf("unknown op: %v", err)
	}
}
