package kvo

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
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

// netRig is an API server (no controllers: the tests write the statuses they need) with
// namespace mail and host baremetal-1, whose extra address mail is 203.0.113.21.
func netRig(t *testing.T) (context.Context, *client.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	t.Setenv("KVO_SERVER", ts.URL)
	t.Setenv("KVO_NAMESPACE", "")
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "mail"}}); err != nil {
		t.Fatal(err)
	}
	h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "baremetal-1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.6", ExternalIP: "203.0.113.20", Addresses: []v1.HostAddress{{Name: "mail", Kind: v1.NetworkExternal, Address: "203.0.113.21"}},
			Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
	if err := c.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	return ctx, c
}

func kvo(t *testing.T, ctx context.Context, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(ctx, args, strings.NewReader(""), &out, &errb)
	return out.String(), errb.String(), code
}

// wantIn checks got has each of want, with runs of spaces counted as one (columns move).
func wantIn(t *testing.T, what, got string, want ...string) {
	t.Helper()
	squeeze := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	for _, w := range want {
		if !strings.Contains(squeeze(got), squeeze(w)) {
			t.Errorf("%s: no %q in:\n%s", what, w, got)
		}
	}
}

// kvo create ip checks its flags before asking the server, and says the strict forms.
func TestCreateIPFlags(t *testing.T) {
	for _, c := range []struct {
		o    ipOpts
		want string
	}{
		{ipOpts{}, "needs a NAME and a --type"},
		{ipOpts{typ: "Pool"}, "Host or Provider"},
		{ipOpts{typ: v1.IPTypeHost}, "needs --host-address NAME"},
		{ipOpts{typ: v1.IPTypeHost, hostAddress: "mail", region: "us-ord"}, "--provider and --region are for --type Provider"},
		{ipOpts{typ: v1.IPTypeProvider, provider: "linode"}, "needs --provider PROVIDER and --region REGION"},
		{ipOpts{typ: v1.IPTypeProvider, provider: "linode", region: "us-ord", hostAddress: "mail"}, "--host-address is for --type Host"},
	} {
		_, err := ipSpecFromFlags(c.o)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "hostPort: { ip: NAME }") {
			t.Errorf("%+v: %v (want %q and the strict form)", c.o, err, c.want)
		}
	}
	if spec, err := ipSpecFromFlags(ipOpts{typ: v1.IPTypeProvider, provider: "linode", region: "us-ord"}); err != nil || spec.Provider != "linode" || spec.Region != "us-ord" {
		t.Fatalf("provider: %+v %v", spec, err)
	}
}

// The whole round on a real API: create a Host IP, a silo holds it, every layout shows it, and
// deleting it while held says who holds it (the server's 409, without the code).
func TestIPCommandsOnTheAPI(t *testing.T) {
	ctx, c := netRig(t)
	out, errs, code := kvo(t, ctx, "create", "ip", "mail", "-n", "mail", "--type", "Host", "--host-address", "mail")
	if code != 0 {
		t.Fatalf("create ip: %d %s", code, errs)
	}
	wantIn(t, "create ip", out, "ip/mail created", "hostPort: { ip: mail }")
	if _, errs, code := kvo(t, ctx, "create", "ip", "x", "-n", "mail", "--type", "Host"); code == 0 || !strings.Contains(errs, "--host-address") {
		t.Fatalf("create ip without --host-address: %d %s", code, errs)
	}

	silo := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "smtp", Namespace: "mail"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "mail:v1"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Ports: []v1.SiloPort{{Name: "smtp", Port: 25}, {Name: "https", Port: 8443}},
			Services: []v1.SiloService{
				{Name: "smtp", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "mail"}, Ports: []v1.ServicePort{{Port: "smtp"}}},
				{Name: "webmail", Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "https", As: 443}}},
			}}}
	if err := c.Create(ctx, silo); err != nil {
		t.Fatal(err)
	}
	var ip v1.IP
	if err := c.Get(ctx, "IP", "mail", "mail", &ip); err != nil {
		t.Fatal(err)
	}
	ip.Status = v1.IPStatus{Address: "203.0.113.21", Where: "host baremetal-1", Host: "baremetal-1",
		Holder: &v1.IPHolder{Holder: "silo/smtp", UID: silo.UID, Ports: []string{"25/TCP"}}}
	if err := c.UpdateStatus(ctx, &ip); err != nil {
		t.Fatal(err)
	}
	silo.Status.Host = "baremetal-1"
	silo.Status.Movable = "no: pinned to baremetal-1 (IP mail is that host's address)"
	if err := c.UpdateStatus(ctx, silo); err != nil {
		t.Fatal(err)
	}

	out, _, _ = kvo(t, ctx, "get", "ips", "-n", "mail")
	wantIn(t, "get ips", out, "TYPE", "ADDRESS", "WHERE", "SET", "USED BY", "MOVES",
		"Host", "203.0.113.21", "host baremetal-1", "silo/smtp (25/TCP)", "no: pinned to its host")
	out, _, _ = kvo(t, ctx, "describe", "ip", "mail", "-n", "mail")
	wantIn(t, "describe ip", out, "Host (host address mail)", "Used by:", "silo/smtp (25/TCP)", "refused while silo/smtp uses it")
	out, _, _ = kvo(t, ctx, "describe", "silo", "smtp", "-n", "mail")
	wantIn(t, "describe silo", out, "Can move: no: pinned to baremetal-1 (IP mail is that host's address)", "On host loss: Wait",
		"Services:", "smtp      HostPort  ip: mail", "203.0.113.21:25", "webmail", "worker: external", "https→443")
	out, _, _ = kvo(t, ctx, "describe", "host", "baremetal-1")
	wantIn(t, "describe host", out, "Addresses:", "(main)  external  IPv4    203.0.113.20  used by mail/smtp (webmail)",
		"mail    external  IPv4    203.0.113.21  ip mail/mail, used by silo/smtp (25/TCP)")

	_, errs, code = kvo(t, ctx, "delete", "ip", "mail", "-n", "mail")
	if code == 0 || strings.Contains(errs, "409") || !strings.Contains(errs, "IP mail is held by silo/smtp (25/TCP)") || !strings.Contains(errs, "delete that one first") {
		t.Fatalf("delete a held ip: %d %q", code, errs)
	}
	ip.Status.Holder = nil
	if err := c.Get(ctx, "IP", "mail", "mail", &ip); err != nil {
		t.Fatal(err)
	}
	ip.Status.Holder = nil
	if err := c.UpdateStatus(ctx, &ip); err != nil {
		t.Fatal(err)
	}
	if out, errs, code := kvo(t, ctx, "delete", "ip", "mail", "-n", "mail"); code != 0 || !strings.Contains(out, "ip/mail deleted") {
		t.Fatalf("delete a free ip: %d %s %s", code, out, errs)
	}
}

// kvo get ipsets and describe ipset on the API: a Static set with two members, one in use.
func TestIPSetCommandsOnTheAPI(t *testing.T) {
	ctx, c := netRig(t)
	set := &v1.IPSet{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IPSet"}, ObjectMeta: meta.ObjectMeta{Name: "relays", Namespace: "mail"},
		Spec: v1.IPSetSpec{Type: v1.IPSetStatic, Members: []v1.IPSetMember{{HostAddress: "mail"}, {IP: "relay-1"}}}}
	if err := c.Create(ctx, set); err != nil {
		t.Fatal(err)
	}
	set.Status.Members = []v1.IPSetMemberStatus{{Ordinal: 0, IP: "relays-0", Address: "203.0.113.21", UsedBy: "relay-0"}}
	if err := c.UpdateStatus(ctx, set); err != nil {
		t.Fatal(err)
	}
	out, _, _ := kvo(t, ctx, "get", "ipsets", "-n", "mail")
	wantIn(t, "get ipsets", out, "TYPE      MEMBERS   USED   MAX", "relays   Static    2         1      2")
	out, _, _ = kvo(t, ctx, "describe", "ipset", "relays", "-n", "mail")
	wantIn(t, "describe ipset", out, "Static (the members listed", "Used by:    -",
		"0        hostAddress: mail  relays-0  203.0.113.21  relay-0", "1        ip: relay-1        relay-1   -")
}

// A manifest in an older shape is refused with the strict form beside the decode error.
func TestApplyOldNetworkingShapes(t *testing.T) {
	ctx, _ := netRig(t)
	head := "apiVersion: kevaso/v1\nkind: Silo\nmetadata: {name: a, namespace: mail}\nspec:\n  runtime: docker\n  container: {image: x}\n  ports: [{name: http, port: 80}]\n"
	for name, y := range map[string]string{
		"service":         head + "  service:\n    ports: [{port: http}]\n",
		"per-port":        head + "  services:\n  - ports: [{port: http, hostPort: [external]}]\n",
		"string hostPort": head + "  services:\n  - type: HostPort\n    hostPort: external\n    ports: [{port: http}]\n",
		"ip class":        "apiVersion: kevaso/v1\nkind: IP\nmetadata: {name: a, namespace: mail}\nspec: {class: ip-pool}\n",
	} {
		f := t.TempDir() + "/a.yaml"
		if err := os.WriteFile(f, []byte(y), 0o644); err != nil {
			t.Fatal(err)
		}
		_, errs, code := kvo(t, ctx, "apply", "-f", f)
		want := "hostPort: { ip: NAME }"
		if name == "ip class" {
			want = "spec: { type: Host, hostAddress: NAME }"
		}
		if code == 0 || !strings.Contains(errs, want) {
			t.Errorf("%s: %d %s", name, code, errs)
		}
	}
	// The server's own refusal already says the fix: two ways in inside one service.
	f := t.TempDir() + "/b.yaml"
	if err := os.WriteFile(f, []byte(head+"  services:\n  - type: HostPort\n    hostPort: {ip: x, worker: external}\n    ports: [{port: http}]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, errs, code := kvo(t, ctx, "apply", "-f", f); code == 0 || !strings.Contains(errs, "make a service for each") {
		t.Errorf("two ways in: %d %s", code, errs)
	}
}
