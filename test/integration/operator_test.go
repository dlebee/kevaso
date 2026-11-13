package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/examples/operator-session/session"
	"kevaso.com/core/internal/operators"
	"kevaso.com/core/sdk/operator"
)

// fakeHost runs a plugin's controller in the test instead of as a systemd unit over SSH: it writes
// the credentials it's given where systemd would ($CREDENTIALS_DIRECTORY, $STATE_DIRECTORY) and
// starts the example's controller program on them.
type fakeHost struct {
	t       *testing.T
	mu      sync.Mutex
	stop    context.CancelFunc
	done    chan struct{}
	creds   map[string][]byte
	stopped bool
}

func (h *fakeHost) Address() string { return "cp1.example.test" }

func (h *fakeHost) Start(_ context.Context, c operators.Controller) error {
	dir, state := h.t.TempDir(), h.t.TempDir()
	for name, b := range c.Credentials {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o400); err != nil {
			return err
		}
	}
	creds, err := operator.Load(dir, state)
	if err != nil {
		return err
	}
	_ = h.Stop(context.Background(), c.Plugin) // an upgrade replaces the running one
	ctx, cancel := context.WithCancel(context.Background())
	h.mu.Lock()
	h.stop, h.done, h.creds, h.stopped = cancel, make(chan struct{}), c.Credentials, false
	h.mu.Unlock()
	go func() {
		defer close(h.done)
		if err := session.Main(ctx, creds); err != nil {
			h.t.Errorf("controller: %v", err)
		}
	}()
	return nil
}

func (h *fakeHost) Stop(context.Context, string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stop != nil {
		h.stop()
		<-h.done
		h.stop = nil
	}
	h.stopped = true
	return nil
}

func eventually(t *testing.T, ctx context.Context, what string, ok func() bool) {
	t.Helper()
	for !ok() {
		select {
		case <-ctx.Done():
			t.Fatalf("%s: never happened", what)
		case <-time.After(30 * time.Millisecond):
		}
	}
}

// M17's plugin operators (design §4.2, §6; ADR 0006), end to end in one process: the example
// operator's package is installed through the same code as kvoadm plugin install (the host
// faked), its controller runs as its own service account and turns a Session into silos with a
// status, scales it, and the plugin can't be uninstalled while sessions exist.
func TestPluginOperator(t *testing.T) {
	c := newCluster(t)
	ctx := c.ctx
	pkg, err := operators.Load("../../examples/operator-session")
	if err != nil {
		t.Fatal(err)
	}
	host := &fakeHost{t: t}
	var summary string
	in := &operators.Installer{API: c.admin, Server: c.url, CA: c.ca, Wait: 5 * time.Second,
		Confirm: func(s string) bool { summary = s; return true }}
	t.Cleanup(func() { _ = host.Stop(context.Background(), "sessions") })

	refused := &operators.Installer{API: c.admin, Server: c.url, CA: c.ca, Confirm: func(string) bool { return false }}
	if err := refused.Install(ctx, pkg, host, operators.InstallOptions{}); err == nil || host.creds != nil {
		t.Fatalf("installed without a yes: %v", err)
	}
	if err := in.Install(ctx, pkg, host, operators.InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Plugin sessions 0.1.0", "sessiontemplates.example.dev, sessions.example.dev", "ValidationPolicy sessions-not-in-system",
		"as kevaso-system/plugin-sessions", "get list watch create delete", "silos, in every namespace", "serviceaccounts/token (only plugin-sessions)"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q:\n%s", want, summary)
		}
	}
	// The controller holds a token for its own service account, never the admin's: it can't do
	// what its roles don't say.
	if strings.Contains(string(host.creds["token.json"]), "admin") || len(host.creds["ca.pem"]) == 0 {
		t.Errorf("credentials: %q", host.creds["plugin.json"])
	}
	creds, _ := operator.Load(writeCreds(t, host.creds), t.TempDir())
	asPlugin, err := creds.Client(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := asPlugin.List(ctx, "Secret", "kevaso-system"); status(err) != 403 {
		t.Errorf("the plugin listing secrets: %v", err)
	}
	if err := asPlugin.Create(ctx, &v1.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "escalate"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: "plugin-sessions", Namespace: "kevaso-system"}}}); status(err) != 403 {
		t.Errorf("the plugin making itself cluster-admin: %v", err)
	}

	// Ownership: the definitions belong to the Plugin, and can't be deleted on their own.
	var kd v1.KindDefinition
	if err := c.admin.Get(ctx, "KindDefinition", "", "sessions.example.dev", &kd); err != nil || v1.OwnerPlugin(&kd.ObjectMeta) != "sessions" {
		t.Fatalf("definition: owner %q, %v", v1.OwnerPlugin(&kd.ObjectMeta), err)
	}
	if err := c.admin.Delete(ctx, "KindDefinition", "", "sessions.example.dev"); status(err) != 409 || !strings.Contains(err.Error(), "belongs to plugin sessions") {
		t.Errorf("deleting a plugin's definition directly: %v", err)
	}
	// Installing again is an upgrade in place; another package can't take its objects.
	if err := in.Install(ctx, pkg, host, operators.InstallOptions{}); err != nil {
		t.Fatalf("installing again: %v", err)
	}

	// A session becomes a silo and a status.
	_ = c.admin.Create(ctx, ns("dev"))
	if err := c.admin.Create(ctx, fromYAML(t, `apiVersion: example.dev/v1
kind: SessionTemplate
metadata: { name: claude, namespace: dev }
spec:
  silo: { runtime: cloud-hypervisor, image: ubuntu-24.04, resources: { cpu: 2, memory: 4Gi } }
`)); err != nil {
		t.Fatal(err)
	}
	sess := fromYAML(t, `apiVersion: example.dev/v1
kind: Session
metadata: { name: fix-login, namespace: dev }
spec: { template: claude, prompt: find the bug }
`)
	if err := c.admin.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	get := func() *session.Session {
		var u v1.Unstructured
		var s session.Session
		if err := c.admin.Get(ctx, session.Sessions, "dev", "fix-login", &u); err != nil || u.Into(&s) != nil {
			return nil
		}
		return &s
	}
	eventually(t, ctx, "the session's silo and status", func() bool {
		s := get()
		return s != nil && s.Status.Replicas == 1 && s.Status.Phase == "Starting" && len(s.Status.Silos) == 1 && s.Status.ObservedGeneration == s.Generation
	})
	var silo v1.Silo
	if err := c.admin.Get(ctx, "Silo", "dev", "fix-login-0", &silo); err != nil {
		t.Fatal(err)
	}
	if silo.Labels[session.SessionLabel] != "fix-login" || silo.Annotations[session.PromptAnnotation] != "find the bug" || silo.Spec.Resources.CPU != 2 {
		t.Errorf("silo from the template: %+v", silo.ObjectMeta)
	}
	if got := get(); !strings.Contains(strings.Join(got.Finalizers, ","), session.Finalizer) {
		t.Errorf("finalizers %v", got.Finalizers)
	}
	// The controller reports in: kvoadm plugin list sees it running.
	eventually(t, ctx, "a heartbeat", func() bool {
		l, err := in.List(ctx, time.Now())
		return err == nil && len(l) == 1 && l[0].Running && l[0].Host == "cp1.example.test" && strings.Join(l[0].Kinds, ",") == "sessions.example.dev,sessiontemplates.example.dev"
	})

	// Scale (the definition declares it), and the transition rule on the template.
	sc, err := c.admin.GetScale(ctx, session.Sessions, "dev", "fix-login")
	if err != nil || sc.Spec.Replicas != 1 || sc.Status.Replicas != 1 {
		t.Fatalf("scale: %+v %v", sc, err)
	}
	sc.Spec.Replicas = 3
	if err := c.admin.UpdateScale(ctx, session.Sessions, sc); err != nil {
		t.Fatal(err)
	}
	eventually(t, ctx, "three silos", func() bool { s := get(); return s != nil && s.Status.Replicas == 3 })
	sc.Spec.Replicas, sc.ResourceVersion = 11, ""
	if err := c.admin.UpdateScale(ctx, session.Sessions, sc); !client.IsInvalid(err) {
		t.Errorf("scaling past the schema's maximum: %v", err)
	}
	u, _ := v1.ToUnstructured(sess)
	_ = c.admin.Get(ctx, session.Sessions, "dev", "fix-login", u)
	u.Fields["spec"].(map[string]any)["template"] = "other"
	if err := c.admin.Update(ctx, u); !client.IsInvalid(err) || !strings.Contains(err.Error(), "template can't change") {
		t.Errorf("changing a session's template: %v", err)
	}
	// The plugin's policy.
	_ = c.admin.Create(ctx, ns("kevaso-system"))
	sys := fromYAML(t, "apiVersion: example.dev/v1\nkind: Session\nmetadata: { name: x, namespace: kevaso-system }\nspec: { template: claude }\n")
	if err := c.admin.Create(ctx, sys); !client.IsInvalid(err) || !strings.Contains(err.Error(), "not kevaso-system") {
		t.Errorf("a session in kevaso-system: %v", err)
	}

	// Uninstall: refused while sessions exist, done once they're gone.
	hostFor := func(addr string) (operators.Host, error) {
		if addr != host.Address() {
			t.Errorf("uninstall reached for %q", addr)
		}
		return host, nil
	}
	if err := in.Uninstall(ctx, "sessions", hostFor, false); err == nil || !strings.Contains(err.Error(), "1 sessions.example.dev") {
		t.Fatalf("uninstall with a session left: %v", err)
	}
	if host.stopped {
		t.Fatal("a refused uninstall stopped the controller")
	}
	if err := c.admin.Delete(ctx, session.Sessions, "dev", "fix-login"); err != nil {
		t.Fatal(err)
	}
	eventually(t, ctx, "the session and its silos gone", func() bool {
		l, _ := c.admin.List(ctx, "Silo", "dev")
		return get() == nil && l != nil && len(l.Items) == 0
	})
	if err := c.admin.Delete(ctx, session.Templates, "dev", "claude"); err != nil {
		t.Fatal(err)
	}
	if err := in.Uninstall(ctx, "sessions", hostFor, false); err != nil {
		t.Fatal(err)
	}
	if !host.stopped {
		t.Error("the controller still runs")
	}
	for _, gone := range []struct{ kind, ns, name string }{
		{"KindDefinition", "", "sessions.example.dev"}, {"KindDefinition", "", "sessiontemplates.example.dev"},
		{"ValidationPolicy", "", "sessions-not-in-system"}, {"ClusterRole", "", "sessions-controller"},
		{"ClusterRoleBinding", "", "sessions-controller"}, {"ServiceAccount", "kevaso-system", "plugin-sessions"}, {"Plugin", "", "sessions"},
	} {
		obj, _ := v1.Lookup(gone.kind)
		if err := c.admin.Get(ctx, gone.kind, gone.ns, gone.name, obj.New()); !client.IsNotFound(err) {
			t.Errorf("%s %s after uninstall: %v", gone.kind, gone.name, err)
		}
	}
	// Its token died with its service account.
	if _, err := asPlugin.List(ctx, "Silo", "dev"); status(err) != 401 {
		t.Errorf("the plugin's token after uninstall: %v", err)
	}
}

func writeCreds(t *testing.T, creds map[string][]byte) string {
	dir := t.TempDir()
	for n, b := range creds {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// kvo scale works on a defined kind whose definition declares the scale subresource.
func TestKvoScaleDefinedKind(t *testing.T) {
	h := newHarness(t)
	kinds, err := os.ReadFile("../../examples/operator-session/kinds.yaml")
	if err != nil {
		t.Fatal(err)
	}
	h.ok("apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: demo }\n---\n"+string(kinds), "apply", "-f", "-")
	h.ok("apiVersion: example.dev/v1\nkind: Session\nmetadata: { name: s1 }\nspec: { template: t }\n", "apply", "-f", "-", "-n", "demo")
	if out := h.ok("", "scale", "session", "s1", "--replicas", "4", "-n", "demo"); !strings.Contains(out, "sessions.example.dev/s1 scaled to 4") {
		t.Errorf("kvo scale:\n%s", out)
	}
	if out := h.ok("", "get", "sessions", "-n", "demo"); !strings.Contains(out, "4") {
		t.Errorf("get after scale:\n%s", out)
	}
	if _, errOut, code := h.kvo(context.Background(), "", "scale", "sessiontemplates", "t", "--replicas", "2", "-n", "demo"); code == 0 || !strings.Contains(errOut, "no scale subresource") {
		t.Errorf("kvo scale on a kind without scale: %d %s", code, errOut)
	}
}
