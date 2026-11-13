package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/container"
	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/guest"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// pullHost is a host with a container engine that only pulls: it records each pull's command and
// the auth file it was pointed at, as it was during the pull, and keeps files in memory.
type pullHost struct {
	mu     sync.Mutex
	files  map[string][]byte
	pulls  []pullSeen
	digest string
}

type pullSeen struct {
	args string
	auth string // the user:password in the auth file, decoded ("" without one)
}

func (h *pullHost) Run(_ context.Context, c hostexec.Cmd) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a := c.Args
	switch {
	case len(a) > 0 && a[len(a)-2] != "inspect" && strings.Contains(strings.Join(a, " "), "pull --quiet"):
		seen := pullSeen{args: c.Name + " " + strings.Join(a, " ")}
		for p, b := range h.files {
			if strings.HasPrefix(p, container.PullDir+"/") {
				var cfg struct {
					Auths map[string]struct{ Auth string } `json:"auths"`
				}
				_ = json.Unmarshal(b, &cfg)
				for _, v := range cfg.Auths {
					d, _ := base64.StdEncoding.DecodeString(v.Auth)
					seen.auth = string(d)
				}
			}
		}
		h.pulls = append(h.pulls, seen)
		if strings.Contains(a[len(a)-1], "denied") {
			_, _ = io.WriteString(c.Stderr, "Error response from daemon: unauthorized: authentication required")
			return 1, nil
		}
	case len(a) > 3 && a[0] == "image" && a[1] == "inspect":
		ref := a[len(a)-1]
		r, _ := v1.ParseImageRef(ref)
		_, _ = io.WriteString(c.Stdout, `["`+r.Registry+"/"+r.Repository+"@"+h.digest+`"]`)
	}
	return 0, nil
}

func (h *pullHost) WriteFile(p string, d []byte, _ os.FileMode) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files[p] = append([]byte(nil), d...)
	return nil
}
func (h *pullHost) ReadFile(p string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if b, ok := h.files[p]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}
func (h *pullHost) RemoveAll(p string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k := range h.files {
		if k == p || strings.HasPrefix(k, p+"/") {
			delete(h.files, k)
		}
	}
	return nil
}
func (h *pullHost) Glob(string) ([]string, error) { return nil, nil }

func (h *pullHost) seen() ([]pullSeen, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	left := 0
	for p := range h.files {
		if strings.HasPrefix(p, container.PullDir) {
			left++
		}
	}
	return append([]pullSeen(nil), h.pulls...), left
}

// pulling is the fake runtime with the docker runtime's real Pull on a pullHost.
type pulling struct {
	*fake.Runtime
	puller *container.Runtime
}

func (p pulling) Pull(ctx context.Context, id kri.ID, image string, auth *kri.RegistryAuth) (string, error) {
	return p.puller.Pull(ctx, id, image, auth)
}

// Private registries end to end in one process (design §0.2): naming a pull secret needs use on
// it; the credential reaches only the agent of the silo's host, for that silo's pull, through a
// throwaway auth file that's gone after; another host and the silo itself never get it; a rotated
// value is the next pull's; a namespace default applies by registry host; a refused pull is
// ImagePullFailed with the registry's reason; OpenShell takes no credential.
func TestPrivateRegistryPull(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithTimeout(c.ctx, 60*time.Second)
	defer cancel()
	_ = c.admin.Create(ctx, ns("web3"))
	if err := c.admin.Create(ctx, &v1.Role{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Role"},
		ObjectMeta: meta.ObjectMeta{Name: "builder", Namespace: "web3"}, Rules: []v1.PolicyRule{
			{Verbs: []string{"get", "list", "watch", "create", "update", "delete"}, Resources: []string{"silos", "silosets"}},
		}}); err != nil {
		t.Fatal(err)
	}
	c.bind(t, "ada", "ClusterRole", "admin")
	c.bind(t, "ed", "Role", "builder")
	ada, ed := c.as(t, "ada"), c.as(t, "ed")

	registry := func(name, server, value string, def bool) *v1.Secret {
		s := secretObj(name, nil, value)
		s.Spec.Type, s.Spec.Server, s.Spec.Username = v1.SecretRegistry, server, "bot"
		if def {
			s.Labels = map[string]string{v1.LabelDefaultPull: "true"}
		}
		return s
	}
	if err := ada.Create(ctx, registry("ghcr-pull", "ghcr.io", "tok-1", false)); err != nil {
		t.Fatal(err)
	}
	if err := ada.Create(ctx, registry("hub", "docker.io", "hub-tok", true)); err != nil {
		t.Fatal(err)
	}
	var raw json.RawMessage
	if err := ada.Call(ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/ghcr-pull/value", nil, &raw); status(err) != http.StatusForbidden {
		t.Fatalf("a registry secret read back (it's write-only by default): %s %v", raw, err)
	}
	if err := ada.Create(ctx, registry("hub-2", "registry-1.docker.io", "x", true)); status(err) != http.StatusConflict {
		t.Fatalf("a second default for docker.io: %v", err)
	}
	if err := ada.Create(ctx, grantObj("leak", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "ghcr-pull"}}})); !client.IsInvalid(err) {
		t.Fatalf("a grant handing a registry secret to a silo: %v", err)
	}

	api := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "web3"},
		Spec: v1.SiloSpec{Runtime: "docker", Image: "ghcr.io/acme/api:v1", ImagePull: &v1.ImagePull{SecretRef: "ghcr-pull"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
	if err := ed.Create(ctx, api); status(err) != http.StatusForbidden || !strings.Contains(err.Error(), "may not use secret ghcr-pull") {
		t.Fatalf("naming a pull secret without use on it: %v", err)
	}
	set := &v1.SiloSet{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "SiloSet"}, ObjectMeta: meta.ObjectMeta{Name: "pool", Namespace: "web3"},
		Spec: v1.SiloSetSpec{Instances: 0, Template: v1.SiloTemplate{SiloSpec: api.Spec}}}
	if err := ed.Create(ctx, set); status(err) != http.StatusForbidden {
		t.Fatalf("a set naming a pull secret without use on it: %v", err)
	}
	for what, bad := range map[string]struct {
		spec v1.SiloSpec
		msg  string
	}{
		"openshell":  {v1.SiloSpec{Runtime: "openshell-container", Image: "ghcr.io/acme/api:v1", ImagePull: &v1.ImagePull{SecretRef: "ghcr-pull"}}, "isn't available on openshell-container"},
		"wrong host": {v1.SiloSpec{Runtime: "docker", Image: "quay.io/acme/api:v1", ImagePull: &v1.ImagePull{SecretRef: "ghcr-pull"}}, "is for ghcr.io; the image is on quay.io"},
		"a disk":     {v1.SiloSpec{Runtime: "cloud-hypervisor", Image: "ubuntu-24.04", ImagePull: &v1.ImagePull{SecretRef: "ghcr-pull"}}, "boots an Image's disk"},
		"missing":    {v1.SiloSpec{Runtime: "docker", Image: "ghcr.io/acme/api:v1", ImagePull: &v1.ImagePull{SecretRef: "nope"}}, `no secret "nope"`},
	} {
		s := &v1.Silo{TypeMeta: api.TypeMeta, ObjectMeta: meta.ObjectMeta{Name: "bad", Namespace: "web3"}, Spec: bad.spec}
		if err := ada.Create(ctx, s); !client.IsInvalid(err) || !strings.Contains(err.Error(), bad.msg) {
			t.Errorf("%s: %v, want %q", what, err, bad.msg)
		}
	}
	// With use on it (by name), the same silo is admitted.
	if err := c.admin.Create(ctx, &v1.Role{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Role"},
		ObjectMeta: meta.ObjectMeta{Name: "pull-ghcr", Namespace: "web3"}, Rules: []v1.PolicyRule{
			{Verbs: []string{"use"}, Resources: []string{"secrets"}, ResourceNames: []string{"ghcr-pull"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "ed-pull", Namespace: "web3"}, RoleRef: v1.RoleRef{Kind: "Role", Name: "pull-ghcr"},
		Subjects: []v1.Subject{{Kind: "User", Name: "ed"}}}); err != nil {
		t.Fatal(err)
	}
	if err := ed.Create(ctx, api); err != nil {
		t.Fatalf("with use on the secret: %v", err)
	}
	place := func(s *v1.Silo, host string) {
		t.Helper()
		for {
			if err := c.admin.Get(ctx, "Silo", s.Namespace, s.Name, s); err != nil {
				t.Fatal(err)
			}
			s.Status.Host, s.Status.Phase = host, "Scheduled"
			err := c.admin.UpdateStatus(ctx, s)
			if !client.IsConflict(err) {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
		}
	}
	place(api, "hv1")
	web := &v1.Silo{TypeMeta: api.TypeMeta, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "web3"},
		Spec: v1.SiloSpec{Runtime: "docker", Image: "nginx:1.27", Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
	denied := &v1.Silo{TypeMeta: api.TypeMeta, ObjectMeta: meta.ObjectMeta{Name: "denied", Namespace: "web3"},
		Spec: v1.SiloSpec{Runtime: "docker", Image: "ghcr.io/acme/denied:v1", ImagePull: &v1.ImagePull{SecretRef: "ghcr-pull"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
	for _, s := range []*v1.Silo{web, denied} {
		if err := ada.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		place(s, "hv1")
	}

	digest := "sha256:" + strings.Repeat("d1", 32)
	host := &pullHost{files: map[string][]byte{}, digest: digest}
	rt := pulling{Runtime: fake.New(), puller: &container.Runtime{Host: host, Engine: "docker"}}
	hv1 := &agent.Agent{Client: c.host(t, "hv1"), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}}
	go hv1.Run(ctx)

	get := func(s *v1.Silo) *v1.Silo {
		var cur v1.Silo
		_ = c.admin.Get(ctx, "Silo", s.Namespace, s.Name, &cur)
		return &cur
	}
	wait := func(what string, ok func() (bool, string)) {
		t.Helper()
		for {
			good, msg := ok()
			if good {
				return
			}
			if ctx.Err() != nil {
				t.Fatalf("%s: %s", what, msg)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	pullOf := func(image string) (pullSeen, bool) {
		pulls, _ := host.seen()
		for i := len(pulls) - 1; i >= 0; i-- {
			if strings.HasSuffix(pulls[i].args, " "+image) {
				return pulls[i], true
			}
		}
		return pullSeen{}, false
	}
	wait("api running with the digest pulled", func() (bool, string) {
		s := get(api)
		return meta.IsTrue(s.Status.Conditions, "Ready") && s.Status.Image != nil && s.Status.Image.Digest == digest, condMsgs(s.Status.Conditions)
	})
	if p, ok := pullOf("ghcr.io/acme/api:v1"); !ok || p.auth != "bot:tok-1" || !strings.Contains(p.args, "--config "+container.PullDir+"/") || strings.Contains(p.args, "tok-1") {
		t.Fatalf("api's pull: %+v", p)
	}
	wait("web pulled with the namespace's default for docker.io", func() (bool, string) {
		p, ok := pullOf("nginx:1.27")
		return ok && p.auth == "bot:hub-tok", p.args
	})
	wait("denied: ImagePullFailed with the registry's reason", func() (bool, string) {
		s := get(denied)
		cd := meta.FindCondition(s.Status.Conditions, "Ready")
		return cd != nil && cd.Reason == agent.ReasonImagePullFailed && strings.Contains(cd.Message, "unauthorized: authentication required") &&
			!strings.Contains(cd.Message, "tok-1"), condMsgs(s.Status.Conditions)
	})

	// Rotation: the next pull (a reset) uses the new value.
	sec := &v1.Secret{}
	_ = ada.Get(ctx, "Secret", "web3", "ghcr-pull", sec)
	sec.Spec.Value = []byte("tok-2")
	if err := ada.Update(ctx, sec); err != nil {
		t.Fatal(err)
	}
	cur := get(api)
	cur.Spec.Reset = "r1"
	if err := ada.Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	wait("api reset, pulled with the rotated value", func() (bool, string) {
		s := get(api)
		p, _ := pullOf("ghcr.io/acme/api:v1")
		return s.Status.Image != nil && s.Status.Image.Reset == "r1" && p.auth == "bot:tok-2", p.auth + " " + condMsgs(s.Status.Conditions)
	})
	// Nothing left behind: once the silo that keeps retrying its refused pull is gone, no auth file
	// remains (one exists only while a pull runs).
	if err := ada.Delete(ctx, "Silo", "web3", "denied"); err != nil {
		t.Fatal(err)
	}
	wait("no auth file left", func() (bool, string) {
		_, left := host.seen()
		return left == 0, fmt.Sprint(left, " left")
	})

	// Another host never gets it, nor does a host for an image that isn't the silo's.
	ask := func(cl *client.Client, hostName, image string) client.BrokerResponse {
		var resp client.BrokerResponse
		s := get(api)
		if err := cl.Call(ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{Namespace: "web3", Name: "api", UID: s.UID, Host: hostName,
			Request: client.BrokerRequest{Op: client.OpPullCredential, Name: image}}, &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	hv2 := c.host(t, "hv2")
	if r := ask(hv2, "hv2", "ghcr.io/acme/api:v1"); r.Registry != nil || r.Error == "" {
		t.Fatalf("hv2 got the credential of a silo on hv1: %+v", r)
	}
	if r := ask(c.host(t, "hv1"), "hv1", "ghcr.io/acme/other:v1"); r.Registry != nil || r.Error == "" {
		t.Fatalf("hv1 got the credential for an image that isn't the silo's: %+v", r)
	}

	// The silo's own broker can't read it, by either op.
	dir, _ := os.MkdirTemp("/tmp", "kvp") // unix socket paths are short on macOS
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ch := channels{dir}
	b := &agent.Broker{Client: c.host(t, "hv1"), HostName: "hv1"}
	s := get(api)
	if err := b.Ensure(ctx, ch, kri.ID{Namespace: "web3", Name: "api", UID: s.UID}); err != nil {
		t.Fatal(err)
	}
	for _, req := range []client.BrokerRequest{{Op: client.OpPullCredential, Name: "ghcr.io/acme/api:v1"}, {Op: client.OpGetSecret, Name: "ghcr-pull"}} {
		resp, err := guest.Call(ctx, ch.dialer(s.UID), req)
		if err == nil && (resp.Registry != nil || len(resp.Value) > 0 || resp.Error == "") {
			t.Fatalf("the silo asked %s and got %+v", req.Op, resp)
		}
		if bytes.Contains([]byte(resp.Error+errString(err)), []byte("tok-")) {
			t.Fatalf("the credential in an answer to the silo: %v %v", resp, err)
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
