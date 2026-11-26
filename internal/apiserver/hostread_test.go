package apiserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/pki"
)

func enrollHost(t *testing.T, e *authEnv, name, role string) *client.Client {
	t.Helper()
	if err := e.admin.Create(e.ctx, host(name)); err != nil {
		t.Fatal(err)
	}
	tok, err := e.tokens.Create(e.ctx, name, []string{role}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, name, role)
	if err != nil {
		t.Fatal(err)
	}
	return e.tlsClient(t, &cred)
}

// controlPlaneHost is a host certificate of role control-plane. /enroll does not issue one;
// the API still accepts one, and this signs it the way the cluster CA does.
func controlPlaneHost(t *testing.T, e *authEnv, name string) *client.Client {
	t.Helper()
	if err := e.admin.Create(e.ctx, host(name)); err != nil {
		t.Fatal(err)
	}
	id := pki.Identity{Type: "host", Name: name, Role: "control-plane"}
	key, csr, err := pki.NewKeyAndCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := e.ca.SignCSR(csr, id, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return e.tlsClient(t, &client.Credentials{Certificate: cert, Key: key})
}

func mustCreate(t *testing.T, e *authEnv, obj meta.Object) {
	t.Helper()
	if err := e.admin.Create(e.ctx, obj); err != nil {
		t.Fatalf("create %s %s: %v", obj.GetTypeMeta().Kind, obj.GetObjectMeta().Name, err)
	}
}

func place(t *testing.T, e *authEnv, name, namespace, on string, spec v1.SiloSpec) *v1.Silo {
	t.Helper()
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"},
		ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Spec: spec}
	mustCreate(t, e, s)
	s.Status.Host = on
	if err := e.admin.UpdateStatus(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	return s
}

func namesOf(t *testing.T, c *client.Client, ctx context.Context, kind, namespace string) []string {
	t.Helper()
	l, err := c.List(ctx, kind, namespace)
	if err != nil {
		t.Fatalf("list %s: %v", kind, err)
	}
	var names []string
	for _, raw := range l.Items {
		obj, _, err := v1.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		m := obj.GetObjectMeta()
		names = append(names, m.Namespace+"/"+m.Name)
	}
	slices.Sort(names)
	return names
}

func hasName(names []string, namespace, name string) bool {
	return slices.Contains(names, namespace+"/"+name)
}

// A worker reads the kinds running its silos takes, and is refused the rest. Cluster-wide kinds
// include objects that have nothing to do with this host. Related kinds do not.
func TestWorkerReadScope(t *testing.T) {
	e := setupAuth(t)
	mustCreate(t, e, ns("dev"))
	mustCreate(t, e, ns("idle"))
	worker := enrollHost(t, e, "hv2", "worker")
	_ = enrollHost(t, e, "hv3", "worker")
	cp := controlPlaneHost(t, e, "cp")

	mustCreate(t, e, &v1.Service{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Service"},
		ObjectMeta: meta.ObjectMeta{Name: "far", Namespace: "idle"},
		Spec:       v1.ServiceSpec{Selector: map[string]string{"app": "far"}, Ports: []v1.ServicePortSpec{{Name: "http", Port: 80}}}})
	mustCreate(t, e, &v1.IngressClass{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IngressClass"},
		ObjectMeta: meta.ObjectMeta{Name: "edge"},
		Spec:       v1.IngressClassSpec{Controller: v1.IngressController{Driver: "nginx", Namespace: "idle", Silo: "proxy"}}})
	place(t, e, "theirs", "dev", "hv3", v1.SiloSpec{Runtime: "cloud-hypervisor"})
	mustCreate(t, e, &v1.Grant{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Grant"},
		ObjectMeta: meta.ObjectMeta{Name: "theirs", Namespace: "dev"},
		Spec:       v1.GrantSpec{Egress: []v1.EgressRule{{To: "example.com"}}}})

	cluster := map[string]bool{"Host": true, "Silo": true, "Service": true, "IngressClass": true}
	related := map[string]bool{"Grant": true, "Secret": true, "Lease": true, "Ingress": true, "OpenShellPolicy": true}
	for _, k := range v1.Kinds() {
		if k.Kind == "ClusterSecret" {
			continue
		}
		_, err := worker.List(e.ctx, k.Kind, "")
		switch {
		case cluster[k.Kind] || related[k.Kind]:
			if err != nil {
				t.Errorf("list %s: %v", k.Kind, err)
			}
		default:
			if code(err) != http.StatusForbidden {
				t.Errorf("list %s: want 403, got %v", k.Kind, err)
			}
		}
	}
	if _, err := worker.Watch(e.ctx, "Role", "", "0"); code(err) != http.StatusForbidden {
		t.Fatalf("watch Role: want 403, got %v", err)
	}
	if _, err := worker.List(e.ctx, "ClusterSecret", ""); err != nil {
		t.Fatalf("list ClusterSecret: %v", err)
	}
	if _, err := worker.Watch(e.ctx, "ClusterSecret", "", "0"); err != nil {
		t.Fatalf("watch ClusterSecret: %v", err)
	}
	if err := worker.Call(e.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket/value?for=juicefs&side=controller", nil, nil); code(err) != http.StatusForbidden || !strings.Contains(err.Error(), "only for a plugin's node side") {
		t.Fatalf("worker value side=controller: want 403 naming the side, got %v", err)
	}
	if err := worker.Call(e.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/dev/secrets/x/value", nil, nil); code(err) != http.StatusForbidden {
		t.Fatalf("secret value: want 403, got %v", err)
	}

	// A silo placed on another host is readable: DNS, allowFrom and the egress denylist need it,
	// and so does deciding that a local copy's disk stays.
	var theirs v1.Silo
	if err := worker.Get(e.ctx, "Silo", "dev", "theirs", &theirs); err != nil || theirs.Status.Host != "hv3" {
		t.Fatalf("silo on another host: %v %+v", err, theirs.Status)
	}
	if !hasName(namesOf(t, worker, e.ctx, "Silo", ""), "dev", "theirs") {
		t.Fatal("list silos omitted one placed on another host")
	}
	if !hasName(namesOf(t, worker, e.ctx, "Host", ""), "", "hv3") {
		t.Fatal("list hosts omitted another host")
	}
	if !hasName(namesOf(t, worker, e.ctx, "Service", ""), "idle", "far") {
		t.Fatal("list services omitted a service in a namespace this host does not run")
	}
	if !hasName(namesOf(t, worker, e.ctx, "IngressClass", ""), "", "edge") {
		t.Fatal("list ingress classes omitted a class whose controller is not here")
	}
	// The other host's grant is not. Neither is a namespace this host runs nothing in.
	if err := worker.Get(e.ctx, "Grant", "dev", "theirs", &v1.Grant{}); code(err) != http.StatusForbidden {
		t.Fatalf("grant of a silo on another host: want 403, got %v", err)
	}
	var missing v1.Grant
	if err := worker.Get(e.ctx, "Grant", "dev", "missing", &missing); code(err) != http.StatusNotFound {
		t.Fatalf("missing grant: want 404, got %v", err)
	}
	if got := namesOf(t, worker, e.ctx, "Grant", "idle"); len(got) != 0 {
		t.Fatalf("grants in a namespace with no silo here: %v", got)
	}

	d := &v1.KindDefinition{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "KindDefinition"},
		ObjectMeta: meta.ObjectMeta{Name: "widgets.acme.dev"},
		Spec: v1.KindDefinitionSpec{Group: "acme.dev", Version: "v1", Scope: v1.Namespaced,
			Names: v1.KindNames{Kind: "Widget", Plural: "widgets"}}}
	if err := json.Unmarshal([]byte(`{"type":"object","properties":{"spec":{"type":"object","properties":{"n":{"type":"string"}}}}}`), &d.Spec.Schema); err != nil {
		t.Fatal(err)
	}
	mustCreate(t, e, d)
	if err := worker.Call(e.ctx, http.MethodGet, "/apis/acme.dev/v1/namespaces/dev/widgets", nil, nil); code(err) != http.StatusForbidden {
		t.Fatalf("defined kind: want 403, got %v", err)
	}

	// A control-plane host is not a worker certificate.
	if _, err := cp.List(e.ctx, "Role", ""); err != nil {
		t.Fatalf("control-plane list Role: %v", err)
	}
	wctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	if _, err := cp.Watch(wctx, "Role", "", "0"); err != nil {
		t.Fatalf("control-plane watch Role: %v", err)
	}
}

// Grants, secrets, leases and ingresses are readable only for a silo on this host, including one
// a move is taking to or from it.
func TestWorkerReadsOnlyWhatIsOnIt(t *testing.T) {
	e := setupAuth(t)
	mustCreate(t, e, ns("dev"))
	mustCreate(t, e, ns("idle"))
	worker := enrollHost(t, e, "hv2", "worker")
	_ = enrollHost(t, e, "hv3", "worker")

	mustCreate(t, e, &v1.Grant{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Grant"},
		ObjectMeta: meta.ObjectMeta{Name: "use", Namespace: "dev"},
		Spec: v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db", Key: "password"}},
			Operations: &v1.GrantOperations{Sign: &v1.SignOperation{KeyRef: "signing"}}}})
	mustCreate(t, e, &v1.Grant{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Grant"},
		ObjectMeta: meta.ObjectMeta{Name: "leave", Namespace: "dev"},
		Spec:       v1.GrantSpec{Egress: []v1.EgressRule{{To: "leave.example.com"}}}})
	mustCreate(t, e, &v1.Grant{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Grant"},
		ObjectMeta: meta.ObjectMeta{Name: "far", Namespace: "dev"},
		Spec:       v1.GrantSpec{Egress: []v1.EgressRule{{To: "far.example.com"}}}})
	mustCreate(t, e, &v1.Grant{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Grant"},
		ObjectMeta: meta.ObjectMeta{Name: "unused", Namespace: "idle"},
		Spec:       v1.GrantSpec{Egress: []v1.EgressRule{{To: "idle.example.com"}}}})
	for _, name := range []string{"db", "signing", "other"} {
		mustCreate(t, e, &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
			ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"}})
	}
	for _, name := range []string{"pull", "defaultpull"} {
		labels := map[string]string{}
		if name == "defaultpull" {
			labels[v1.LabelDefaultPull] = "true"
		}
		mustCreate(t, e, &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
			ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev", Labels: labels},
			Spec:       v1.SecretSpec{Type: v1.SecretRegistry, Server: "ghcr.io", Username: "u"}})
	}

	place(t, e, "web", "dev", "hv2", v1.SiloSpec{Runtime: "cloud-hypervisor", Grants: []string{"use"}})
	place(t, e, "puller", "dev", "hv2", v1.SiloSpec{Runtime: "docker",
		Container: &v1.ContainerSource{Image: "ghcr.io/acme/web:1", Pull: &v1.ImagePull{SecretRef: "pull"}},
		Resources: v1.Resources{CPU: 1, Memory: "1Gi"}})
	place(t, e, "far", "dev", "hv3", v1.SiloSpec{Runtime: "cloud-hypervisor", Grants: []string{"far"}})
	moving := place(t, e, "moving", "dev", "hv3", v1.SiloSpec{Runtime: "cloud-hypervisor", Grants: []string{"leave"}})
	moving.Status.MovingFrom = "hv2"
	if err := e.admin.UpdateStatus(e.ctx, moving); err != nil {
		t.Fatal(err)
	}

	grants := namesOf(t, worker, e.ctx, "Grant", "")
	for _, want := range []string{"use", "leave"} {
		if !hasName(grants, "dev", want) {
			t.Errorf("grant %s not listed: %v", want, grants)
		}
	}
	for _, ban := range []string{"far", "unused"} {
		if hasName(grants, "dev", ban) {
			t.Errorf("grant %s listed: %v", ban, grants)
		}
	}
	if err := worker.Get(e.ctx, "Grant", "dev", "leave", &v1.Grant{}); err != nil {
		t.Fatalf("grant of a silo moving away: %v", err)
	}
	if err := worker.Get(e.ctx, "Grant", "idle", "unused", &v1.Grant{}); code(err) != http.StatusForbidden {
		t.Fatalf("grant in a namespace with nothing here: want 403, got %v", err)
	}

	osp := func(name, namespace string) *v1.OpenShellPolicy {
		return &v1.OpenShellPolicy{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "OpenShellPolicy"},
			ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace},
			Spec: v1.OpenShellPolicySpec{NetworkPolicies: []v1.OpenShellNetworkPolicy{{
				Name: "web", Endpoints: []v1.OpenShellEndpoint{{Host: "example.com", Port: 443}},
			}}}}
	}
	for _, name := range []string{"use", "leave", "far"} {
		mustCreate(t, e, osp(name, "dev"))
	}
	mustCreate(t, e, osp("unused", "idle"))
	osSpec := func(policy string) v1.SiloSpec {
		return v1.SiloSpec{Runtime: "openshell", Container: &v1.ContainerSource{Image: "ubuntu-24.04"},
			Resources: v1.Resources{CPU: 1, Memory: "256Mi"}, OpenShellPolicies: []string{policy}}
	}
	place(t, e, "osp-web", "dev", "hv2", osSpec("use"))
	place(t, e, "osp-far", "dev", "hv3", osSpec("far"))
	leaving := place(t, e, "osp-moving", "dev", "hv3", osSpec("leave"))
	leaving.Status.MovingFrom = "hv2"
	if err := e.admin.UpdateStatus(e.ctx, leaving); err != nil {
		t.Fatal(err)
	}
	policies := namesOf(t, worker, e.ctx, "OpenShellPolicy", "")
	for _, want := range []string{"use", "leave"} {
		if !hasName(policies, "dev", want) {
			t.Errorf("openshell policy %s not listed: %v", want, policies)
		}
	}
	for _, ban := range []string{"far", "unused"} {
		if hasName(policies, "dev", ban) || hasName(policies, "idle", ban) {
			t.Errorf("openshell policy %s listed: %v", ban, policies)
		}
	}
	if err := worker.Get(e.ctx, "OpenShellPolicy", "dev", "leave", &v1.OpenShellPolicy{}); err != nil {
		t.Fatalf("policy of a silo moving away: %v", err)
	}
	if err := worker.Get(e.ctx, "OpenShellPolicy", "dev", "far", &v1.OpenShellPolicy{}); code(err) != http.StatusForbidden {
		t.Fatalf("policy of a silo on another host: want 403, got %v", err)
	}
	if err := worker.Get(e.ctx, "OpenShellPolicy", "idle", "unused", &v1.OpenShellPolicy{}); code(err) != http.StatusForbidden {
		t.Fatalf("policy nothing here names: want 403, got %v", err)
	}

	secrets := namesOf(t, worker, e.ctx, "Secret", "")
	for _, want := range []string{"db", "signing", "pull"} {
		if !hasName(secrets, "dev", want) {
			t.Errorf("secret %s not listed: %v", want, secrets)
		}
	}
	for _, ban := range []string{"other", "defaultpull"} {
		if hasName(secrets, "dev", ban) {
			t.Errorf("secret %s listed: %v", ban, secrets)
		}
		if err := worker.Get(e.ctx, "Secret", "dev", ban, &v1.Secret{}); code(err) != http.StatusForbidden {
			t.Errorf("get secret %s: want 403, got %v", ban, err)
		}
	}

	// Leases: one port of a silo here, one of a silo on the other host.
	for _, silo := range []string{"web", "far"} {
		s := &v1.Silo{}
		if err := e.admin.Get(e.ctx, "Silo", "dev", silo, s); err != nil {
			t.Fatal(err)
		}
		s.Spec.Ports = []v1.SiloPort{{Name: "debug", Port: 9229}}
		s.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Port: "debug", HostPort: []string{v1.NetworkExternal}, Lease: &v1.PortLease{}}}}
		if err := e.admin.Update(e.ctx, s); err != nil {
			t.Fatal(err)
		}
		if err := e.admin.Call(e.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/"+silo+"/open", v1.LeaseOpenRequest{Port: "debug", For: "1m"}, &client.LeaseAnswer{}); err != nil {
			t.Fatalf("open %s: %v", silo, err)
		}
	}
	leases := namesOf(t, worker, e.ctx, "Lease", "")
	if len(leases) != 1 {
		t.Fatalf("leases: %v", leases)
	}

	mustCreate(t, e, &v1.IngressClass{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IngressClass"},
		ObjectMeta: meta.ObjectMeta{Name: "office"},
		Spec: v1.IngressClassSpec{Controller: v1.IngressController{Driver: "nginx", Namespace: "dev", Silo: "web"},
			Hosts: []v1.HostAssignment{{Host: "*.example.com", Namespaces: []string{"dev"}}}}})
	web := &v1.Silo{}
	if err := e.admin.Get(e.ctx, "Silo", "dev", "web", web); err != nil {
		t.Fatal(err)
	}
	web.Spec.Ports = append(web.Spec.Ports, v1.SiloPort{Name: "http", Port: 80})
	web.Spec.Service.Ports = append(web.Spec.Service.Ports, v1.ServicePort{Port: "http"})
	web.Spec.Service.Name = "web"
	if err := e.admin.Update(e.ctx, web); err != nil {
		t.Fatal(err)
	}
	back := place(t, e, "back", "dev", "hv2", v1.SiloSpec{Runtime: "cloud-hypervisor"})
	back.Labels = map[string]string{"app": "back"}
	if err := e.admin.Update(e.ctx, back); err != nil {
		t.Fatal(err)
	}
	mustCreate(t, e, &v1.Service{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Service"},
		ObjectMeta: meta.ObjectMeta{Name: "back", Namespace: "dev"},
		Spec:       v1.ServiceSpec{Selector: map[string]string{"app": "back"}, Ports: []v1.ServicePortSpec{{Name: "http", Port: 80}}}})
	far := &v1.Silo{}
	if err := e.admin.Get(e.ctx, "Silo", "dev", "far", far); err != nil {
		t.Fatal(err)
	}
	far.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 80}}
	far.Spec.Service = &v1.SiloService{Name: "far", Ports: []v1.ServicePort{{Port: "http"}}}
	if err := e.admin.Update(e.ctx, far); err != nil {
		t.Fatal(err)
	}
	ing := func(name, svc string) {
		t.Helper()
		mustCreate(t, e, &v1.Ingress{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Ingress"},
			ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.IngressSpec{IngressClass: "office", Hosts: []string{name + ".example.com"},
				Rules: []v1.IngressRule{{Service: v1.IngressTarget{Name: svc, Port: "http"}}}}})
	}
	ing("to-web", "web")
	ing("to-back", "back")
	ing("to-far", "far")
	ings := namesOf(t, worker, e.ctx, "Ingress", "")
	for _, want := range []string{"to-web", "to-back"} {
		if !hasName(ings, "dev", want) {
			t.Errorf("ingress %s not listed: %v", want, ings)
		}
	}
	if hasName(ings, "dev", "to-far") {
		t.Fatalf("ingress of another host's silo listed: %v", ings)
	}
	if err := worker.Get(e.ctx, "Ingress", "dev", "to-far", &v1.Ingress{}); code(err) != http.StatusForbidden {
		t.Fatalf("get ingress of another host: want 403, got %v", err)
	}
}

type secretEv struct {
	typ, name, gen string
}

func gather(ch <-chan client.Event, wait time.Duration) []client.Event {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	var got []client.Event
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return got
			}
			got = append(got, ev)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(500 * time.Millisecond)
		case <-timer.C:
			return got
		}
	}
}

func secretEvs(t *testing.T, evs []client.Event) []secretEv {
	t.Helper()
	var out []secretEv
	for _, ev := range evs {
		obj, _, err := v1.Decode(ev.Object)
		if err != nil {
			t.Fatal(err)
		}
		s, ok := obj.(*v1.Secret)
		if !ok {
			t.Fatalf("event %s is a %T", ev.Type, obj)
		}
		out = append(out, secretEv{ev.Type, s.Name, s.Labels["gen"]})
	}
	return out
}

func secretGen(t *testing.T, e *authEnv, name, gen string) {
	t.Helper()
	var s v1.Secret
	if err := e.admin.Get(e.ctx, "Secret", "dev", name, &s); err != nil {
		t.Fatal(err)
	}
	if s.Labels == nil {
		s.Labels = map[string]string{}
	}
	s.Labels["gen"] = gen
	if err := e.admin.Update(e.ctx, &s); err != nil {
		t.Fatal(err)
	}
}

func watchSecrets(t *testing.T, e *authEnv, worker *client.Client) (context.CancelFunc, <-chan client.Event) {
	t.Helper()
	ctx, cancel := context.WithCancel(e.ctx)
	ch, err := worker.Watch(ctx, "Secret", "", "0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return cancel, ch
}

// A watch opened after a secret was already rewritten does not send the earlier revisions.
func TestWorkerWatchDoesNotReplay(t *testing.T) {
	e := setupAuth(t)
	mustCreate(t, e, ns("dev"))
	worker := enrollHost(t, e, "hv2", "worker")
	mustCreate(t, e, &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
		ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev", Labels: map[string]string{"gen": "v1"}}})
	secretGen(t, e, "db", "v2")
	mustCreate(t, e, &v1.Grant{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Grant"},
		ObjectMeta: meta.ObjectMeta{Name: "use", Namespace: "dev"},
		Spec:       v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db", Key: "password"}}}})
	place(t, e, "web", "dev", "hv2", v1.SiloSpec{Runtime: "cloud-hypervisor", Grants: []string{"use"}})
	mustCreate(t, e, &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
		ObjectMeta: meta.ObjectMeta{Name: "other", Namespace: "dev", Labels: map[string]string{"gen": "v1"}}})

	cancel, ch := watchSecrets(t, e, worker)
	defer cancel()
	got := secretEvs(t, gather(ch, 5*time.Second))
	if len(got) != 1 || got[0] != (secretEv{"ADDED", "db", "v2"}) {
		t.Fatalf("watch from the start, secret already on the host: %+v", got)
	}
	secretGen(t, e, "other", "v2")
	if extra := secretEvs(t, gather(ch, time.Second)); len(extra) != 0 {
		t.Fatalf("an unrelated secret's update: %+v", extra)
	}
	secretGen(t, e, "db", "v3")
	if next := secretEvs(t, gather(ch, 5*time.Second)); len(next) != 1 || next[0] != (secretEv{"MODIFIED", "db", "v3"}) {
		t.Fatalf("update after the link: %+v", next)
	}
}

// A watch opened before the silo is placed sends the secret once, as it is when the link appears,
// and not the revisions from before.
func TestWorkerWatchStartsWhenTheSiloArrives(t *testing.T) {
	e := setupAuth(t)
	mustCreate(t, e, ns("dev"))
	worker := enrollHost(t, e, "hv2", "worker")
	mustCreate(t, e, &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
		ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev", Labels: map[string]string{"gen": "v1"}}})
	secretGen(t, e, "db", "v2")
	mustCreate(t, e, &v1.Grant{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Grant"},
		ObjectMeta: meta.ObjectMeta{Name: "use", Namespace: "dev"},
		Spec:       v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db", Key: "password"}}}})

	cancel, ch := watchSecrets(t, e, worker)
	defer cancel()
	if got := secretEvs(t, gather(ch, time.Second)); len(got) != 0 {
		t.Fatalf("before anything is placed here: %+v", got)
	}
	place(t, e, "web", "dev", "hv2", v1.SiloSpec{Runtime: "cloud-hypervisor", Grants: []string{"use"}})
	if got := secretEvs(t, gather(ch, 5*time.Second)); len(got) != 1 || got[0] != (secretEv{"ADDED", "db", "v2"}) {
		t.Fatalf("when the silo arrives: %+v", got)
	}
}

// When the silo leaves, the watch says the secret is gone and does not send a later revision.
func TestWorkerWatchDropsWhenTheSiloLeaves(t *testing.T) {
	e := setupAuth(t)
	mustCreate(t, e, ns("dev"))
	worker := enrollHost(t, e, "hv2", "worker")
	mustCreate(t, e, &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
		ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev", Labels: map[string]string{"gen": "v2"}}})
	mustCreate(t, e, &v1.Grant{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Grant"},
		ObjectMeta: meta.ObjectMeta{Name: "use", Namespace: "dev"},
		Spec:       v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db", Key: "password"}}}})
	s := place(t, e, "web", "dev", "hv2", v1.SiloSpec{Runtime: "cloud-hypervisor", Grants: []string{"use"}})

	cancel, ch := watchSecrets(t, e, worker)
	defer cancel()
	if got := secretEvs(t, gather(ch, 5*time.Second)); len(got) != 1 || got[0].gen != "v2" {
		t.Fatalf("initial: %+v", got)
	}
	if err := e.admin.Get(e.ctx, "Silo", "dev", "web", s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.MovingFrom = "hv3", ""
	if err := e.admin.UpdateStatus(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	if got := secretEvs(t, gather(ch, 5*time.Second)); len(got) != 1 || got[0] != (secretEv{"DELETED", "db", "v2"}) {
		t.Fatalf("after the silo leaves: %+v", got)
	}
	secretGen(t, e, "db", "v4")
	if extra := secretEvs(t, gather(ch, time.Second)); len(extra) != 0 {
		t.Fatalf("a revision after the silo left: %+v", extra)
	}
}
