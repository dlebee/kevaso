package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
)

// Secrets with named keys (hack/design/secret-keys.md): keys are always explicit. Writes, reads
// back, admission, and every delivery naming one key or every key ("*").

func keyed(name string, data map[string]string) *v1.Secret {
	s := secretObj(name, nil, "")
	s.Spec.Data = map[string][]byte{}
	for k, v := range data {
		s.Spec.Data[k] = []byte(v)
	}
	return s
}

func TestSecretKeysWriteAndRead(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	db := keyed("db", map[string]string{"username": "app", "password": "pw-1"})
	if err := c.admin.Create(c.ctx, db); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(db.Status.Keys, []string{"password", "username"}) || db.Status.Size != len("app")+len("pw-1") || db.Status.Version != 1 {
		t.Fatalf("status: %+v", db.Status)
	}
	var raw json.RawMessage
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/db", nil, &raw); err != nil || strings.Contains(string(raw), "pw-1") || strings.Contains(string(raw), `"data":`) {
		t.Fatalf("get carries a value: %s %v", raw, err)
	}
	read := func(q string) (client.SecretValue, error) {
		var v client.SecretValue
		err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/db/value"+q, nil, &v)
		return v, err
	}
	// The value read names its key, or every key: no key at all is refused, not guessed.
	if _, err := read(""); status(err) != http.StatusBadRequest || !strings.Contains(err.Error(), "?key=KEY") || !strings.Contains(err.Error(), "?key=*") {
		t.Fatalf("no key named: %v", err)
	}
	if v, err := read("?key=*"); err != nil || string(v.Data["username"]) != "app" || string(v.Data["password"]) != "pw-1" || len(v.Data) != 2 {
		t.Fatalf("every key: %v %v", v.Data, err)
	}
	if v, err := read("?key=password"); err != nil || string(v.Value) != "pw-1" || v.Data != nil {
		t.Fatalf("one key: %+v %v", v, err)
	}
	if _, err := read("?key=nope"); status(err) != http.StatusNotFound {
		t.Fatalf("unknown key: %v", err)
	}

	// spec.value is gone: a manifest that still carries it is refused, never read as some key.
	obj := map[string]any{"apiVersion": v1.APIVersion, "kind": "Secret", "metadata": map[string]any{"name": "old", "namespace": "web3"},
		"spec": map[string]any{"value": "c2VjcmV0"}}
	if err := c.admin.Call(c.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/web3/secrets", obj, nil); err == nil || !strings.Contains(err.Error(), "value") {
		t.Fatalf("spec.value: %v", err)
	}
	// setData changes one key and keeps the others; removeKeys removes; each is one version.
	var cur *v1.Secret
	update := func(f func(s *v1.Secret)) error {
		cur = &v1.Secret{} // decoding into a used one would keep its write-only fields
		if err := c.admin.Get(c.ctx, "Secret", "web3", "db", cur); err != nil {
			t.Fatal(err)
		}
		f(cur)
		return c.admin.Update(c.ctx, cur)
	}
	if err := update(func(s *v1.Secret) {
		s.Spec.SetData = map[string][]byte{"password": []byte("pw-2"), "host": []byte("db.local")}
	}); err != nil {
		t.Fatal(err)
	}
	if v, _ := read("?key=*"); string(v.Data["password"]) != "pw-2" || string(v.Data["username"]) != "app" || string(v.Data["host"]) != "db.local" || v.Version != 2 {
		t.Fatalf("after setData: %v v%d", v.Data, v.Version)
	}
	if err := update(func(s *v1.Secret) { s.Spec.RemoveKeys = []string{"host"} }); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cur.Status.Keys, []string{"password", "username"}) || cur.Status.Version != 3 {
		t.Fatalf("after removeKeys: %+v", cur.Status)
	}
	for _, bad := range []struct {
		why string
		f   func(s *v1.Secret)
	}{
		{"one of them", func(s *v1.Secret) {
			s.Spec.Data, s.Spec.SetData = map[string][]byte{"x": []byte("x")}, map[string][]byte{"a": []byte("b")}
		}},
		{"no key", func(s *v1.Secret) { s.Spec.RemoveKeys = []string{"host"} }},
		{"both", func(s *v1.Secret) {
			s.Spec.SetData, s.Spec.RemoveKeys = map[string][]byte{"username": []byte("x")}, []string{"username"}
		}},
		{"at least one key", func(s *v1.Secret) { s.Spec.RemoveKeys = []string{"password", "username"} }},
		{"same variable name", func(s *v1.Secret) { s.Spec.SetData = map[string][]byte{"user-name": nil, "USER_NAME": nil} }},
		{"letters, digits", func(s *v1.Secret) { s.Spec.SetData = map[string][]byte{"../x": []byte("y")} }},
		{"letters, digits", func(s *v1.Secret) { s.Spec.SetData = map[string][]byte{"*": []byte("y")} }},
	} {
		if err := update(bad.f); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), bad.why) {
			t.Fatalf("%s: %v", bad.why, err)
		}
	}
	// data replaces every key.
	if err := update(func(s *v1.Secret) { s.Spec.Data = map[string][]byte{"dsn": []byte("pg://x")} }); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cur.Status.Keys, []string{"dsn"}) {
		t.Fatalf("data replaces every key: %+v", cur.Status)
	}

	// generate names its key; a fixed-shape secret's key is its own name.
	gen := secretObj("gen", nil, "")
	gen.Spec.Generate = "token"
	if err := c.admin.Create(c.ctx, gen); err != nil || !slices.Equal(gen.Status.Keys, []string{"token"}) {
		t.Fatalf("generate token: %+v %v", gen.Status, err)
	}
	bad := secretObj("gen-bad", nil, "")
	bad.Spec.Generate = "*"
	if err := c.admin.Create(c.ctx, bad); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "spec.generate") {
		t.Fatalf("generate *: %v", err)
	}
	k := keyed("signer", map[string]string{"a": "b"})
	k.Spec.Type = v1.SecretEd25519
	if err := c.admin.Create(c.ctx, k); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), `"private-key"`) {
		t.Fatalf("a signing key with keys: %v", err)
	}
	k = secretObj("signer", nil, "")
	k.Spec.Type, k.Spec.Generate = v1.SecretEd25519, "token"
	if err := c.admin.Create(c.ctx, k); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "generate: private-key") {
		t.Fatalf("a signing key generated as token: %v", err)
	}
	k = secretObj("signer", nil, "")
	k.Spec.Type, k.Spec.Generate = v1.SecretEd25519, v1.PrivateKeyKey
	if err := c.admin.Create(c.ctx, k); err != nil || !slices.Equal(k.Status.Keys, []string{v1.PrivateKeyKey}) || k.Status.PublicKey == "" {
		t.Fatalf("a signing key: %+v %v", k.Status, err)
	}
	r := keyed("pull", map[string]string{"token": "x"})
	r.Spec.Type, r.Spec.Server, r.Spec.Username = v1.SecretRegistry, "ghcr.io", "bot"
	if err := c.admin.Create(c.ctx, r); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), `"password"`) {
		t.Fatalf("a registry secret without its password key: %v", err)
	}
	r = keyed("pull", map[string]string{v1.PasswordKey: "x"})
	r.Spec.Type, r.Spec.Server, r.Spec.Username = v1.SecretRegistry, "ghcr.io", "bot"
	if err := c.admin.Create(c.ctx, r); err != nil || !slices.Equal(r.Status.Keys, []string{v1.PasswordKey}) {
		t.Fatalf("a registry secret: %+v %v", r.Status, err)
	}
}

// A write that changes some keys can't loosen the secret (make it readable): only a write
// bringing every key can (K-018). The vault's tests show a setData keeps a write-only value so.
func TestSecretKeysWriteOnlySticks(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	s := keyed("wo", map[string]string{"a": "1", "b": "2"})
	f := false
	s.Spec.ValueReadable = &f
	if err := c.admin.Create(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	cur := &v1.Secret{}
	_ = c.admin.Get(c.ctx, "Secret", "web3", "wo", cur)
	tr := true
	cur.Spec.ValueReadable = &tr
	cur.Spec.SetData = map[string][]byte{"a": []byte("new")}
	if err := c.admin.Update(c.ctx, cur); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "every key again") {
		t.Fatalf("loosening with setData: %v", err)
	}
	var v client.SecretValue
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/wo/value?key=*", nil, &v); status(err) != http.StatusForbidden {
		t.Fatalf("write-only read: %v", err)
	}
	// Readable with every key again: fine, and that value is readable.
	cur = &v1.Secret{}
	_ = c.admin.Get(c.ctx, "Secret", "web3", "wo", cur)
	cur.Spec.ValueReadable = &tr
	cur.Spec.Data = map[string][]byte{"a": []byte("x")}
	if err := c.admin.Update(c.ctx, cur); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/wo/value?key=*", nil, &v); err != nil || string(v.Data["a"]) != "x" {
		t.Fatalf("readable after a whole write: %v %v", v.Data, err)
	}
}

// Admission: every entry names its key (one, or "*"); inject takes one named key; a key named
// must be one of the secret's. Signing keys have no keys to name.
func TestSecretKeysAdmission(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	if err := c.admin.Create(c.ctx, keyed("api", map[string]string{"token": "t", "id": "i"})); err != nil {
		t.Fatal(err)
	}
	k := secretObj("signer", nil, "")
	k.Spec.Type, k.Spec.Generate = v1.SecretEd25519, v1.PrivateKeyKey
	if err := c.admin.Create(c.ctx, k); err != nil {
		t.Fatal(err)
	}
	to := &v1.InjectTarget{Host: "api.example.com"}
	both := `key is required: name one key (key: KEY) or every key (key: "*")`
	for _, bad := range []struct {
		why string
		gs  v1.GrantSecret
	}{
		{both, v1.GrantSecret{Name: "api"}},
		{both, v1.GrantSecret{Name: "api", Deliver: v1.DeliverFile}},
		{both, v1.GrantSecret{Name: "api", Deliver: v1.DeliverEnv}},
		{"key is required: name the one key to inject (key: KEY)", v1.GrantSecret{Name: "api", Deliver: v1.DeliverInject, To: to}},
		{`inject adds one key: name it (key: KEY), not "*"`, v1.GrantSecret{Name: "api", Key: v1.AllKeys, Deliver: v1.DeliverInject, To: to}},
		{`has no key "nope"`, v1.GrantSecret{Name: "api", Key: "nope", Deliver: v1.DeliverEnv}},
		{`has no key "nope"`, v1.GrantSecret{Name: "api", Key: "nope"}},
		{`has no key "nope"`, v1.GrantSecret{Name: "api", Key: "nope", Deliver: v1.DeliverInject, To: to}},
		{"bad/key", v1.GrantSecret{Name: "api", Key: "bad/key", Deliver: v1.DeliverFile}},
		{"doesn't allow delivery broker", v1.GrantSecret{Name: "signer", Key: v1.PrivateKeyKey}},
		{"doesn't allow delivery file", v1.GrantSecret{Name: "signer", Key: v1.AllKeys, Deliver: v1.DeliverFile}},
	} {
		g := grantObj("bad", v1.GrantSpec{Secrets: []v1.GrantSecret{bad.gs}})
		if err := c.admin.Create(c.ctx, g); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), bad.why) {
			t.Fatalf("%+v: want %q, got %v", bad.gs, bad.why, err)
		}
	}
	// A manifest without key: the same refusal, with both forms in the message.
	obj := map[string]any{"apiVersion": v1.APIVersion, "kind": "Grant", "metadata": map[string]any{"name": "raw", "namespace": "web3"},
		"spec": map[string]any{"secrets": []any{map[string]any{"name": "api", "deliver": "file"}}}}
	if err := c.admin.Call(c.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/web3/grants", obj, nil); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), both) {
		t.Fatalf("a manifest with no key: %v", err)
	}
	for i, gs := range []v1.GrantSecret{
		{Name: "api", Key: "token", Deliver: v1.DeliverInject, To: to},
		{Name: "api", Key: v1.AllKeys},
		{Name: "api", Key: v1.AllKeys, Deliver: v1.DeliverFile},
		{Name: "api", Key: "id", Deliver: v1.DeliverEnv},
	} {
		if err := c.admin.Create(c.ctx, grantObj(fmt.Sprintf("ok-%d", i), v1.GrantSpec{Secrets: []v1.GrantSecret{gs}})); err != nil {
			t.Fatalf("%+v: %v", gs, err)
		}
	}
}

// Every delivery with keys, end to end through the broker: the endpoint (one key, every key, a
// grant limited to one key, no key refused), files and variables the host writes (one key, every
// key as a folder or a set of variables), inject of one key, and a key rotated, added and removed
// reaching it all.
func TestSecretKeysDeliveries(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	for _, s := range []*v1.Secret{
		keyed("db", map[string]string{"username": "app", "password": "pw-1"}),
		keyed("api", map[string]string{"token": "tok-1", "id": "id-1"}),
		keyed("plain", map[string]string{"token": "only"}),
	} {
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	g := grantObj("app", v1.GrantSpec{Secrets: []v1.GrantSecret{
		{Name: "db", Key: v1.AllKeys},                                             // broker, every key
		{Name: "api", Key: "id"},                                                  // broker, one key only
		{Name: "plain", Key: "token"},                                             // broker, its one key, named
		{Name: "db", Key: v1.AllKeys, Deliver: v1.DeliverFile},                    // a folder
		{Name: "db", Key: "password", Deliver: v1.DeliverFile, Path: "/run/pw"},   // one file at a path
		{Name: "plain", Key: "token", Deliver: v1.DeliverFile},                    // one file, /run/secrets/plain/token
		{Name: "plain", Key: v1.AllKeys, Deliver: v1.DeliverFile, Path: "/run/p"}, // a folder even with one key
		{Name: "db", Key: v1.AllKeys, Deliver: v1.DeliverEnv},                     // DB_USERNAME, DB_PASSWORD
		{Name: "db", Key: "password", Deliver: v1.DeliverEnv, Env: "PGPASSWORD"},  // one variable
		{Name: "plain", Key: "token", Deliver: v1.DeliverEnv},                     // PLAIN_TOKEN: no special case for one key
		{Name: "api", Key: v1.AllKeys, Deliver: v1.DeliverEnv, Env: "API"},        // a prefix
		{Name: "api", Key: "token", Deliver: v1.DeliverInject, To: &v1.InjectTarget{Host: "api.example.com"}},
	}})
	if err := c.admin.Create(c.ctx, g); err != nil {
		t.Fatal(err)
	}
	s := silo("node", "web3")
	s.Spec.Grants = []string{"app"}
	if err := c.admin.Create(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = "hv1"
	if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	eps := c.endpoints(t, "hv1")
	eps.add(t, s)
	get := func(path string) epAnswer { return eps.call(t, s, http.MethodGet, path, nil) }
	every := func(path string) map[string][]byte {
		t.Helper()
		a := get(path)
		var all agent.SecretKeys
		if err := json.Unmarshal([]byte(a.body), &all); a.code != 200 || err != nil || a.header.Get("Content-Type") != "application/json" {
			t.Fatalf("%s: %d %q", path, a.code, a.body)
		}
		return all.Data
	}

	if a := get("/v1/secrets/db/password"); a.code != 200 || a.body != "pw-1" || a.header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("one key: %d %q", a.code, a.body)
	}
	if d := every("/v1/secrets/db/*"); len(d) != 2 || string(d["username"]) != "app" || string(d["password"]) != "pw-1" {
		t.Fatalf("every key: %v", d)
	}
	if d := every("/v1/secrets/api/*"); len(d) != 1 || string(d["id"]) != "id-1" {
		t.Fatalf("every key of a grant naming one: %v", d)
	}
	if d := every("/v1/secrets/plain/*"); len(d) != 1 || string(d["token"]) != "only" {
		t.Fatalf("every key of a one-key secret is still JSON: %v", d)
	}
	if a := get("/v1/secrets/plain/token"); a.code != 200 || a.body != "only" {
		t.Fatalf("a one-key secret, its key named: %d %q", a.code, a.body)
	}
	// No key: refused, with both forms; never a guess, whatever the secret holds.
	for _, p := range []string{"/v1/secrets/plain", "/v1/secrets/db", "/v1/secrets/missing"} {
		if a := get(p); a.code != http.StatusBadRequest || !strings.Contains(a.msg(), p+"/KEY") || !strings.Contains(a.msg(), p+"/*") {
			t.Fatalf("%s: %d %q", p, a.code, a.msg())
		}
	}
	if a, b := get("/v1/secrets/api/token"), get("/v1/secrets/missing/token"); a.code != 404 || b.code != 404 || strings.ReplaceAll(a.msg(), "api", "X") != strings.ReplaceAll(b.msg(), "missing", "X") {
		t.Fatalf("a key the grant doesn't give must look like nothing: %d %q / %d %q", a.code, a.msg(), b.code, b.msg())
	}
	if a := get("/v1/secrets/db/nope"); a.code != 404 {
		t.Fatalf("unknown key: %d", a.code)
	}
	if a := get("/v1/secrets/db/Bad%2Fkey"); a.code != 404 && a.code != 400 {
		t.Fatalf("a bad key: %d", a.code)
	}

	hv1 := c.host(t, "hv1")
	ask := func(op, key string) client.BrokerResponse {
		t.Helper()
		var r client.BrokerResponse
		if err := hv1.Call(c.ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{Namespace: "web3", Name: "node", UID: s.UID,
			Request: client.BrokerRequest{Op: op, Name: "db", Key: key}}, &r); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		return r
	}
	// The broker itself refuses a get with no key (an old host would send one).
	if r := ask(client.OpGetSecret, ""); r.Error == "" || r.Value != nil || r.Data != nil {
		t.Fatalf("a get with no key: %+v", r)
	}
	got := func() map[string]string {
		t.Helper()
		r := ask(client.OpDeliveryValues, "")
		if r.Error != "" {
			t.Fatal(r.Error)
		}
		out := map[string]string{}
		for _, d := range r.Deliveries {
			where := d.Path
			if d.Mode == v1.DeliverEnv {
				where = "$" + d.Env
			}
			out[where] = string(d.Value)
		}
		return out
	}
	want := map[string]string{
		"/run/secrets/db/username": "app", "/run/secrets/db/password": "pw-1", "/run/pw": "pw-1",
		"/run/secrets/plain/token": "only", "/run/p/token": "only",
		"$DB_USERNAME": "app", "$DB_PASSWORD": "pw-1", "$PGPASSWORD": "pw-1", "$PLAIN_TOKEN": "only", "$API_TOKEN": "tok-1", "$API_ID": "id-1",
	}
	if g := got(); fmt.Sprint(g) != fmt.Sprint(want) {
		t.Fatalf("deliveries:\n got %v\nwant %v", g, want)
	}
	inj := ask(client.OpInjections, "").Injections
	if len(inj) != 1 || string(inj[0].Raw) != "tok-1" || inj[0].Value != "Bearer tok-1" || inj[0].Key != "token" {
		t.Fatalf("injections: %+v", inj)
	}

	// One key rotated: every delivery of it changes, the others stay, one new version.
	cur := &v1.Secret{}
	_ = c.admin.Get(c.ctx, "Secret", "web3", "db", cur)
	cur.Spec.SetData = map[string][]byte{"password": []byte("pw-2")}
	if err := c.admin.Update(c.ctx, cur); err != nil {
		t.Fatal(err)
	}
	for k, v := range want {
		if v == "pw-1" {
			want[k] = "pw-2"
		}
	}
	if g := got(); fmt.Sprint(g) != fmt.Sprint(want) {
		t.Fatalf("after rotating one key:\n got %v\nwant %v", g, want)
	}
	if a := get("/v1/secrets/db/password"); a.body != "pw-2" || a.header.Get("Kevaso-Version") != "2" {
		t.Fatalf("endpoint after rotation: %q v%s", a.body, a.header.Get("Kevaso-Version"))
	}
	// The secret still reaches only this silo through grants naming it: the fan-out is per secret.
	if aff := agent.Affected([]*v1.Silo{s}, []*v1.Grant{g}, "Secret", "web3", "db"); len(aff) != 1 {
		t.Fatalf("fan-out: %d", len(aff))
	}

	// A key added: "*" gives it (a new file in the folder, a new variable, in the JSON); an
	// entry naming one key doesn't change. A key removed goes from "*" the same way.
	p := &v1.Secret{}
	_ = c.admin.Get(c.ctx, "Secret", "web3", "plain", p)
	p.Spec.SetData = map[string][]byte{"other": []byte("o")}
	if err := c.admin.Update(c.ctx, p); err != nil {
		t.Fatal(err)
	}
	want["/run/p/other"] = "o"
	if g := got(); fmt.Sprint(g) != fmt.Sprint(want) {
		t.Fatalf("after adding a key:\n got %v\nwant %v", g, want)
	}
	if d := every("/v1/secrets/plain/*"); len(d) != 1 || string(d["token"]) != "only" {
		t.Fatalf("a grant naming one key gives that key alone, whatever is added: %v", d)
	}
	_ = c.admin.Get(c.ctx, "Secret", "web3", "db", cur)
	cur.Spec.SetData, cur.Spec.RemoveKeys = nil, []string{"username"}
	if err := c.admin.Update(c.ctx, cur); err != nil {
		t.Fatal(err)
	}
	delete(want, "/run/secrets/db/username")
	delete(want, "$DB_USERNAME")
	if g := got(); fmt.Sprint(g) != fmt.Sprint(want) {
		t.Fatalf("after removing a key:\n got %v\nwant %v", g, want)
	}
	if d := every("/v1/secrets/db/*"); len(d) != 1 || string(d["password"]) != "pw-2" {
		t.Fatalf("every key after removing one: %v", d)
	}

	// The key an inject names, removed from the secret: left out, never another key guessed.
	a := &v1.Secret{}
	_ = c.admin.Get(c.ctx, "Secret", "web3", "api", a)
	a.Spec.RemoveKeys = []string{"token"}
	if err := c.admin.Update(c.ctx, a); err != nil {
		t.Fatal(err)
	}
	if n := len(ask(client.OpInjections, "").Injections); n != 0 {
		t.Fatalf("an inject whose key is gone: %d injections", n)
	}
}

// A ClusterSecret holds keys the same way; its value read names a key or every key.
func TestClusterSecretKeys(t *testing.T) {
	c := newCluster(t)
	cs := &v1.ClusterSecret{}
	cs.APIVersion, cs.Kind, cs.Name = v1.APIVersion, "ClusterSecret", "bucket"
	cs.Spec.Data = map[string][]byte{"access-key": []byte("AK"), "secret-key": []byte("SK")}
	if err := c.admin.Create(c.ctx, cs); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cs.Status.Keys, []string{"access-key", "secret-key"}) || cs.Status.Version != 1 {
		t.Fatalf("status: %+v", cs.Status)
	}
	var v client.SecretValue
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket/value", nil, &v); status(err) != http.StatusBadRequest || !strings.Contains(err.Error(), "?key=*") {
		t.Fatalf("no key named: %v", err)
	}
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket/value?key=*", nil, &v); err != nil || string(v.Data["secret-key"]) != "SK" || len(v.Data) != 2 {
		t.Fatalf("read: %v %v", v.Data, err)
	}
	cur := &v1.ClusterSecret{}
	_ = c.admin.Get(c.ctx, "ClusterSecret", "", "bucket", cur)
	cur.Spec.SetData = map[string][]byte{"secret-key": []byte("SK2")}
	if err := c.admin.Update(c.ctx, cur); err != nil {
		t.Fatal(err)
	}
	v = client.SecretValue{}
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket/value?key=secret-key", nil, &v); err != nil || string(v.Value) != "SK2" || v.Version != 2 || v.Data != nil {
		t.Fatalf("one key after setData: %q v%d %v", v.Value, v.Version, err)
	}
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket/value?key=access-key", nil, &v); err != nil || string(v.Value) != "AK" {
		t.Fatalf("the other key kept: %q %v", v.Value, err)
	}
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket/value?key=nope", nil, &v); status(err) != http.StatusNotFound {
		t.Fatalf("unknown key: %v", err)
	}
	obj := map[string]any{"apiVersion": v1.APIVersion, "kind": "ClusterSecret", "metadata": map[string]any{"name": "old"},
		"spec": map[string]any{"value": "c2VjcmV0"}}
	if err := c.admin.Call(c.ctx, http.MethodPost, "/apis/kevaso/v1/clustersecrets", obj, nil); err == nil {
		t.Fatal("a ClusterSecret with spec.value was taken")
	}
}
