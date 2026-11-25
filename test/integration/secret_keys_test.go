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

// Secrets with named keys (hack/design/secret-keys.md): writes, reads back, admission, and every
// delivery naming a key or not.

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
	if v, err := read(""); err != nil || string(v.Data["username"]) != "app" || string(v.Data["password"]) != "pw-1" || len(v.Data) != 2 {
		t.Fatalf("all keys: %v %v", v.Data, err)
	}
	if v, err := read("?key=password"); err != nil || string(v.Value) != "pw-1" || v.Data != nil {
		t.Fatalf("one key: %+v %v", v, err)
	}
	if _, err := read("?key=nope"); status(err) != http.StatusNotFound {
		t.Fatalf("unknown key: %v", err)
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
	if v, _ := read(""); string(v.Data["password"]) != "pw-2" || string(v.Data["username"]) != "app" || string(v.Data["host"]) != "db.local" || v.Version != 2 {
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
		{"one of them", func(s *v1.Secret) { s.Spec.Value, s.Spec.SetData = []byte("x"), map[string][]byte{"a": []byte("b")} }},
		{"no key", func(s *v1.Secret) { s.Spec.RemoveKeys = []string{"host"} }},
		{"both", func(s *v1.Secret) {
			s.Spec.SetData, s.Spec.RemoveKeys = map[string][]byte{"username": []byte("x")}, []string{"username"}
		}},
		{"at least one key", func(s *v1.Secret) { s.Spec.RemoveKeys = []string{"password", "username"} }},
		{"same variable name", func(s *v1.Secret) { s.Spec.SetData = map[string][]byte{"user-name": nil, "USER_NAME": nil} }},
		{"letters, digits", func(s *v1.Secret) { s.Spec.SetData = map[string][]byte{"../x": []byte("y")} }},
	} {
		if err := update(bad.f); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), bad.why) {
			t.Fatalf("%s: %v", bad.why, err)
		}
	}
	// value replaces every key with the one key value.
	if err := update(func(s *v1.Secret) { s.Spec.Value = []byte("just-one") }); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cur.Status.Keys, []string{v1.ValueKey}) {
		t.Fatalf("value shorthand: %+v", cur.Status)
	}

	// Signing keys and registry secrets hold the key value only.
	k := keyed("signer", map[string]string{"a": "b"})
	k.Spec.Type = v1.SecretEd25519
	if err := c.admin.Create(c.ctx, k); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "holds one value") {
		t.Fatalf("a signing key with keys: %v", err)
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
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/wo/value", nil, &v); status(err) != http.StatusForbidden {
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
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/web3/secrets/wo/value", nil, &v); err != nil || string(v.Data["a"]) != "x" {
		t.Fatalf("readable after a whole write: %v %v", v.Data, err)
	}
}

// Admission: a key a grant names must be one of the secret's; an inject without a key needs a
// secret with one key. Signing keys have no keys to name.
func TestSecretKeysAdmission(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	if err := c.admin.Create(c.ctx, keyed("api", map[string]string{"token": "t", "id": "i"})); err != nil {
		t.Fatal(err)
	}
	to := &v1.InjectTarget{Host: "api.example.com"}
	for _, bad := range []struct {
		why string
		gs  v1.GrantSecret
	}{
		{`has no key "nope"`, v1.GrantSecret{Name: "api", Key: "nope", Deliver: v1.DeliverEnv}},
		{`has no key "nope"`, v1.GrantSecret{Name: "api", Key: "nope"}},
		{"an inject adds one, so name it", v1.GrantSecret{Name: "api", Deliver: v1.DeliverInject, To: to}},
		{"bad/key", v1.GrantSecret{Name: "api", Key: "bad/key", Deliver: v1.DeliverFile}},
	} {
		g := grantObj("bad", v1.GrantSpec{Secrets: []v1.GrantSecret{bad.gs}})
		if err := c.admin.Create(c.ctx, g); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), bad.why) {
			t.Fatalf("%+v: want %q, got %v", bad.gs, bad.why, err)
		}
	}
	ok := grantObj("ok", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "api", Key: "token", Deliver: v1.DeliverInject, To: to}}})
	if err := c.admin.Create(c.ctx, ok); err != nil {
		t.Fatalf("inject naming a key: %v", err)
	}
}

// Every delivery with keys, end to end through the broker: the endpoint (one key, every key, a
// grant limited to one key), files and variables the host writes (a folder of keys, one key, the
// shorthand's one file), inject of one key, and a key rotated reaching it all.
func TestSecretKeysDeliveries(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	for _, s := range []*v1.Secret{
		keyed("db", map[string]string{"username": "app", "password": "pw-1"}),
		keyed("api", map[string]string{"token": "tok-1", "id": "id-1"}),
		secretObj("plain", nil, "only"),
	} {
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	g := grantObj("app", v1.GrantSpec{Secrets: []v1.GrantSecret{
		{Name: "db"},                          // broker, every key
		{Name: "api", Key: "id"},              // broker, one key only
		{Name: "plain"},                       // broker, the shorthand
		{Name: "db", Deliver: v1.DeliverFile}, // a folder
		{Name: "db", Key: "password", Deliver: v1.DeliverFile, Path: "/run/pw"},  // one file
		{Name: "plain", Deliver: v1.DeliverFile},                                 // the shorthand's one file
		{Name: "db", Deliver: v1.DeliverEnv},                                     // DB_USERNAME, DB_PASSWORD
		{Name: "db", Key: "password", Deliver: v1.DeliverEnv, Env: "PGPASSWORD"}, // one variable
		{Name: "api", Deliver: v1.DeliverEnv, Env: "API"},                        // a prefix
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

	if a := get("/v1/secrets/db/password"); a.code != 200 || a.body != "pw-1" || a.header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("one key: %d %q", a.code, a.body)
	}
	a := get("/v1/secrets/db")
	var all agent.SecretKeys
	if err := json.Unmarshal([]byte(a.body), &all); a.code != 200 || err != nil || string(all.Data["username"]) != "app" || string(all.Data["password"]) != "pw-1" || a.header.Get("Content-Type") != "application/json" {
		t.Fatalf("every key: %d %q", a.code, a.body)
	}
	if a := get("/v1/secrets/api"); a.code != 200 || a.body != "id-1" {
		t.Fatalf("a grant naming one key, no key asked: %d %q", a.code, a.body)
	}
	if a, b := get("/v1/secrets/api/token"), get("/v1/secrets/missing/token"); a.code != 404 || b.code != 404 || strings.ReplaceAll(a.msg(), "api", "X") != strings.ReplaceAll(b.msg(), "missing", "X") {
		t.Fatalf("a key the grant doesn't give must look like nothing: %d %q / %d %q", a.code, a.msg(), b.code, b.msg())
	}
	if a := get("/v1/secrets/db/nope"); a.code != 404 {
		t.Fatalf("unknown key: %d", a.code)
	}
	if a := get("/v1/secrets/plain"); a.code != 200 || a.body != "only" {
		t.Fatalf("the shorthand: %d %q", a.code, a.body)
	}
	if a := get("/v1/secrets/db/Bad%2Fkey"); a.code != 404 && a.code != 400 {
		t.Fatalf("a bad key: %d", a.code)
	}

	hv1 := c.host(t, "hv1")
	ask := func(op string) client.BrokerResponse {
		t.Helper()
		var r client.BrokerResponse
		if err := hv1.Call(c.ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{Namespace: "web3", Name: "node", UID: s.UID,
			Request: client.BrokerRequest{Op: op}}, &r); err != nil || r.Error != "" {
			t.Fatalf("%s: %v %s", op, err, r.Error)
		}
		return r
	}
	got := func() map[string]string {
		out := map[string]string{}
		for _, d := range ask(client.OpDeliveryValues).Deliveries {
			where := d.Path
			if d.Mode == v1.DeliverEnv {
				where = "$" + d.Env
			}
			out[where] = string(d.Value)
		}
		return out
	}
	want := map[string]string{
		"/run/secrets/db/username": "app", "/run/secrets/db/password": "pw-1", "/run/pw": "pw-1", "/run/secrets/plain": "only",
		"$DB_USERNAME": "app", "$DB_PASSWORD": "pw-1", "$PGPASSWORD": "pw-1", "$API_TOKEN": "tok-1", "$API_ID": "id-1",
	}
	if g := got(); fmt.Sprint(g) != fmt.Sprint(want) {
		t.Fatalf("deliveries:\n got %v\nwant %v", g, want)
	}
	inj := ask(client.OpInjections).Injections
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

	// A key added to the secret an inject without a key used: left out, not guessed.
	plainInj := grantObj("plain-inject", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "plain", Deliver: v1.DeliverInject, To: &v1.InjectTarget{Host: "x.example.com"}}}})
	if err := c.admin.Create(c.ctx, plainInj); err != nil {
		t.Fatal(err)
	}
	_ = c.admin.Get(c.ctx, "Silo", "web3", "node", s)
	s.Spec.Grants = append(s.Spec.Grants, "plain-inject")
	if err := c.admin.Update(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	if n := len(ask(client.OpInjections).Injections); n != 2 {
		t.Fatalf("injections with plain's one key: %d", n)
	}
	p := &v1.Secret{}
	_ = c.admin.Get(c.ctx, "Secret", "web3", "plain", p)
	p.Spec.SetData = map[string][]byte{"other": []byte("o")}
	if err := c.admin.Update(c.ctx, p); err != nil {
		t.Fatal(err)
	}
	if n := len(ask(client.OpInjections).Injections); n != 1 {
		t.Fatalf("an inject without a key on a secret with two keys: %d injections", n)
	}
	// And the shorthand's one file became a folder of keys.
	if g := got(); g["/run/secrets/plain/value"] != "only" || g["/run/secrets/plain/other"] != "o" || g["/run/secrets/plain"] != "" {
		t.Fatalf("plain as a folder: %v", g)
	}
}

// A ClusterSecret holds keys the same way.
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
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket/value", nil, &v); err != nil || string(v.Data["secret-key"]) != "SK" {
		t.Fatalf("read: %v %v", v.Data, err)
	}
	cur := &v1.ClusterSecret{}
	_ = c.admin.Get(c.ctx, "ClusterSecret", "", "bucket", cur)
	cur.Spec.SetData = map[string][]byte{"secret-key": []byte("SK2")}
	if err := c.admin.Update(c.ctx, cur); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket/value?key=secret-key", nil, &v); err != nil || string(v.Value) != "SK2" || v.Version != 2 {
		t.Fatalf("one key after setData: %q v%d %v", v.Value, v.Version, err)
	}
	if err := c.admin.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/clustersecrets/bucket/value?key=access-key", nil, &v); err != nil || string(v.Value) != "AK" {
		t.Fatalf("the other key kept: %q %v", v.Value, err)
	}
}
