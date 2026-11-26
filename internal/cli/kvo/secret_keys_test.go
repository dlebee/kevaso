package kvo

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func TestSecretFlagsKeys(t *testing.T) {
	dir := t.TempDir()
	user, pw := filepath.Join(dir, "user"), filepath.Join(dir, "a=b.txt")
	_ = os.WriteFile(user, []byte("app\n"), 0o600)
	_ = os.WriteFile(pw, []byte("pw"), 0o600)

	data, err := secretOpts{fromFiles: []string{"username=" + user, "password=-"}}.keys(strings.NewReader("s3cret\n"))
	if err != nil || len(data) != 2 || string(data["username"]) != "app" || string(data["password"]) != "s3cret" {
		t.Fatalf("keys: %v %v", data, err)
	}
	if data, err := (secretOpts{fromFiles: []string{"token=" + pw}}).keys(nil); err != nil || string(data["token"]) != "pw" {
		t.Fatalf("a KEY=FILE whose FILE holds =: %v %v", data, err)
	}
	// A --from-file that names no key is refused, with the form.
	for _, f := range []string{pw, user, "-", "token=", "=" + user} {
		_, err := secretOpts{fromFiles: []string{f}}.keys(strings.NewReader("x"))
		if err == nil || !strings.Contains(err.Error(), "name the key: --from-file KEY=FILE, or --from-file KEY=- for stdin") {
			t.Errorf("--from-file %s: %v", f, err)
		}
	}
	for _, bad := range []secretOpts{
		{fromFiles: []string{user, "password=" + pw}},         // a bare FILE among keys
		{fromFiles: []string{"a=-", "b=-"}},                   // stdin twice
		{fromFiles: []string{"a=" + user, "a=" + pw}},         // a key twice
		{fromLiterals: []string{"a=b"}},                       // no --i-know
		{fromLiterals: []string{"just-a-value"}, iKnow: true}, // literals are KEY=VALUE
	} {
		if _, err := bad.keys(strings.NewReader("x")); err == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
	if data, err := (secretOpts{fromLiterals: []string{"token=tok=="}, iKnow: true}).keys(nil); err != nil || string(data["token"]) != "tok==" {
		t.Fatalf("literal: %v %v", data, err)
	}
	if data, err := (secretOpts{}).keys(nil); err != nil || data != nil {
		t.Fatalf("no flags: %v %v", data, err)
	}
}

// kvo create secret, secret set and get --reveal name every key: a bare --from-file, a --reveal
// without --key are refused with the form; --generate KEY sends the key to make; --key "*" reads
// every key (?key=*) as KEY: VALUE lines.
func TestSecretCommandsNameKeys(t *testing.T) {
	t.Setenv("KVO_SERVER", "http://127.0.0.1:9")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "secret", "db"}, "a secret needs at least one key: --from-file KEY=FILE, --from-file KEY=- (stdin"},
		{[]string{"create", "secret", "db", "--from-file", "pw.txt"}, "--from-file pw.txt: name the key: --from-file KEY=FILE, or --from-file KEY=- for stdin (e.g. --from-file token=pw.txt)"},
		{[]string{"create", "secret", "db", "--from-file", "-"}, "--from-file -: name the key: --from-file KEY=FILE, or --from-file KEY=- for stdin"},
		{[]string{"create", "secret", "db", "--generate"}, "--generate"},
		{[]string{"create", "secret", "db", "--generate", "token", "--from-file", "a=-"}, "--generate KEY makes the value: no --from-file with it"},
		{[]string{"secret", "set", "db"}, "secret set needs the keys to change: --from-file KEY=FILE, --from-file KEY=- (stdin; repeatable) or --remove-key KEY"},
		{[]string{"secret", "set", "db", "--from-file", "-"}, "--from-file -: name the key"},
		{[]string{"get", "secret", "db", "--reveal"}, `--reveal needs --key: kvo get secret db --reveal --key KEY for one key, or --key "*" for every key`},
	} {
		var out, errb bytes.Buffer
		if code := Run(context.Background(), tc.args, strings.NewReader("x"), &out, &errb); code == 0 || !strings.Contains(errb.String(), tc.want) {
			t.Errorf("%v: code %d, %q; want %q", tc.args, code, errb.String(), tc.want)
		}
	}

	var sent []v1.Secret
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/apis/kevaso/v1/namespaces/dev/secrets":
			var s v1.Secret
			_ = json.NewDecoder(r.Body).Decode(&s)
			sent = append(sent, s)
			s.Status = v1.SecretStatus{Version: 1, Keys: []string{"token"}}
			s.Spec.Data = nil
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(s)
		case r.Method == http.MethodGet && r.URL.Path == "/apis/kevaso/v1/namespaces/dev/secrets/db":
			_ = json.NewEncoder(w).Encode(v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev", ResourceVersion: "4"}})
		case r.Method == http.MethodPut && r.URL.Path == "/apis/kevaso/v1/namespaces/dev/secrets/db":
			var s v1.Secret
			_ = json.NewDecoder(r.Body).Decode(&s)
			sent = append(sent, s)
			s.Status = v1.SecretStatus{Version: 2, Keys: []string{"password", "username"}}
			_ = json.NewEncoder(w).Encode(s)
		case r.Method == http.MethodGet && r.URL.Path == "/apis/kevaso/v1/namespaces/dev/secrets/db/value":
			queries = append(queries, r.URL.Query().Get("key"))
			if r.URL.Query().Get("key") == v1.AllKeys {
				_ = json.NewEncoder(w).Encode(client.SecretValue{Data: map[string][]byte{"username": []byte("app"), "password": []byte("pw")}, Version: 2})
				return
			}
			_ = json.NewEncoder(w).Encode(client.SecretValue{Value: []byte("pw"), Version: 2})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("KVO_SERVER", srv.URL)
	run := func(stdin string, args ...string) string {
		t.Helper()
		var out, errb bytes.Buffer
		if code := Run(context.Background(), args, strings.NewReader(stdin), &out, &errb); code != 0 {
			t.Fatalf("%v: %d %s", args, code, errb.String())
		}
		return out.String()
	}
	if out := run("", "create", "secret", "api", "-n", "dev", "--generate", "token"); !strings.Contains(out, "secret/api created (version 1, key token)") {
		t.Fatalf("generate: %q", out)
	}
	if s := sent[len(sent)-1]; s.Spec.Generate != "token" || s.Spec.Data != nil {
		t.Fatalf("generate sent %+v", s.Spec)
	}
	run("s3cret\n", "create", "secret", "api", "-n", "dev", "--from-file", "token=-")
	if s := sent[len(sent)-1]; s.Spec.Generate != "" || len(s.Spec.Data) != 1 || string(s.Spec.Data["token"]) != "s3cret" {
		t.Fatalf("create sent %+v", s.Spec)
	}
	if out := run("pw2\n", "secret", "set", "db", "-n", "dev", "--from-file", "password=-"); !strings.Contains(out, "secret/db: version 2, keys password, username") {
		t.Fatalf("set: %q", out)
	}
	if s := sent[len(sent)-1]; s.Spec.Data != nil || len(s.Spec.SetData) != 1 || string(s.Spec.SetData["password"]) != "pw2" {
		t.Fatalf("set sent %+v (setData only: the other keys stay)", s.Spec)
	}
	if out := run("", "get", "secret", "db", "-n", "dev", "--reveal", "--key", "password"); out != "pw" {
		t.Fatalf("reveal one key: %q", out)
	}
	if out := run("", "get", "secret", "db", "-n", "dev", "--reveal", "--key", "*"); out != "password: pw\nusername: app\n" {
		t.Fatalf("reveal every key: %q", out)
	}
	if strings.Join(queries, ",") != "password,*" {
		t.Fatalf("value reads asked for %v", queries)
	}
}
