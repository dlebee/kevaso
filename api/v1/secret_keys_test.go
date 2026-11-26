package v1

import (
	"slices"
	"strings"
	"testing"
)

func TestSecretKeyNames(t *testing.T) {
	for _, k := range []string{"value", "password", "tls.crt", "DB_HOST", "a", "a-b_c.d"} {
		if !ValidKey(k) {
			t.Errorf("%q should be a key", k)
		}
	}
	for _, k := range []string{"", ".", "..", ".hidden", "a/b", "a b", "-a", "a-", "x=y", strings.Repeat("a", 254)} {
		if ValidKey(k) {
			t.Errorf("%q shouldn't be a key", k)
		}
	}
	if p := KeyProblems([]string{"db-host", "DB_HOST"}); len(p) != 1 || !strings.Contains(p[0], "same variable name") {
		t.Fatalf("colliding variables: %v", p)
	}
	if p := KeyProblems([]string{"username", "password"}); p != nil {
		t.Fatalf("fine keys: %v", p)
	}
}

func TestGrantSecretKeyNaming(t *testing.T) {
	multi := []string{"password", "username"}
	for _, c := range []struct {
		gs   GrantSecret
		key  string
		file string
		env  string
	}{
		// "*": a folder and PREFIX_KEY, whatever the secret holds.
		{GrantSecret{Name: "db", Key: AllKeys}, "password", "/run/secrets/db/password", "DB_PASSWORD"},
		{GrantSecret{Name: "db", Key: AllKeys, Path: "/run/db", Env: "PG"}, "username", "/run/db/username", "PG_USERNAME"},
		{GrantSecret{Name: "api-token", Key: AllKeys}, "token", "/run/secrets/api-token/token", "API_TOKEN_TOKEN"},
		// A named key: its own file and variable; one key is never a special case.
		{GrantSecret{Name: "db", Key: "password"}, "password", "/run/secrets/db/password", "DB_PASSWORD"},
		{GrantSecret{Name: "db", Key: "password", Path: "/run/pw", Env: "PGPASSWORD"}, "password", "/run/pw", "PGPASSWORD"},
		{GrantSecret{Name: "api-token", Key: "token"}, "token", "/run/secrets/api-token/token", "API_TOKEN_TOKEN"},
		{GrantSecret{Name: "api-token", Key: "value"}, "value", "/run/secrets/api-token/value", "API_TOKEN_VALUE"},
		{GrantSecret{Name: "my.cert", Key: AllKeys}, "tls.crt", "/run/secrets/my.cert/tls.crt", "MY_CERT_TLS_CRT"},
	} {
		if got := c.gs.FilePath(c.key); got != c.file {
			t.Errorf("%+v key %s: file %s, want %s", c.gs, c.key, got, c.file)
		}
		if got := c.gs.EnvName(c.key); got != c.env {
			t.Errorf("%+v key %s: env %s, want %s", c.gs, c.key, got, c.env)
		}
	}
	all := GrantSecret{Name: "db", Key: AllKeys}
	one := GrantSecret{Name: "db", Key: "password"}
	none := GrantSecret{Name: "db"}
	if !slices.Equal(all.Keys(multi), multi) || !slices.Equal(one.Keys(multi), []string{"password"}) || one.Keys([]string{"token"}) != nil || none.Keys(multi) != nil {
		t.Fatal("Keys")
	}
	if !all.Gives("password") || !one.Gives("password") || one.Gives("username") || none.Gives("password") || none.Gives("") || one.Gives("") {
		t.Fatal("Gives")
	}
}

func TestGrantSecretKeyRefProblem(t *testing.T) {
	for _, c := range []struct {
		gs   GrantSecret
		want string // "" for fine
	}{
		{GrantSecret{Name: "db", Key: "password"}, ""},
		{GrantSecret{Name: "db", Key: AllKeys}, ""},
		{GrantSecret{Name: "db", Key: AllKeys, Deliver: DeliverFile}, ""},
		{GrantSecret{Name: "db", Key: AllKeys, Deliver: DeliverEnv}, ""},
		{GrantSecret{Name: "t", Key: "token", Deliver: DeliverInject}, ""},
		{GrantSecret{Name: "db"}, `key is required: name one key (key: KEY) or every key (key: "*")`},
		{GrantSecret{Name: "db", Deliver: DeliverFile}, `or every key (key: "*")`},
		{GrantSecret{Name: "t", Deliver: DeliverInject}, "name the one key to inject"},
		{GrantSecret{Name: "t", Key: AllKeys, Deliver: DeliverInject}, `inject adds one key: name it (key: KEY), not "*"`},
		{GrantSecret{Name: "db", Key: "a/b"}, `key "a/b"`},
		{GrantSecret{Name: "db", Key: "**"}, `key "**"`},
	} {
		got := c.gs.KeyRefProblem()
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%+v: %q, want %q", c.gs, got, c.want)
		}
	}
}

func TestFixedKey(t *testing.T) {
	for typ, want := range map[string]string{"": "", SecretOpaque: "", SecretRegistry: PasswordKey, SecretEd25519: PrivateKeyKey, SecretECDSAP256: PrivateKeyKey} {
		if got := FixedKey(typ); got != want {
			t.Errorf("FixedKey(%q) = %q, want %q", typ, got, want)
		}
	}
	if PasswordKey != "password" || PrivateKeyKey != "private-key" || CertificateKey != "tls.pem" || AllKeys != "*" {
		t.Fatal("the fixed key names changed")
	}
	for _, k := range []string{PasswordKey, PrivateKeyKey, CertificateKey} {
		if !ValidKey(k) {
			t.Errorf("%q must be a valid key", k)
		}
	}
	if ValidKey(AllKeys) {
		t.Fatal(`"*" must never be a key`)
	}
}
