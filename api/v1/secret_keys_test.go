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
	single := []string{ValueKey}
	for _, c := range []struct {
		gs   GrantSecret
		key  string
		have []string
		file string
		env  string
	}{
		{GrantSecret{Name: "db"}, "password", multi, "/run/secrets/db/password", "DB_PASSWORD"},
		{GrantSecret{Name: "db", Path: "/run/db", Env: "PG"}, "username", multi, "/run/db/username", "PG_USERNAME"},
		{GrantSecret{Name: "db", Key: "password"}, "password", multi, "/run/secrets/db/password", "DB_PASSWORD"},
		{GrantSecret{Name: "db", Key: "password", Path: "/run/pw", Env: "PGPASSWORD"}, "password", multi, "/run/pw", "PGPASSWORD"},
		{GrantSecret{Name: "api-token"}, ValueKey, single, "/run/secrets/api-token", "API_TOKEN"},
		{GrantSecret{Name: "api-token", Path: "/run/t/token", Env: "TOKEN"}, ValueKey, single, "/run/t/token", "TOKEN"},
		{GrantSecret{Name: "my.cert"}, "tls.crt", []string{"tls.crt", "tls.key"}, "/run/secrets/my.cert/tls.crt", "MY_CERT_TLS_CRT"},
	} {
		if got := c.gs.FilePath(c.key, c.have); got != c.file {
			t.Errorf("%+v key %s: file %s, want %s", c.gs, c.key, got, c.file)
		}
		if got := c.gs.EnvName(c.key); got != c.env {
			t.Errorf("%+v key %s: env %s, want %s", c.gs, c.key, got, c.env)
		}
	}
	all := GrantSecret{Name: "db"}
	one := GrantSecret{Name: "db", Key: "password"}
	if !slices.Equal(all.Keys(multi), multi) || !slices.Equal(one.Keys(multi), []string{"password"}) || one.Keys(single) != nil {
		t.Fatal("Keys")
	}
	if all.InjectKey(multi) != "" || all.InjectKey([]string{"token"}) != "token" || one.InjectKey(multi) != "password" || one.InjectKey(single) != "" {
		t.Fatal("InjectKey")
	}
}
