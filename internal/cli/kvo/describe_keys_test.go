package kvo

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// kvo describe grant says, for each entry, the key it names (or every key) and where it lands:
// one file or a folder, NAME_KEY or PREFIX_KEY for each key, the endpoint path to ask.
func TestDescribeGrantNamesKeys(t *testing.T) {
	g := &v1.Grant{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Grant"}, ObjectMeta: meta.ObjectMeta{Name: "app", Namespace: "dev"},
		Spec: v1.GrantSpec{Secrets: []v1.GrantSecret{
			{Name: "db", Key: "password", Deliver: v1.DeliverFile},
			{Name: "db", Key: "*", Deliver: v1.DeliverFile},
			{Name: "db", Key: "*", Deliver: v1.DeliverFile, Path: "/run/db"},
			{Name: "db", Key: "password", Deliver: v1.DeliverEnv},
			{Name: "db", Key: "password", Deliver: v1.DeliverEnv, Env: "PGPASSWORD"},
			{Name: "db-main", Key: "*", Deliver: v1.DeliverEnv},
			{Name: "db", Key: "*", Deliver: v1.DeliverEnv, Env: "PG"},
			{Name: "db", Key: "password"},
			{Name: "db", Key: "*", Deliver: v1.DeliverBroker},
			{Name: "api", Key: "token", Deliver: v1.DeliverInject, To: &v1.InjectTarget{Host: "api.example.com"}},
		}}}
	var b bytes.Buffer
	if err := describeObject(&b, g); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"db (key password): tier 4, file: /run/secrets/db/password (tmpfs",
		"db (every key): tier 4, file: /run/secrets/db/ (a folder, a file per key)",
		"db (every key): tier 4, file: /run/db/ (a folder, a file per key)",
		"db (key password): tier 4, env DB_PASSWORD ",
		"db (key password): tier 4, env PGPASSWORD ",
		"db-main (every key): tier 4, env DB_MAIN_KEY for each key ",
		"db (every key): tier 4, env PG_KEY for each key ",
		"db (key password): tier 4, broker: the silo fetches it when needed (curl -fsS -H 'Kevaso-Local: 1' http://169.254.42.1/v1/secrets/db/password)",
		"db (every key): tier 4, broker: the silo fetches it when needed (curl -fsS -H 'Kevaso-Local: 1' http://169.254.42.1/v1/secrets/db/KEY or /v1/secrets/db/* for every key)",
		"api (key token): tier 2, injection: the egress gate adds Authorization: Bearer {{value}} for api.example.com ({{value}}: the key's value)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "single value") || strings.Contains(out, "one file for") {
		t.Errorf("describe still guesses a shape:\n%s", out)
	}
}

// A secret's keys are listed by name, whatever they are: no "one value".
func TestDescribeSecretKeys(t *testing.T) {
	now := time.Now()
	for keys, want := range map[string]string{"token": "token", "password,username": "password, username"} {
		s := &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
			Status: v1.SecretStatus{Version: 1, UpdatedAt: &now, Keys: strings.Split(keys, ",")}}
		var b bytes.Buffer
		if err := describeObject(&b, s); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), "Keys:") || !strings.Contains(b.String(), want) || strings.Contains(b.String(), "one value") {
			t.Errorf("keys %s: %s", keys, b.String())
		}
	}
}
