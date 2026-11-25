package kvo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretFlagsKeys(t *testing.T) {
	dir := t.TempDir()
	user, pw := filepath.Join(dir, "user"), filepath.Join(dir, "a=b.txt")
	_ = os.WriteFile(user, []byte("app\n"), 0o600)
	_ = os.WriteFile(pw, []byte("pw"), 0o600)

	value, data, err := secretOpts{fromFiles: []string{pw}}.keys(strings.NewReader(""))
	if err != nil || string(value) != "pw" || data != nil {
		t.Fatalf("a bare FILE (even with = in it) is the one value: %q %v %v", value, data, err)
	}
	value, data, err = secretOpts{fromFiles: []string{"username=" + user, "password=-"}}.keys(strings.NewReader("s3cret\n"))
	if err != nil || value != nil || string(data["username"]) != "app" || string(data["password"]) != "s3cret" {
		t.Fatalf("keys: %q %v %v", value, data, err)
	}
	for _, bad := range []secretOpts{
		{fromFiles: []string{user, "password=" + pw}},         // a bare FILE among keys
		{fromFiles: []string{"a=-", "b=-"}},                   // stdin twice
		{fromFiles: []string{"a=" + user, "a=" + pw}},         // a key twice
		{fromLiterals: []string{"a=b"}},                       // no --i-know
		{fromLiterals: []string{"just-a-value"}, iKnow: true}, // literals are KEY=VALUE
	} {
		if _, _, err := bad.keys(strings.NewReader("x")); err == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
	if _, data, err := (secretOpts{fromLiterals: []string{"value=tok=="}, iKnow: true}).keys(nil); err != nil || string(data["value"]) != "tok==" {
		t.Fatalf("literal: %v %v", data, err)
	}
}
