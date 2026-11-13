package ocienv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A config.json as containerd's bundle has it (abridged), with odd spacing on purpose: everything
// but process.env must come back byte for byte.
const dockerConfig = `{"ociVersion":"1.2.0",
  "process": {"user":{"uid":0,"gid":0},"args":["/sbin/docker-init","--","sleep","infinity"],
     "env" : [ "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOSTNAME=api", "APP_TOKEN=from-the-image", "LANG=C.UTF-8", "APP_TOKEN=again" ],
     "cwd":"/","capabilities":{"bounding":["CAP_CHOWN"]}},
  "root":{"path":"/var/lib/docker/overlay2/abc/merged"},
  "annotations":{"kevaso.com/env-secrets":"0123456789","org.opencontainers.image.stopSignal":"15"},
  "linux":{"maskedPaths":["/proc/kcore"],"env":["not-this-one"]}}
`

func TestSetEnv(t *testing.T) {
	out, err := SetEnv([]byte(dockerConfig), []Var{{Name: "APP_TOKEN", Value: []byte(`s3cr"et <&> ü`)}, {Name: "DB_URL", Value: []byte("postgres://x")}})
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Process struct{ Env []string } `json:"process"`
	}
	if err := json.Unmarshal(out, &c); err != nil {
		t.Fatal(err)
	}
	want := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOSTNAME=api", `APP_TOKEN=s3cr"et <&> ü`, "LANG=C.UTF-8", "DB_URL=postgres://x"}
	if fmt.Sprint(c.Process.Env) != fmt.Sprint(want) {
		t.Fatalf("env %q\nwant %q", c.Process.Env, want)
	}
	// Byte for byte outside process.env.
	start := strings.Index(dockerConfig, `[ "PATH`)
	end := strings.Index(dockerConfig, `=again" ]`) + len(`=again" ]`)
	if !strings.HasPrefix(string(out), dockerConfig[:start]) || !strings.HasSuffix(string(out), dockerConfig[end:]) {
		t.Fatalf("bytes outside process.env changed:\n%s", out)
	}
	if !bytes.Contains(out, []byte(`<&>`)) {
		t.Error("values are escaped beyond JSON's need")
	}
}

func TestSetEnvNoEnvYet(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`{"process":{"args":["sh"]},"x":1}`, `{"process":{"env":["A=1"],"args":["sh"]},"x":1}`},
		{`{"process":{ },"x":1}`, `{"process":{"env":["A=1"] },"x":1}`},
		{`{"process":{"env":null}}`, `{"process":{"env":["A=1"]}}`},
	} {
		out, err := SetEnv([]byte(c.in), []Var{{Name: "A", Value: []byte("1")}})
		if err != nil || string(out) != c.want {
			t.Errorf("%s: %s %v, want %s", c.in, out, err, c.want)
		}
	}
}

func TestSetEnvRefuses(t *testing.T) {
	for _, c := range []struct {
		config string
		vars   []Var
		want   string
	}{
		{`{"ociVersion":"1.2.0","root":{}}`, []Var{{Name: "A", Value: []byte("1")}}, "no process"},
		{`{"process":null}`, []Var{{Name: "A", Value: []byte("1")}}, "no process"},
		{`{"process":{"env":[]},"process":{"env":[]}}`, []Var{{Name: "A", Value: []byte("1")}}, "twice"},
		{`{"process":{"env":[],"env":["B=2"]}}`, []Var{{Name: "A", Value: []byte("1")}}, "twice"},
		{`{"process":{"env":"x"}}`, []Var{{Name: "A", Value: []byte("1")}}, "process.env"},
		{`{"process":{}} {}`, []Var{{Name: "A", Value: []byte("1")}}, "after the object"},
		{`[1]`, []Var{{Name: "A", Value: []byte("1")}}, "not an object"},
		{`{"process":{}}`, []Var{{Name: "A", Value: []byte{0xff, 0xfe}}}, "UTF-8"},
		{`{"process":{}}`, []Var{{Name: "1A", Value: []byte("1")}}, "variable name"},
	} {
		_, err := SetEnv([]byte(c.config), c.vars)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.config, err, c.want)
		}
		if err != nil && bytes.Contains([]byte(err.Error()), []byte{0xff}) {
			t.Error("an error carries the value")
		}
	}
}

// A config with thousands of mounts and a long env: the edit is exact and keeps the rest.
func TestSetEnvLarge(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"ociVersion":"1.2.0","mounts":[`)
	for i := range 50000 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"destination":"/m/%d","type":"bind","source":"/s/%d","options":["rbind","ro"]}`, i, i)
	}
	b.WriteString(`],"process":{"env":[`)
	for i := range 2000 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"V%d=%s"`, i, strings.Repeat("x", 100))
	}
	b.WriteString(`],"args":["sh"]},"annotations":{}}`)
	in := b.String()
	out, err := SetEnv([]byte(in), []Var{{Name: "V7", Value: []byte("new")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(in) < 4<<20 {
		t.Fatalf("not large: %d bytes", len(in))
	}
	i := strings.Index(in, `"env":[`) + len(`"env":`)
	if string(out[:i]) != in[:i] || !strings.HasSuffix(string(out), `,"args":["sh"]},"annotations":{}}`) {
		t.Fatal("bytes outside process.env changed")
	}
	if !bytes.Contains(out, []byte(`"V7=new"`)) || bytes.Count(out, []byte(`"V7=`)) != 1 || !bytes.Contains(out, []byte(`"V1999=`)) {
		t.Fatal("env not edited right")
	}
}

func TestParseEnvFile(t *testing.T) {
	vars, err := ParseEnvFile([]byte("A=1\nB=x=y z\n\nC=\n"))
	if err != nil || len(vars) != 3 || string(vars[1].Value) != "x=y z" || vars[2].Name != "C" || len(vars[2].Value) != 0 {
		t.Fatalf("%v %v", vars, err)
	}
	for _, bad := range []string{"novalue\n", "1A=x\n", "A=1\nA=2\n", "=x\n"} {
		_, err := ParseEnvFile([]byte(bad))
		if err == nil {
			t.Errorf("%q: no error", bad)
		} else if strings.Contains(err.Error(), "x") && strings.Contains(bad, "=x") {
			t.Errorf("%q: the error shows the line: %v", bad, err)
		}
	}
}
