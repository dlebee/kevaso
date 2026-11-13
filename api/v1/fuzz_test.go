package v1

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

// FuzzParseImageRef: container.image goes to docker/podman pull as an argument, as written, once
// admission has parsed it. Whatever parses can't be read as a flag or carry a space or a control
// character, and parsing what it prints gives it back.
//
//	cd api && go test ./v1 -run '^$' -fuzz FuzzParseImageRef -fuzztime 60s
func FuzzParseImageRef(f *testing.F) {
	for _, s := range []string{"nginx", "nginx:1.27", "library/nginx", "ghcr.io/acme/api:v1", "ghcr.io/acme/api@sha256:" + strings.Repeat("a", 64),
		"localhost:5000/x", "registry.example.com:5000/a/b/c:tag@sha256:" + strings.Repeat("0", 64), "-v", "--config=/etc", "a b", "x\ny",
		"index.docker.io/x", "UPPER/case", "a:b:c", "@sha256:", ":tag", "a/", "/a", "a//b", "ghcr.io:99999/x", "ghcr.io/x:" + strings.Repeat("t", 129)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseImageRef(s)
		if err != nil {
			return
		}
		if strings.HasPrefix(s, "-") {
			t.Fatalf("%q parsed: a pull would read it as a flag", s)
		}
		for _, c := range s {
			if unicode.IsSpace(c) || unicode.IsControl(c) || c > unicode.MaxASCII {
				t.Fatalf("%q parsed with %q in it", s, c)
			}
		}
		if r.Repository == "" || r.Registry == "" {
			t.Fatalf("%q parsed to %+v", s, r)
		}
		again, err := ParseImageRef(r.String())
		if err != nil || again != r {
			t.Fatalf("%q → %+v → %q → %+v, %v", s, r, r.String(), again, err)
		}
		if r.Pinned() != strings.Contains(s, "@") {
			t.Fatalf("%q: pinned %v", s, r.Pinned())
		}
	})
}

// FuzzDecodeStrict: what kvo apply reads from a file. Anything decodes or fails cleanly, and
// what decodes round-trips: encoding it and decoding again gives the same object.
//
//	cd api && go test ./v1 -run '^$' -fuzz FuzzDecodeStrict -fuzztime 60s
func FuzzDecodeStrict(f *testing.F) {
	for _, s := range []string{
		`{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"a","namespace":"d","labels":{"x":"y"}},"spec":{"runtime":"docker","container":{"image":"nginx"},"ports":[{"name":"w","port":80}],"service":{"ports":[{"port":"w","hostPort":["external"],"sources":["10.0.0.0/8"]}]}}}`,
		`{"apiVersion":"kevaso/v1","kind":"Grant","metadata":{"name":"g"},"spec":{"egress":[{"to":"api.example.com","ports":["443"]}]}}`,
		`{"apiVersion":"kevaso/v1","kind":"Secret","metadata":{"name":"s"},"spec":{"value":"eA=="}}`,
		`{"apiVersion":"kevaso/v1","kind":"Host","metadata":{"name":"h"},"spec":{"internalIP":"10.0.0.5","components":{"worker":{}}}}`,
		`{"apiVersion":"db.example.com/v1","kind":"Database","metadata":{"name":"a"},"spec":{"size":1}}`,
		`{"apiVersion":"kevaso/v1","kind":"Silo","spec":{"servce":{}}}`,
		`{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"a"},"metadata":{"name":"b"}}`,
		`{"apiVersion":"kevaso/v1","kind":"Silo","Metadata":{"name":"a"}}`,
		`[]`, `null`, `{"kind":1}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		obj, k, err := DecodeStrict(data)
		if err != nil {
			return
		}
		if _, ok := obj.(*Unstructured); ok {
			// A defined kind: its fields are its schema's. (encoding/json matches keys without
			// regard to case, so {"ApiVersion": …} picks the kind but not the object's own
			// apiVersion: harmless, the server checks it, but not a round trip.)
			return
		}
		b, err := json.Marshal(obj)
		if err != nil {
			t.Fatalf("decoded %s, can't encode it: %v", k.Kind, err)
		}
		again, _, err := DecodeStrict(b)
		if err != nil {
			t.Fatalf("decoded %s, its encoding doesn't decode: %v\n%s", k.Kind, err, b)
		}
		b2, _ := json.Marshal(again)
		if !reflect.DeepEqual(b, b2) {
			t.Fatalf("round trip changed the %s:\n%s\n%s", k.Kind, b, b2)
		}
	})
}
