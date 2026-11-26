package v1

import (
	"strings"
	"testing"
)

func TestDecodeStrict(t *testing.T) {
	good := `{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"a"},"spec":{"runtime":"docker","container":{"image":"nginx"}}}`
	if _, k, err := DecodeStrict([]byte(good)); err != nil || k.Kind != "Silo" {
		t.Fatalf("a good silo: %v %v", k.Kind, err)
	}
	// What Decode drops, DecodeStrict refuses: a misspelled sources would open the port to all.
	typo := `{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"a"},"spec":{"runtime":"docker","ports":[{"name":"w","port":80}],"services":[{"type":"HostPort","ports":[{"port":"w","source":["10.0.0.0/8"]}]}]}}`
	if _, _, err := Decode([]byte(typo)); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if _, _, err := DecodeStrict([]byte(typo)); err == nil || !strings.Contains(err.Error(), `unknown field "source"`) {
		t.Fatalf("DecodeStrict kept a misspelled field: %v", err)
	}
	// The ways in are strict structs: a misspelled way, or a kind/name string, is refused.
	for field, bad := range map[string]string{
		"wrker": `"services":[{"type":"HostPort","hostPort":{"wrker":"external"},"ports":[{"port":"w"}]}]`,
		"class": `"services":[{"type":"LoadBalancer","loadBalancer":{"class":"x"},"ports":[{"port":"w"}]}]`,
		"ip":    `"services":[{"type":"HostPort","hostPort":"ip/edge","ports":[{"port":"w"}]}]`,
		"pool":  `"network":{"egress":{"source":"pool"}}`,
	} {
		obj := `{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"a"},"spec":{"runtime":"docker","ports":[{"name":"w","port":80}],` + bad + `}}`
		if _, _, err := DecodeStrict([]byte(obj)); err == nil {
			t.Errorf("%s: DecodeStrict took %s", field, bad)
		}
	}
	for kind, bad := range map[string]string{
		"IP":    `{"apiVersion":"kevaso/v1","kind":"IP","metadata":{"name":"a","namespace":"n"},"spec":{"type":"Provider","class":"linode"}}`,
		"IPSet": `{"apiVersion":"kevaso/v1","kind":"IPSet","metadata":{"name":"a","namespace":"n"},"spec":{"type":"Static","members":[{"host":"h"}]}}`,
		"Host":  `{"apiVersion":"kevaso/v1","kind":"Host","metadata":{"name":"a"},"spec":{"externalIP":"203.0.113.1","components":{},"network":{"addresses":["203.0.113.2"]}}}`,
	} {
		if _, _, err := DecodeStrict([]byte(bad)); err == nil {
			t.Errorf("%s: DecodeStrict took an old or misspelled field", kind)
		}
	}
	// A defined kind's fields are its schema's, checked by the server.
	defined := `{"apiVersion":"db.example.com/v1","kind":"Database","metadata":{"name":"a"},"spec":{"anything":1}}`
	if _, _, err := DecodeStrict([]byte(defined)); err != nil {
		t.Fatalf("a defined kind: %v", err)
	}
}
