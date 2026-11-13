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
	typo := `{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"a"},"spec":{"runtime":"docker","ports":[{"name":"w","port":80}],"service":{"ports":[{"port":"w","hostPort":["external"],"source":["10.0.0.0/8"]}]}}}`
	if _, _, err := Decode([]byte(typo)); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if _, _, err := DecodeStrict([]byte(typo)); err == nil || !strings.Contains(err.Error(), `unknown field "source"`) {
		t.Fatalf("DecodeStrict kept a misspelled field: %v", err)
	}
	// A defined kind's fields are its schema's, checked by the server.
	defined := `{"apiVersion":"db.example.com/v1","kind":"Database","metadata":{"name":"a"},"spec":{"anything":1}}`
	if _, _, err := DecodeStrict([]byte(defined)); err != nil {
		t.Fatalf("a defined kind: %v", err)
	}
}
