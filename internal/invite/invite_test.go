package invite

import "testing"

func TestRequestCheck(t *testing.T) {
	for _, c := range []struct {
		r  Request
		ok bool
	}{
		{Request{User: "bob"}, true},
		{Request{User: "bob", Namespace: "payments"}, true},
		{Request{User: "bob", Namespace: "payments", Role: "viewer"}, true},
		{Request{}, false},
		{Request{User: "bob", Role: "editor"}, false}, // a role needs a namespace
	} {
		if err := c.r.Check(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.r, err)
		}
	}
}
