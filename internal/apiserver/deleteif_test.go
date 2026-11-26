package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// K-031: a DELETE that says which object the caller saw (its UID, and its version where the
// caller has one) deletes only that object. A caller that decided from a stale view must not
// remove what now has the name: a new object under it, or the same one changed since.
func TestK031DeleteCarriesWhatTheCallerSaw(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	mk := func() *v1.IP {
		x := &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "x", Namespace: "d"}, Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "x"}}
		must(c.Create(ctx, x))
		return x
	}
	del := func(q url.Values) int {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL+"/apis/kevaso/v1/namespaces/d/ips/x?"+q.Encode(), nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	exists := func() *v1.IP {
		var x v1.IP
		if err := c.Get(ctx, "IP", "d", "x", &x); err != nil {
			return nil
		}
		return &x
	}

	seen := mk()
	must(c.Delete(ctx, "IP", "d", "x"))
	now := mk() // the same name, another object
	if code := del(url.Values{"uid": {seen.UID}}); code != http.StatusConflict {
		t.Errorf("delete of uid %s answered %d, want 409", seen.UID, code)
	}
	if x := exists(); x == nil || x.UID != now.UID {
		t.Fatal("a delete for the old object removed the new one of the same name")
	}
	// The same object, changed since the caller read it.
	read := *exists()
	read.Labels = map[string]string{"changed": "yes"} // an IP's spec never changes
	changed := read
	must(c.Update(ctx, &changed))
	if code := del(url.Values{"uid": {now.UID}, "resourceVersion": {now.ResourceVersion}}); code != http.StatusConflict {
		t.Errorf("delete at an old version answered %d, want 409", code)
	}
	if exists() == nil {
		t.Fatal("a delete at an old version removed the object")
	}
	// What the caller saw, as it is: deleted. And by name alone, as before.
	if code := del(url.Values{"uid": {now.UID}, "resourceVersion": {changed.ResourceVersion}}); code != http.StatusOK {
		t.Errorf("delete of what is there answered %d", code)
	}
	mk()
	if code := del(nil); code != http.StatusOK || exists() != nil {
		t.Errorf("delete by name answered %d", code)
	}
}
