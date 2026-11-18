package kvoadm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// With no silos on the host, host remove deletes it and does not send confirmOff, including
// when --confirm-off was passed. A silo placed after that list makes the server answer 409;
// the command then shows the list, asks, and sends confirmOff only after a yes.
func TestHostRemoveWithoutSilosDoesNotConfirmOff(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	var queries []string
	mem := store.NewMemory(0)
	srv, err := apiserver.New(mem, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/hosts/") {
			mu.Lock()
			queries = append(queries, r.URL.Path+"?"+r.URL.RawQuery)
			mu.Unlock()
			if strings.HasSuffix(r.URL.Path, "/hosts/hvlate") && !strings.Contains(r.URL.RawQuery, "confirmOff=true") {
				once.Do(func() {
					s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"},
						ObjectMeta: meta.ObjectMeta{Name: "late", Namespace: "dev"},
						Spec:       v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Availability: v1.Availability{OnHostLoss: v1.OnHostLossRecreate}}}
					s.Status.Host = "hvlate"
					b, err := json.Marshal(s)
					if err != nil {
						t.Error(err)
						return
					}
					if _, err := mem.Create(r.Context(), store.Key{Kind: "Silo", Namespace: "dev", Name: "late"}, b); err != nil {
						t.Error(err)
					}
				})
			}
		}
		srv.ServeHTTP(w, r)
	}))
	defer ts.Close()
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hv1", "hv2", "hvlate"} {
		if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	say := func(f string, a ...any) { fmt.Fprintf(&out, f+"\n", a...) }

	if err := removeWorkerHost(ctx, c, "hv1", false, strings.NewReader(""), say); err != nil {
		t.Fatal(err)
	}
	if err := removeWorkerHost(ctx, c, "hv2", true, strings.NewReader(""), say); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]string(nil), queries...)
	mu.Unlock()
	for _, q := range got {
		if strings.Contains(q, "confirmOff=true") {
			t.Fatalf("confirmOff was sent with no silos on the host: %s", q)
		}
	}
	for _, name := range []string{"hv1", "hv2"} {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", name, &h); !client.IsNotFound(err) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	out.Reset()
	if err := removeWorkerHost(ctx, c, "hvlate", false, strings.NewReader("y\n"), say); err != nil {
		t.Fatalf("after the server saw a silo: %v\n%s", err, out.String())
	}
	text := out.String()
	if !strings.Contains(text, "Is hvlate off or wiped?") {
		t.Fatalf("the question was not asked:\n%s", text)
	}
	mu.Lock()
	got = append([]string(nil), queries...)
	mu.Unlock()
	var first, second string
	for _, q := range got {
		if !strings.Contains(q, "/hosts/hvlate") {
			continue
		}
		if first == "" {
			first = q
			continue
		}
		second = q
	}
	if first == "" || strings.Contains(first, "confirmOff=true") {
		t.Fatalf("first delete: %q", first)
	}
	if second == "" || !strings.Contains(second, "confirmOff=true") {
		t.Fatalf("second delete: %q", second)
	}
	var h v1.Host
	if err := c.Get(ctx, "Host", "", "hvlate", &h); !client.IsNotFound(err) {
		t.Fatalf("hvlate: %v", err)
	}
}
