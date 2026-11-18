package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

func removedAPI(msg string, code int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(client.Error{Code: code, Reason: http.StatusText(code), Message: msg})
	}))
}

func runningSilo(t *testing.T) (*fake.Runtime, kri.ID) {
	t.Helper()
	rt := fake.New()
	id := kri.ID{Namespace: "ns", Name: "web", UID: "uid-web"}
	if err := rt.Create(context.Background(), kri.Spec{ID: id}); err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	return rt, id
}

// The distinct removal 401 stops every silo and leaves its disk. Reconcile does nothing
// further. Any other error is returned and the silo keeps running.
func TestRemovedHostStopsSilosAndKeepsDisks(t *testing.T) {
	rt, id := runningSilo(t)
	srv := removedAPI("host hv1 was removed from the cluster; join it again with kvoadm host add", http.StatusUnauthorized)
	defer srv.Close()
	c := client.New(srv.URL)
	a := &Agent{
		Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"fake": rt},
		Log: func(string, ...any) {}, silos: informer.New(c, "Silo"),
	}
	a.sawDelete(id, false, a.watermark().history())
	res, err := a.Reconcile(context.Background(), engine.Key{Kind: "Silo", Namespace: id.Namespace, Name: id.Name})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("a removal was retried: %v", res.RequeueAfter)
	}
	st, _ := rt.Status(context.Background(), id)
	if st.State != kri.Stopped {
		t.Fatalf("state %s, want stopped", st.State)
	}
	if _, ok := rt.Spec(id); !ok {
		t.Fatal("the disk was deleted")
	}
	for _, call := range rt.Calls {
		if strings.HasPrefix(call, "delete") {
			t.Fatalf("delete was called: %v", rt.Calls)
		}
	}
	before := len(rt.Calls)
	if _, err := a.Reconcile(context.Background(), engine.Key{Kind: "Silo", Namespace: id.Namespace, Name: id.Name}); err != nil {
		t.Fatal(err)
	}
	if len(rt.Calls) != before {
		t.Fatalf("reconcile after removal did more work: %v", rt.Calls[before:])
	}
}

// A stop that does not finish is killed, the way the fence kills. The disk stays.
func TestRemovedHostKillsASiloThatDoesNotStop(t *testing.T) {
	rt, id := runningSilo(t)
	a := &Agent{
		HostName: "hv1", Runtimes: map[string]kri.Runtime{"fake": noStop{rt}},
		Log: func(string, ...any) {},
	}
	a.HostRemoved(context.Background())
	st, _ := rt.Status(context.Background(), id)
	if st.State != kri.Stopped {
		t.Fatalf("state %s, want stopped", st.State)
	}
	if _, ok := rt.Spec(id); !ok {
		t.Fatal("the disk was deleted")
	}
	killed := false
	for _, call := range rt.Calls {
		if strings.HasPrefix(call, "delete") {
			t.Fatalf("delete was called: %v", rt.Calls)
		}
		if strings.HasPrefix(call, "kill") {
			killed = true
		}
	}
	if !killed {
		t.Fatalf("a stop that failed was not killed: %v", rt.Calls)
	}
}

type noStop struct{ *fake.Runtime }

func (noStop) Stop(context.Context, kri.ID) error {
	return errors.New("the guest ignored the power button")
}

func TestAnotherErrorDoesNotStopTheHost(t *testing.T) {
	rt, id := runningSilo(t)
	srv := removedAPI("unavailable", http.StatusInternalServerError)
	defer srv.Close()
	c := client.New(srv.URL)
	a := &Agent{
		Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"fake": rt},
		Log: func(string, ...any) {}, silos: informer.New(c, "Silo"),
	}
	a.sawDelete(id, false, a.watermark().history())
	_, err := a.Reconcile(context.Background(), engine.Key{Kind: "Silo", Namespace: id.Namespace, Name: id.Name})
	if err == nil || client.HostWasRemoved(err) {
		t.Fatalf("want the server error, got %v", err)
	}
	if a.removed.Load() {
		t.Fatal("an ordinary error was treated as removal")
	}
	st, _ := rt.Status(context.Background(), id)
	if st.State != kri.Running {
		t.Fatalf("state %s, want still running", st.State)
	}
}
