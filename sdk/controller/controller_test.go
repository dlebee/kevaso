package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// fakeAPI lists one Silo and no Hosts; the Host list waits until releaseHosts is closed. Watches
// stay open with nothing on them.
type fakeAPI struct{ releaseHosts chan struct{} }

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("watch") != "" {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return
	}
	items := []any{}
	switch {
	case strings.HasSuffix(r.URL.Path, "/hosts"):
		select {
		case <-f.releaseHosts:
		case <-r.Context().Done():
			return
		}
	case strings.HasSuffix(r.URL.Path, "/silos"):
		items = append(items, &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"},
			ObjectMeta: meta.ObjectMeta{Name: "s", Namespace: "d", UID: "u1", ResourceVersion: "1"}})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items, "metadata": map[string]string{"resourceVersion": "1"}})
}

// K-027's shape in the plugin SDK: a controller that also reads another kind's cache (Also) must
// not reconcile before that cache has its first list, or it takes "not listed yet" for "gone".
func TestK027WorkersWaitForEveryWatchedCache(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	api := &fakeAPI{releaseHosts: make(chan struct{})}
	ts := httptest.NewServer(api)
	defer ts.Close()
	defer cancel()
	c := client.New(ts.URL)
	silos, hosts := informer.New(c, "Silo"), informer.New(c, "Host")

	var once sync.Once
	waitingFor = func(kind string) {
		if kind == "Host" {
			once.Do(func() { close(api.releaseHosts) })
		}
	}
	defer func() { waitingFor = func(string) {} }()
	reconciled := make(chan bool, 1)
	ctl := &Controller{Name: "t", Informer: silos,
		Also: []Watch{{Informer: hosts, Map: func(informer.Key) []informer.Key { return nil }}},
		Reconcile: func(ctx context.Context, k informer.Key) (Result, error) {
			select {
			case reconciled <- hosts.Synced():
			default:
			}
			return Result{}, nil
		}}
	go ctl.Run(ctx)
	select {
	case synced := <-reconciled:
		if !synced {
			t.Fatal("reconciled before the Host cache it also reads had its first list")
		}
	case <-ctx.Done():
		t.Fatal("never reconciled")
	}
}
