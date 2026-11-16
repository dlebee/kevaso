package agent

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// bootInit is a runtime whose init step succeeds and whose main process can be counted.
// Until that process is started, Status says the machine failed.
type bootInit struct {
	*fake.Runtime
	starts atomic.Int32
}

func (b *bootInit) RunInit(context.Context, kri.ID, kri.InitStep, io.Writer) (int, error) {
	return 0, nil
}

func (b *bootInit) Start(ctx context.Context, id kri.ID) error {
	b.starts.Add(1)
	return b.Runtime.Start(ctx, id)
}

func (b *bootInit) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	if b.starts.Load() == 0 {
		return kri.Status{State: kri.Failed, Message: "the vmm exited"}, nil
	}
	return b.Runtime.Status(ctx, id)
}

// Rule 1: a crash restart that runs every-boot init claims the start again immediately before
// the main process. Init can outlast a renewal; the main process follows a claim that applied
// on the silo as stored then. Placed elsewhere during that init, it is not started here.
func TestACrashRestartClaimsAgainBeforeTheMainProcess(t *testing.T) {
	inner := fake.New()
	boot := &bootInit{Runtime: inner}
	g := newGuardRig(t, boot, func(a *Agent) { a.ClaimRefresh = time.Hour })
	s := g.create(guardSilo("web", func(s *v1.Silo) {
		s.Spec.Init = &v1.Init{When: "everyBoot", Steps: []v1.InitStep{{Name: "boot", Run: "true"}}}
	}), "hv1", "")
	if err := inner.Create(g.ctx, kri.Spec{ID: idOf(s), Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	g.cacheIs(s)

	mover := client.New(g.ts.URL)
	var moved atomic.Bool
	ac := client.New(g.ts.URL)
	ac.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err == nil && resp != nil && resp.StatusCode < 300 && r.Method == http.MethodPut && bytes.Contains(body, []byte(`"state":"Done"`)) && !moved.Swap(true) {
			for {
				var cur v1.Silo
				if e := mover.Get(g.ctx, "Silo", "dev", "web", &cur); e != nil {
					t.Errorf("reading the silo to place it elsewhere: %v", e)
					break
				}
				cur.Status.Host = "hv2"
				e := mover.UpdateStatus(g.ctx, &cur)
				if e == nil || !client.IsConflict(e) {
					if e != nil {
						t.Errorf("placing the silo elsewhere: %v", e)
					}
					break
				}
			}
		}
		return resp, err
	})}
	g.a.Client = ac

	_, err := g.reconcile("web")
	if n := boot.starts.Load(); n != 0 {
		t.Fatalf("the main process was started after the silo was placed elsewhere (%d starts): %v", n, err)
	}
	if got := g.stored("web").Status.Host; got != "hv2" {
		t.Fatalf("host %q, want hv2 (reconcile %v): the boot init never finished while the silo was still here", got, err)
	}
}
