package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

// K-119, the API server's half: on a cluster only the source host ends a handoff, or a person's
// confirm-fenced move (K-070). The one other end is the silo controller's (Component), for a
// handoff whose source is lost or gone and armed its fence for the silo as it is: the API server
// checks what it can see (the source lost, its armed fence stored), the controller the silence it
// counted. Anyone else, or without those, is still refused.
func TestK119OnlyTheControllerEndsAHandoffFromAGoneArmedSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(0)
	srv, err := apiserver.NewWithAuth(st, clock.Real{}, &apiserver.Auth{CA: ca, Tokens: &jointoken.Issuer{Store: st, Clock: clock.Real{}}})
	if err != nil {
		t.Fatal(err)
	}
	as := httptest.NewUnstartedServer(srv) // stands for the admin socket
	as.Config = srv.HTTPServer(true)
	as.Start()
	defer as.Close()
	admin := client.New(as.URL)
	comp, closeComp := srv.InProcess()
	defer closeComp()
	hostS, closeS := srv.InProcessAs(pki.Identity{Type: "host", Name: "src", Role: "worker"})
	defer closeS()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(admin.Create(ctx, ns("dev")))
	for _, h := range []string{"src", "dst"} {
		must(admin.Create(ctx, host(h)))
	}
	setLost := func(lost bool) {
		var h v1.Host
		must(admin.Get(ctx, "Host", "", "src", &h))
		h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp"}}
		if lost {
			h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionUnknown, Reason: hostctl.ReasonLost}}
		}
		must(admin.UpdateStatus(ctx, &h))
	}
	// handingOff makes NAME on src, armed by src if asked, then hands it off to dst.
	handingOff := func(name string, armed bool) {
		s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Availability: v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop}}}
		must(admin.Create(ctx, s))
		s.Status.Host, s.Status.Phase = "src", "Running"
		must(admin.UpdateStatus(ctx, s))
		if armed {
			must(admin.Get(ctx, "Silo", "dev", name, s))
			s.Status.Conditions = append(s.Status.Conditions, fence.ArmedCondition("src", 2*time.Minute, s.Generation))
			must(hostS.UpdateStatus(ctx, s))
		}
		must(admin.Get(ctx, "Silo", "dev", name, s))
		s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "dst", "src", "Scheduled"
		must(admin.UpdateStatus(ctx, s))
	}
	end := func(c *client.Client, name string) error {
		var s v1.Silo
		must(admin.Get(ctx, "Silo", "dev", name, &s))
		s.Status.MovingFrom = ""
		return c.UpdateStatus(ctx, &s)
	}

	handingOff("armed", true)
	handingOff("unarmed", false)
	setLost(false)
	if err := end(comp, "armed"); code(err) != http.StatusConflict {
		t.Fatalf("the controller ending a handoff from a live source: %v, want 409", err)
	}
	setLost(true)
	if err := end(admin, "armed"); code(err) != http.StatusConflict {
		t.Fatalf("the admin socket ending a handoff from a lost armed source: %v, want 409", err)
	}
	if err := end(comp, "unarmed"); code(err) != http.StatusConflict {
		t.Fatalf("the controller ending a handoff from a lost source that never armed: %v, want 409", err)
	}
	if err := end(comp, "armed"); err != nil {
		t.Fatalf("the controller ending a handoff from a lost armed source: %v", err)
	}
	var got v1.Silo
	must(admin.Get(ctx, "Silo", "dev", "armed", &got))
	if got.Status.MovingFrom != "" || got.Status.Host != "dst" {
		t.Fatalf("after: %+v", got.Status)
	}
	// Its Host removed counts as gone.
	handingOff("removed", true)
	must(admin.Delete(ctx, "Host", "", "src"))
	if err := end(comp, "removed"); err != nil {
		t.Fatalf("the controller ending a handoff from a removed armed source: %v", err)
	}
}
