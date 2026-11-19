package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

func restoreFixture(t *testing.T) (context.Context, *client.Client, *v1.Silo) {
	t.Helper()
	ctx := context.Background()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	c := client.New(ts.URL)
	if err := c.Create(ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hv1", "hv2"} {
		if err := c.Create(ctx, host(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Create(ctx, &v1.RestoreGate{
		TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RestoreGate"},
		ObjectMeta: meta.ObjectMeta{Name: v1.RestoreGateName},
		Spec:       v1.RestoreGateSpec{History: "h2", Started: time.Now().UTC(), NoHostsAdded: true, Required: []string{"hv1", "hv2"}},
	}); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	return ctx, c, s
}

func reportCopy(t *testing.T, ctx context.Context, c *client.Client, hostName string, running bool) {
	t.Helper()
	var h v1.Host
	if err := c.Get(ctx, "Host", "", hostName, &h); err != nil {
		t.Fatal(err)
	}
	var s v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "web", &s); err != nil {
		t.Fatal(err)
	}
	h.Status.Copies = &v1.HostCopies{History: "h2", Reported: true, Held: []v1.HostHeldCopy{{
		Namespace: "dev", Name: "web", UID: s.UID, Running: running,
	}}}
	if err := c.UpdateStatus(ctx, &h); err != nil {
		t.Fatal(err)
	}
}

func freezeWeb(t *testing.T, ctx context.Context, c *client.Client, hostName, movingFrom string) *v1.Silo {
	t.Helper()
	var s v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "web", &s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = hostName
	s.Status.MovingFrom = movingFrom
	s.Status.Phase = "Running"
	s.Status.SiloIP = "10.64.0.2"
	s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Handle: "vol-1", AttachedTo: "hv1", Mounted: true}}
	s.Status.Restore = &v1.SiloRestore{History: "h2", Phase: v1.RestoreFrozen, Holders: []string{"hv1", "hv2"}}
	s.Status.Conditions = []meta.Condition{{Type: "Frozen", Status: meta.ConditionTrue, Reason: "RestoreConflict", Message: "frozen"}}
	if err := c.UpdateStatus(ctx, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func TestRestoreSettlePlacesTheReportedCopyAndKeepsTheOtherDisk(t *testing.T) {
	ctx, c, _ := restoreFixture(t)
	reportCopy(t, ctx, c, "hv1", false)
	reportCopy(t, ctx, c, "hv2", true)
	s := freezeWeb(t, ctx, c, "hv1", "hv9")
	s.Status.Host, s.Status.MovingFrom, s.Status.SiloIP = "hv2", "", ""
	s.Status.Phase = "Scheduled"
	s.Status.Restore.Phase = v1.RestoreSettled
	s.Status.Conditions = nil
	if err := c.UpdateStatus(ctx, s); !client.IsConflict(err) {
		t.Fatalf("a status write cleared the handoff from hv9: %v", err)
	}
	var out v1.Silo
	err := c.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/web/restore-settle", map[string]string{"to": "hv2"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status.Host != "hv2" || out.Status.SiloIP != "" || out.Status.Phase != "Scheduled" || out.Status.MovingFrom != "" {
		t.Fatalf("placed: %+v", out.Status)
	}
	if out.Status.Restore == nil || out.Status.Restore.History != "h2" || out.Status.Restore.Phase != v1.RestoreSettled {
		t.Fatalf("restore: %+v", out.Status.Restore)
	}
	if meta.FindCondition(out.Status.Conditions, "Frozen") != nil {
		t.Fatalf("Frozen stayed: %+v", out.Status.Conditions)
	}
	if len(out.Status.Volumes) != 1 || !out.Status.Volumes[0].Mounted || out.Status.Volumes[0].Handle != "vol-1" {
		t.Fatalf("the other disk was not kept: %+v", out.Status.Volumes)
	}
}

func TestRestoreSettleRefuses(t *testing.T) {
	ctx, c, _ := restoreFixture(t)
	reportCopy(t, ctx, c, "hv2", true)
	freezeWeb(t, ctx, c, "hv1", "")
	post := func(to string) error {
		return c.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/web/restore-settle", map[string]string{"to": to}, &v1.Silo{})
	}
	if err := post("hv1"); code(err) != http.StatusConflict || !strings.Contains(err.Error(), "has not reported a copy") {
		t.Fatalf("a host that reported nothing: %v", err)
	}
	var s v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "web", &s); err != nil {
		t.Fatal(err)
	}
	s.Status.Restore.Phase = v1.RestoreSettled
	if err := c.UpdateStatus(ctx, &s); err != nil {
		t.Fatal(err)
	}
	if err := post("hv2"); code(err) != http.StatusConflict || !strings.Contains(err.Error(), "is not frozen") {
		t.Fatalf("a silo that is not frozen: %v", err)
	}
	s.Status.Restore = &v1.SiloRestore{History: "h1", Phase: v1.RestoreFrozen, Holders: []string{"hv2"}}
	if err := c.UpdateStatus(ctx, &s); err != nil {
		t.Fatal(err)
	}
	if err := post("hv2"); code(err) != http.StatusConflict || !strings.Contains(err.Error(), "not this history") {
		t.Fatalf("another history: %v", err)
	}
}

func TestRestoreSettleRefusesANonAdmin(t *testing.T) {
	e := setupAccess(t)
	if err := e.admin.Create(e.ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hv1", "hv2"} {
		if err := e.admin.Create(e.ctx, host(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.admin.Create(e.ctx, &v1.RestoreGate{
		TypeMeta:   accessTM("RestoreGate"),
		ObjectMeta: meta.ObjectMeta{Name: v1.RestoreGateName},
		Spec:       v1.RestoreGateSpec{History: "h2", Started: time.Now().UTC(), NoHostsAdded: true, Required: []string{"hv1", "hv2"}},
	}); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: accessTM("Silo"), ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}
	if err := e.admin.Create(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Get(e.ctx, "Silo", "dev", "web", s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = "hv1"
	s.Status.Restore = &v1.SiloRestore{History: "h2", Phase: v1.RestoreFrozen, Holders: []string{"hv2"}}
	if err := e.admin.UpdateStatus(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	var h v1.Host
	if err := e.admin.Get(e.ctx, "Host", "", "hv2", &h); err != nil {
		t.Fatal(err)
	}
	h.Status.Copies = &v1.HostCopies{History: "h2", Reported: true, Held: []v1.HostHeldCopy{{Namespace: "dev", Name: "web", UID: s.UID, Running: true}}}
	if err := e.admin.UpdateStatus(e.ctx, &h); err != nil {
		t.Fatal(err)
	}
	post := func(c *client.Client) error {
		return c.Call(e.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/web/restore-settle", map[string]string{"to": "hv2"}, &v1.Silo{})
	}
	adminSA := e.serviceAccount(t, "dev", "ada")
	if err := e.admin.Create(e.ctx, &v1.RoleBinding{TypeMeta: accessTM("RoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "ada", Namespace: "dev"},
		RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "admin"}, Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: "ada", Namespace: "dev"}}}); err != nil {
		t.Fatal(err)
	}
	if err := post(adminSA); code(err) != http.StatusForbidden || !strings.Contains(err.Error(), "cluster-admin") {
		t.Fatalf("a namespace admin: %v", err)
	}
	narrow := e.serviceAccount(t, "ops", "bot")
	e.grant(t, "settle-only", "ops", "bot", v1.PolicyRule{Verbs: []string{"create"}, Resources: []string{"silos/restore-settle"}})
	if err := post(narrow); code(err) != http.StatusForbidden || !strings.Contains(err.Error(), "cluster-admin") {
		t.Fatalf("a role that is not cluster-admin: %v", err)
	}
	if err := post(e.admin); err != nil {
		t.Fatalf("cluster-admin: %v", err)
	}
}
