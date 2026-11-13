package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/approvals"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/leases"
	"kevaso.com/core/internal/worker"
)

// Design §7.2d through the real API and the host's broker, with two ports leased on different
// terms (debug: a yes first, max 1h, its own sources; preview: no yes, max 2h) and one always open
// (web): a leased port is closed by default; the silo asks and waits; a too-long ask is cut to that
// port's max; opening one leaves the other closed, and each closes on its own; a person with approve on the silo's
// exposure says yes and the host's rules for the port appear; it closes early or at its end, and
// the rules go; a no fails the silo's call; an editor may open but not approve; a service account
// and a host never answer; admission refuses a lease the cluster doesn't allow; leases survive a
// restart of the API server; every step is in the audit log.
func TestPortLeases(t *testing.T) {
	c := newCluster(t)
	c.srv.SetLeaseLimits(leases.Limits{Max: 2 * time.Hour, DefaultMax: time.Hour})
	_ = c.admin.Create(c.ctx, ns("web3"))

	api := silo("api", "web3")
	ext, office := []string{v1.NetworkExternal}, []string{"203.0.113.0/24"}
	api.Spec.Ports = []v1.SiloPort{{Name: "web", Port: 8080}, {Name: "debug", Port: 9229}, {Name: "preview", Port: 3000}}
	api.Spec.Service = &v1.SiloService{
		Ports: []v1.ServicePort{{Port: "web", HostPort: ext, Sources: office},
			{Port: "debug", HostPort: ext, Sources: []string{"203.0.113.7"}, AllowFrom: []string{"worker"},
				Lease: &v1.PortLease{Max: "1h", Approval: &v1.ApprovalRule{Required: true}}},
			{Port: "preview", HostPort: ext, Sources: office, Lease: &v1.PortLease{Max: "2h"}}},
	}

	// Admission.
	for _, bad := range []struct {
		mod  func(*v1.SiloService)
		want string
	}{
		{func(sv *v1.SiloService) { sv.Ports[1].HostPort, sv.Ports[1].Sources = nil, nil },
			"service.ports[debug].lease: only on a port with hostPort or loadBalancer"},
		{func(sv *v1.SiloService) { sv.Ports[2].Lease.Max = "3h" }, "service.ports[preview].lease.max 3h0m0s is more than this cluster allows (2h0m0s)"},
		{func(sv *v1.SiloService) { sv.Ports[1].Lease.Default = "2h" }, "service.ports[debug].lease.default 2h0m0s is more than its max (1h0m0s)"},
	} {
		s := silo("bad", "web3")
		s.Spec.Ports = api.Spec.Ports
		cp := *api.Spec.Service
		cp.Ports = append([]v1.ServicePort(nil), cp.Ports...)
		for i := range cp.Ports {
			if cp.Ports[i].Lease != nil {
				l := *cp.Ports[i].Lease
				cp.Ports[i].Lease = &l
			}
		}
		bad.mod(&cp)
		s.Spec.Service = &cp
		if err := c.admin.Create(c.ctx, s); status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), bad.want) {
			t.Fatalf("admission %q: %v", bad.want, err)
		}
	}
	if err := c.admin.Create(c.ctx, api); err != nil {
		t.Fatal(err)
	}
	api.Status.Host, api.Status.SiloIP = "hv1", "10.64.2.2"
	if err := c.admin.UpdateStatus(c.ctx, api); err != nil {
		t.Fatal(err)
	}
	wk := silo("worker", "web3")
	_ = c.admin.Create(c.ctx, wk)
	wk.Status.Host, wk.Status.SiloIP = "hv1", "10.64.2.9"
	_ = c.admin.UpdateStatus(c.ctx, wk)

	// The host's rules, as its network loop would make them now.
	rules := func() string {
		t.Helper()
		var silos []*v1.Silo
		var ls []*v1.Lease
		sl, err := c.admin.List(c.ctx, "Silo", "web3")
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range sl.Items {
			o, _, _ := v1.Decode(raw)
			silos = append(silos, o.(*v1.Silo))
		}
		ll, err := c.admin.List(c.ctx, "Lease", "web3")
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range ll.Items {
			o, _, _ := v1.Decode(raw)
			ls = append(ls, o.(*v1.Lease))
		}
		return kni.Rules(worker.WithLeases(worker.NetworkView("hv1", &v1.Host{Spec: v1.HostSpec{ExternalIP: "198.51.100.10"}}, silos, nil, nil), silos, ls, time.Now()))
	}
	const (
		debugDNAT = "ip daddr 198.51.100.10 tcp dport 9229 dnat ip to 10.64.2.2:9229"
		debugFwd  = `ip daddr 10.64.2.2 ip saddr 203.0.113.7 tcp dport 9229 ct original ip daddr 198.51.100.10 ct status dnat accept`
		debugCut  = `tcp dport 9229 ct status dnat ct original ip daddr 198.51.100.10 reject with tcp reset`
		webDNAT   = "ip daddr 198.51.100.10 tcp dport 8080 dnat ip to 10.64.2.2:8080"
		private   = "ip saddr 10.64.2.9 ip daddr 10.64.2.2 tcp dport 9229 accept"
		prevDNAT  = "ip daddr 198.51.100.10 tcp dport 3000 dnat ip to 10.64.2.2:3000"
		prevFwd   = `ip daddr 10.64.2.2 ip saddr 203.0.113.0/24 tcp dport 3000 ct original ip daddr 198.51.100.10 ct status dnat accept`
	)
	preview := func(when string, open bool) {
		t.Helper()
		r := rules()
		if strings.Contains(r, prevDNAT) != open || strings.Contains(r, prevFwd) != open {
			t.Fatalf("%s: preview open %v (from its own sources):\n%s", when, open, r)
		}
	}
	closed := func(when string) {
		t.Helper()
		r := rules()
		if strings.Contains(r, debugDNAT) || strings.Contains(r, debugFwd) || !strings.Contains(r, debugCut) || !strings.Contains(r, webDNAT) || !strings.Contains(r, private) {
			t.Fatalf("%s: debug should be closed (web open, private access kept):\n%s", when, r)
		}
	}
	opened := func(when string) {
		t.Helper()
		r := rules()
		if !strings.Contains(r, debugDNAT) || !strings.Contains(r, debugFwd) || strings.Contains(r, debugCut) || !strings.Contains(r, private) {
			t.Fatalf("%s: debug should be open from 203.0.113.7:\n%s", when, r)
		}
	}
	closed("closed by default")
	preview("closed by default", false)

	// The silo's local endpoint.
	hv1Client := c.host(t, "hv1")
	eps := newEndpoints(t, hv1Client, "hv1")
	eps.add(t, api)
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()

	// People: ada (admin: open and approve), ed (editor: open only); bot, a service account with
	// the admin role.
	c.bind(t, "ada", "ClusterRole", "admin")
	c.bind(t, "ed", "ClusterRole", "editor")
	ada, ed := c.as(t, "ada"), c.as(t, "ed")
	if err := c.admin.Create(c.ctx, &v1.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ServiceAccount"},
		ObjectMeta: meta.ObjectMeta{Name: "bot", Namespace: "web3"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "bot", Namespace: "web3"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "admin"},
		Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: "bot"}}}); err != nil {
		t.Fatal(err)
	}
	var tok client.TokenResponse
	if err := c.admin.Call(c.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/web3/serviceaccounts/bot/token", client.TokenRequest{}, &tok); err != nil {
		t.Fatal(err)
	}
	bot, _ := client.NewTLS(c.url, c.ca, nil, nil)
	bot.Token = func(context.Context) (string, error) { return tok.Token, nil }

	answer := func(who *client.Client, name, verb, reason string) error {
		return who.Call(c.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/web3/approvals/"+name+"/"+verb, client.ApprovalAnswer{Reason: reason}, nil)
	}
	openAs := func(who *client.Client, verb, port, d string) (client.LeaseAnswer, error) {
		var ans client.LeaseAnswer
		err := who.Call(c.ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/web3/silos/api/"+verb, v1.LeaseOpenRequest{Port: port, For: d}, &ans)
		return ans, err
	}
	pendingApproval := func() *v1.Approval {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var a v1.Approval
			if err := ada.Get(c.ctx, "Approval", "web3", approvalsName(api.UID), &a); err == nil && a.Status.Phase == v1.ApprovalPending {
				return &a
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("no pending expose approval")
		return nil
	}
	got := make(chan epAnswer, 1)
	silosAsk := func(d string) {
		go func() {
			got <- eps.ask(t, ctx, api, http.MethodPost, "/v1/ports/debug/open?for="+d, nil, 20*time.Millisecond, nil)
		}()
	}

	// A port that isn't leased can't be asked for.
	if r := eps.call(t, api, http.MethodPost, "/v1/ports/web/open", nil); r.code != 403 || !strings.Contains(r.msg(), "not a leased port") {
		t.Fatalf("web: %d %s", r.code, r.body)
	}

	// 1. The silo asks for 5h: cut to its max (1h), and it waits for a yes.
	silosAsk("5h")
	a := pendingApproval()
	if a.Spec.Use != v1.ApprovalForExpose || a.Spec.Port != "debug" || a.Spec.For != "1h0m0s" || a.Spec.ExpiresAt.IsZero() {
		t.Fatalf("approval %+v", a.Spec)
	}
	var l v1.Lease
	if err := ada.Get(c.ctx, "Lease", "web3", leases.Name("api", "debug"), &l); err != nil || l.Status.Phase != v1.LeasePending {
		t.Fatalf("lease while pending: %+v %v", l.Status, err)
	}
	select {
	case r := <-got:
		t.Fatalf("the silo's ask didn't wait: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
	closed("while pending")

	// 2. Who can't answer: an editor (no approve on silos/exposure), a service account (even an
	// admin one), a host. Nor can a lease be written through the plain API.
	if err := answer(ed, a.Name, "approve", ""); status(err) != http.StatusForbidden {
		t.Fatalf("editor approved: %v", err)
	}
	if err := answer(bot, a.Name, "approve", ""); status(err) != http.StatusForbidden || !strings.Contains(err.Error(), "only people") {
		t.Fatalf("service account approved: %v", err)
	}
	if err := answer(hv1Client, a.Name, "approve", ""); status(err) != http.StatusForbidden {
		t.Fatalf("host approved: %v", err)
	}
	forged := l
	until := time.Now().Add(time.Hour)
	forged.Status = v1.LeaseStatus{Phase: v1.LeaseOpen, Until: &until}
	if err := c.admin.Update(c.ctx, &forged); status(err) != http.StatusMethodNotAllowed {
		t.Fatalf("lease written through the API: %v", err)
	}
	// Hosts don't open leases either.
	if _, err := openAs(hv1Client, "open", "debug", "1m"); status(err) != http.StatusForbidden {
		t.Fatalf("host opened: %v", err)
	}

	// 3. ada says yes: the silo's call goes through, for the max, and the rules appear.
	if err := answer(ada, a.Name, "approve", ""); err != nil {
		t.Fatal(err)
	}
	r := <-got
	var open agent.PortOpened
	if r.code != 200 || json.Unmarshal([]byte(r.body), &open) != nil || open.Port != "debug" || !open.Clamped ||
		time.Until(open.Until) > time.Hour || time.Until(open.Until) < 59*time.Minute {
		t.Fatalf("after yes: %d %s", r.code, r.body)
	}
	opened("approved")
	preview("debug opened", false)

	// 3b. preview is leased on its own terms: no yes, its own max (5h is cut to 2h), its own lease
	// and clock; debug's lease doesn't change.
	prA := eps.call(t, api, http.MethodPost, "/v1/ports/preview/open?for=5h", nil)
	var pr agent.PortOpened
	if prA.code != 200 || json.Unmarshal([]byte(prA.body), &pr) != nil || !pr.Clamped || time.Until(pr.Until) < 119*time.Minute || time.Until(pr.Until) > 2*time.Hour {
		t.Fatalf("preview: %d %s", prA.code, prA.body)
	}
	preview("preview opened", true)
	opened("preview opened")
	var pl v1.Lease
	if err := ada.Get(c.ctx, "Lease", "web3", leases.Name("api", "preview"), &pl); err != nil || pl.Status.ApprovedBy != "" || !pl.IsOpen(api.UID, time.Now()) {
		t.Fatalf("preview's lease: %+v %v", pl.Status, err)
	}

	// 4. The editor may ask (to extend) but not approve: the port stays open while it waits;
	// ada says no, and it stays open until its own end.
	ans, err := openAs(ed, "open", "debug", "30m")
	if err != nil || ans.Lease.Status.Pending == nil || ans.Lease.Status.Phase != v1.LeaseOpen {
		t.Fatalf("editor's extension: %+v %v", ans.Lease.Status, err)
	}
	opened("extension pending")
	if err := answer(ada, ans.Lease.Status.Pending.Approval, "deny", "not now"); err != nil {
		t.Fatal(err)
	}
	opened("extension denied")

	// 5. ada closes it early: the rules go, connections are cut.
	if _, err := openAs(ed, "close", "debug", ""); err != nil {
		t.Fatalf("editor closes: %v", err)
	}
	closed("closed early")
	preview("debug closed early", true)
	if _, err := openAs(ed, "close", "debug", ""); status(err) != http.StatusConflict {
		t.Fatalf("close twice: %v", err)
	}

	// 6. A denied ask: the silo's call fails, saying who.
	silosAsk("10m")
	a = pendingApproval()
	if err := answer(ada, a.Name, "deny", "use the staging silo"); err != nil {
		t.Fatal(err)
	}
	if r := <-got; r.code != 403 || !strings.Contains(r.msg(), "denied by ada: use the staging silo") {
		t.Fatalf("denied: %+v", r)
	}
	closed("denied")

	// 7. A service account's ask waits for a person, even with the admin role.
	ans, err = openAs(bot, "open", "debug", "1m")
	if err != nil || ans.Lease.Status.Phase != v1.LeasePending {
		t.Fatalf("service account's ask: %+v %v", ans.Lease.Status, err)
	}
	if _, err := openAs(c.as(t, "nobody"), "open", "debug", "1m"); status(err) != http.StatusForbidden {
		t.Fatalf("a person without open: %v", err)
	}

	// 8. A person who holds approve opens it at once (the waiting ask ends); at its end the rules
	// go by themselves, and the sweep records it.
	ans, err = openAs(ada, "open", "debug", "2s")
	if err != nil || ans.Lease.Status.Phase != v1.LeaseOpen || ans.Lease.Status.ApprovedBy != "ada" || ans.Lease.Status.Pending != nil {
		t.Fatalf("approver's own ask: %+v %v", ans.Lease.Status, err)
	}
	var overtaken v1.Approval
	if err := ada.Get(c.ctx, "Approval", "web3", approvalsName(api.UID), &overtaken); err != nil || overtaken.Status.Phase != v1.ApprovalExpired {
		t.Fatalf("the service account's ask: %+v %v", overtaken.Status, err)
	}
	opened("opened by an approver")
	time.Sleep(time.Until(*ans.Lease.Status.Until) + 50*time.Millisecond)
	closed("at its end")
	preview("debug's end", true)
	if a := eps.call(t, api, http.MethodPost, "/v1/ports/preview/close", nil); a.code != 200 {
		t.Fatalf("the silo closing preview: %d %s", a.code, a.body)
	}
	preview("preview closed by the silo", false)
	if err := c.srv.SweepLeases(c.ctx); err != nil {
		t.Fatal(err)
	}
	if err := ada.Get(c.ctx, "Lease", "web3", leases.Name("api", "debug"), &l); err != nil || l.Status.Phase != v1.LeaseClosed || l.Status.Reason != "time up" {
		t.Fatalf("after the sweep: %+v %v", l.Status, err)
	}

	// 9. Leases are stored objects: a new API server over the same store sees them.
	srv2, err := apiserver.New(c.store, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv2)
	defer hs.Close()
	var again v1.Lease
	if err := client.New(hs.URL).Get(c.ctx, "Lease", "web3", leases.Name("api", "debug"), &again); err != nil || again.Status.Reason != "time up" {
		t.Fatalf("after a restart: %+v %v", again.Status, err)
	}

	// 10. The audit log: every ask, answer, opening and closing.
	want := map[string]bool{"lease-asked/system:silo:web3:api": false, "lease-opened/ada": false, "lease-denied/ada": false,
		"lease-closed/ed": false, "lease-ended/kevasod": false, "lease-asked/ed": false, "approval-Approved/ada": false,
		"lease-opened/system:silo:web3:api": false, "lease-closed/system:silo:web3:api": false}
	for _, e := range c.audit.Entries() {
		if _, ok := want[e.Event+"/"+e.User]; ok {
			want[e.Event+"/"+e.User] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("audit: no %s", k)
		}
	}
}

func approvalsName(siloUID string) string {
	return approvals.Name("api", siloUID, v1.ApprovalForExpose, "debug")
}
