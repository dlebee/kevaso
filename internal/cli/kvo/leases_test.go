package kvo

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func TestLeaseColumns(t *testing.T) {
	now := time.Now()
	later, earlier := now.Add(time.Hour), now.Add(-time.Minute)
	for _, c := range []struct {
		name  string
		st    v1.LeaseStatus
		phase string
		when  string
		by    string
	}{
		{"open", v1.LeaseStatus{Phase: v1.LeaseOpen, Until: &later, RequestedBy: "system:silo:dev:api", ApprovedBy: "ada"}, "Open", "until ", "system:silo:dev:api (yes: ada)"},
		{"open, extension pending", v1.LeaseStatus{Phase: v1.LeaseOpen, Until: &later, RequestedBy: "ada",
			Pending: &v1.LeaseAsk{Approval: "api-1234", RequestedBy: "ed", ExpiresAt: later}}, "Open", "extension waiting on api-1234", "ed"},
		{"pending", v1.LeaseStatus{Phase: v1.LeasePending, Pending: &v1.LeaseAsk{Approval: "api-1234", RequestedBy: "ed", ExpiresAt: later}}, "Pending", "waiting on api-1234, expires in", "ed"},
		{"pending, ran out", v1.LeaseStatus{Phase: v1.LeasePending, Pending: &v1.LeaseAsk{Approval: "api-1234", RequestedBy: "ed", ExpiresAt: earlier}}, "Expired", "nobody answered", "-"},
		{"time up, not yet swept", v1.LeaseStatus{Phase: v1.LeaseOpen, Until: &earlier, RequestedBy: "ada"}, "Closed", "time up", "ada"},
		{"closed", v1.LeaseStatus{Phase: v1.LeaseClosed, Until: &earlier, RequestedBy: "ada", Reason: "closed by ed"}, "Closed", "closed by ed", "ada"},
	} {
		l := &v1.Lease{Spec: v1.LeaseSpec{Silo: "api", Port: "debug"}, Status: c.st}
		got := leaseColumns(l, now)
		if len(got) != len(leaseHead) || got[0] != "api" || got[1] != "debug" || got[2] != c.phase || !strings.Contains(got[3], c.when) || got[4] != c.by {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	if !slices.Contains(leaseHead, "PHASE") {
		t.Error("head")
	}
}

func leasedSilo() *v1.Silo {
	ext := []string{v1.NetworkExternal}
	return &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "api", UID: "u1"}, Spec: v1.SiloSpec{
		Ports: []v1.SiloPort{{Name: "web", Port: 8080}, {Name: "debug", Port: 9229}, {Name: "preview", Port: 3000}},
		Service: &v1.SiloService{Ports: []v1.ServicePort{
			{Port: "web", HostPort: ext},
			{Port: "debug", HostPort: ext, Sources: []string{"203.0.113.0/24"}, Lease: &v1.PortLease{Max: "2h", Approval: &v1.ApprovalRule{Required: true}}},
			{Port: "preview", HostPort: ext, Lease: &v1.PortLease{Max: "8h"}},
		}},
	}}
}

// kvo describe silo: each outside port always open, or leased on its own terms and in its own state.
func TestDescribePorts(t *testing.T) {
	now := time.Now()
	until := now.Add(time.Hour)
	open := &v1.Lease{Spec: v1.LeaseSpec{Silo: "api", SiloUID: "u1", Port: "preview"}, Status: v1.LeaseStatus{Phase: v1.LeaseOpen, Until: &until}}
	open.Namespace = "dev"
	var b bytes.Buffer
	if err := writePorts(&b, leasedSilo(), []*v1.Lease{open}, nil, now); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Outside ports:",
		"web      -",
		"always open",
		"debug    default 30m or its max, max 2h, a person's yes first, from 203.0.113.0/24  closed",
		"preview  default 30m or its max, max 8h",
		"open until " + until.Local().Format(time.Kitchen),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// kvo open with several ports: each its own ask; one refused doesn't stop the others, and kvo
// exits non-zero naming it.
func TestOpenSeveralPorts(t *testing.T) {
	defer func(p time.Duration) { leasePoll = p }(leasePoll)
	leasePoll = time.Millisecond
	until := time.Now().Add(time.Hour)
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet { // the pending lease, polled: denied
			_ = json.NewEncoder(w).Encode(v1.Lease{Spec: v1.LeaseSpec{Port: "debug"}, Status: v1.LeaseStatus{Phase: v1.LeaseDenied, Reason: "denied by ada"}})
			return
		}
		var req v1.LeaseOpenRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		asked = append(asked, req.Port+"/"+req.For)
		l := v1.Lease{Spec: v1.LeaseSpec{Silo: "api", SiloUID: "u1", Port: req.Port}}
		l.Name = "api-" + req.Port
		switch req.Port {
		case "preview":
			l.Status = v1.LeaseStatus{Phase: v1.LeaseOpen, Until: &until}
		case "debug":
			l.Status = v1.LeaseStatus{Phase: v1.LeasePending, Pending: &v1.LeaseAsk{Approval: "api-expose-debug", ExpiresAt: until}}
		default:
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(client.Error{Code: 422, Reason: "Invalid", Message: "silo api port \"web\": not a leased port"})
			return
		}
		_ = json.NewEncoder(w).Encode(client.LeaseAnswer{Lease: l})
	}))
	defer srv.Close()
	var out, errs bytes.Buffer
	o := opts{args: []string{"silo", "api"}, namespace: "dev", lease: leaseOpts{ports: []string{"preview", "web", "debug", "preview"}, forDur: "1h"}}
	err := leaseCommand(context.Background(), client.New(srv.URL), o, "open", &out, &errs)
	if err == nil || err.Error() != "silo/api: 2 of 3 ports not opened: web, debug" {
		t.Fatalf("err %v\nout:\n%s\nerr:\n%s", err, out.String(), errs.String())
	}
	if !slices.Equal(asked, []string{"preview/1h", "web/1h", "debug/1h"}) {
		t.Errorf("asked %v", asked)
	}
	for _, want := range []string{"silo/api port preview: open until", "silo/api port debug: waiting for a yes: kvo approve api-expose-debug -n dev"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	for _, want := range []string{"silo/api port web: refused:", "not a leased port", "silo/api port debug: denied by ada"} {
		if !strings.Contains(errs.String(), want) {
			t.Errorf("missing %q in:\n%s", want, errs.String())
		}
	}
}
