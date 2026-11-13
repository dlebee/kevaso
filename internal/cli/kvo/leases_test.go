package kvo

import (
	"slices"
	"strings"
	"testing"
	"time"

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
