package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/approvals"
	"kevaso.com/core/internal/audit"
	"kevaso.com/core/internal/leases"
	"kevaso.com/core/internal/rbac"
	"kevaso.com/core/internal/store"
)

// Ports opened on a lease (design §7.2d) on the control plane. Asks come from the silo over its
// broker (port-open, port-close) or from a person: POST …/silos/NAME/open and …/close, which need
// the verb open on silos/exposure (by the silo's name or labels). A lease that needs a yes is an
// Approval with the use expose, answered like the others (kvo approve), by the verb approve on
// silos/exposure. Leases are written by the control plane only; the hosts read them and keep the
// firewall in line, closing a port at its time by themselves.

// SetLeaseLimits sets the control plane's limits for leases.
func (s *Server) SetLeaseLimits(l leases.Limits) { s.leaseLimits = l.WithDefaults() }

func (s *Server) limitsForLeases() leases.Limits { return s.leaseLimits.WithDefaults() }

// checkLease is admission for a silo's (or a SiloSet template's) service lease.
func (s *Server) checkLease(t target, obj meta.Object) error {
	if t.status {
		return nil
	}
	var sv *v1.SiloService
	switch o := obj.(type) {
	case *v1.Silo:
		sv = o.Spec.Service
	case *v1.SiloSet:
		sv = o.Spec.Template.Service
	default:
		return nil
	}
	if errs := leases.Validate(sv, s.limitsForLeases()); len(errs) > 0 {
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: %s", t.kind.Kind, obj.GetObjectMeta().Name, joinMessages(errs))
	}
	return nil
}

func (s *Server) getLease(ctx context.Context, ns, name string) (*v1.Lease, int64, error) {
	o, err := s.store.Get(ctx, store.Key{Kind: "Lease", Namespace: ns, Name: name})
	if err != nil {
		return nil, 0, err
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return nil, 0, err
	}
	return obj.(*v1.Lease), o.Revision, nil
}

// putLease creates (rev 0) or replaces a lease, keeping the stored object's identity.
func (s *Server) putLease(ctx context.Context, l *v1.Lease, rev int64, old *v1.Lease) error {
	key := store.Key{Kind: "Lease", Namespace: l.Namespace, Name: l.Name}
	l.TypeMeta = meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Lease"}
	l.ResourceVersion = ""
	if old == nil {
		now := s.clock.Now().UTC().Truncate(time.Second)
		l.UID, l.CreationTimestamp, l.Generation = newUID(), &now, 1
	} else {
		l.UID, l.CreationTimestamp, l.Generation = old.UID, old.CreationTimestamp, old.Generation+1
		l.Labels, l.Annotations = old.Labels, old.Annotations
	}
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if rev == 0 {
		_, err = s.store.Create(ctx, key, data)
	} else {
		_, err = s.store.Update(ctx, key, data, rev)
	}
	return err
}

func (s *Server) auditLease(event, user, typ, ns, silo, port string, allowed bool, reason string) {
	if s.auth == nil || s.auth.Audit == nil {
		return
	}
	s.auth.Audit.Record(audit.Entry{Time: s.clock.Now(), Event: event, User: user, Type: typ, Verb: v1.VerbOpen,
		Resource: v1.ResourceExposure, Namespace: ns, Name: silo, Allowed: allowed, Reason: "port " + port + ": " + reason})
}

func leaseWhy(l *v1.Lease) string {
	switch {
	case l == nil:
		return ""
	case l.Status.Phase == v1.LeaseOpen && l.Status.Until != nil:
		why := "open until " + l.Status.Until.UTC().Format(time.RFC3339)
		if l.Status.ApprovedBy != "" {
			why += ", approved by " + l.Status.ApprovedBy
		}
		if p := l.Status.Pending; p != nil {
			why += ", extension for " + p.For + " waiting on " + p.Approval
		}
		return why
	case l.Status.Pending != nil:
		return "waiting on approval " + l.Status.Pending.Approval + " for " + l.Status.Pending.For
	}
	return strings.ToLower(l.Status.Phase) + ": " + l.Status.Reason
}

// leaseAsk is one ask, from the silo or a person: it decides, stores and audits. The outcome's
// Err is the asker's to see.
func (s *Server) leaseAsk(ctx context.Context, silo *v1.Silo, a leases.Ask, byType string) leases.Outcome {
	a.Namespace, a.Silo, a.SiloUID = silo.Namespace, silo.Name, silo.UID
	if err := leases.Check(silo, a.Port); err != nil {
		return leases.Outcome{Err: err}
	}
	lname := leases.Name(silo.Name, a.Port)
	existing, lrev, err := s.getLease(ctx, silo.Namespace, lname)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return leases.Outcome{Err: fmt.Errorf("lease: try again")}
	}
	aname := approvals.Name(silo.Name, silo.UID, v1.ApprovalForExpose, a.Port)
	appr, arev, err := s.getApproval(ctx, silo.Namespace, aname)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return leases.Outcome{Err: fmt.Errorf("approval: try again")}
	}
	if a.Poll != "" && a.Poll != aname {
		return leases.Outcome{Err: fmt.Errorf("approval %q isn't this port's (%s)", a.Poll, aname)}
	}
	out := leases.Decide(a, silo, existing, appr, s.limitsForLeases(), s.approvalLimits, s.clock.Now())
	if out.Approval != nil {
		if err := s.putApproval(ctx, out.Approval, arev, appr); err != nil {
			return leases.Outcome{Err: fmt.Errorf("approval: try again")}
		}
		switch out.Approval.Status.Phase {
		case v1.ApprovalPending:
			ev := "approval-requested"
			if out.Event == "lease-replaced" {
				ev = "approval-replaced"
			}
			s.auditApproval(ev, a.By, byType, out.Approval, true, "asked: "+out.Approval.Spec.Summary)
		default:
			s.auditApproval("approval-expired", a.By, byType, out.Approval, false, orElse(out.Approval.Status.Reason, "nobody answered"))
		}
	}
	if out.Lease != nil {
		if err := s.putLease(ctx, out.Lease, lrev, existing); err != nil {
			return leases.Outcome{Err: fmt.Errorf("lease: try again")}
		}
	}
	if out.Event != "" {
		why := leaseWhy(out.Lease)
		if out.Clamped {
			why += fmt.Sprintf(" (asked for %s, more than its max %s)", a.For, leases.MaxOf(leases.Of(silo.Spec.Service, a.Port), s.limitsForLeases()))
		}
		s.auditLease(out.Event, a.By, byType, silo.Namespace, silo.Name, a.Port, out.Err == nil, why)
	} else if out.Err != nil && a.Poll == "" {
		s.auditLease("lease-refused", a.By, byType, silo.Namespace, silo.Name, a.Port, false, out.Err.Error())
	}
	return out
}

func orElse(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// leaseClose ends a port's lease early.
func (s *Server) leaseClose(ctx context.Context, silo *v1.Silo, port, by, byType string) (*v1.Lease, error) {
	if err := leases.Check(silo, port); err != nil {
		return nil, err
	}
	existing, lrev, err := s.getLease(ctx, silo.Namespace, leases.Name(silo.Name, port))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	appr, arev, err := s.getApproval(ctx, silo.Namespace, approvals.Name(silo.Name, silo.UID, v1.ApprovalForExpose, port))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	closed, ended, err := leases.Close(existing, appr, silo.UID, by, s.clock.Now())
	if err != nil {
		return nil, fmt.Errorf("silo %s port %s: %w", silo.Name, port, err)
	}
	if ended != nil {
		if err := s.putApproval(ctx, ended, arev, appr); err == nil {
			s.auditApproval("approval-expired", by, byType, ended, false, ended.Status.Reason)
		}
	}
	if err := s.putLease(ctx, closed, lrev, existing); err != nil {
		return nil, err
	}
	s.auditLease("lease-closed", by, byType, silo.Namespace, silo.Name, port, true, closed.Status.Reason)
	return closed, nil
}

// brokerPort answers a silo's port-open and port-close.
func (s *Server) brokerPort(ctx context.Context, call *brokerCall, req client.BrokerRequest) (client.BrokerResponse, string, bool) {
	by := "system:silo:" + call.silo.Namespace + ":" + call.silo.Name
	if req.Op == client.OpPortClose {
		l, err := s.leaseClose(ctx, call.silo, req.Name, by, "silo")
		if err != nil {
			return client.BrokerResponse{Error: err.Error()}, err.Error(), false
		}
		return client.BrokerResponse{Until: l.Status.Until}, "closed", true
	}
	out := s.leaseAsk(ctx, call.silo, leases.Ask{Port: req.Name, For: req.For, Wait: req.Wait, Poll: req.Approval, By: by}, "silo")
	switch {
	case out.Err != nil:
		return client.BrokerResponse{Error: fmt.Sprintf("port %s: %v", req.Name, out.Err)}, out.Err.Error(), false
	case out.Open:
		u := out.Until
		return client.BrokerResponse{Until: &u, Clamped: out.Clamped}, "open until " + u.UTC().Format(time.RFC3339), true
	default:
		w := out.Wait
		return client.BrokerResponse{Pending: &client.ApprovalWait{Namespace: w.Namespace, Name: w.Name, ExpiresAt: w.Spec.ExpiresAt}, Clamped: out.Clamped},
			"waiting for approval " + w.Name, false
	}
}

// siloLease serves POST …/silos/NAME/open and …/close for people (and service accounts). RBAC
// (open on silos/exposure) was checked in wrap. A person who also holds approve there opens a
// port that needs a yes at once; anyone else's ask waits for an approver.
func (s *Server) siloLease(w http.ResponseWriter, r *http.Request, t target) {
	if r.Method != http.MethodPost {
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "%s %s: POST to %s", r.Method, r.URL.Path, t.lease))
		return
	}
	ctx := r.Context()
	who, whoType, mayApprove := "dev", "user", true // kevasod dev: no authentication
	if s.auth != nil {
		id, _ := IdentityFrom(ctx)
		switch {
		case id == LocalAdmin || id == Component:
			who, whoType = id.Name, id.Type
		case id.Type == "user" || id.Type == "serviceaccount":
			who, whoType, mayApprove = id.Name, id.Type, false
		default:
			writeErr(w, errf(http.StatusForbidden, "Forbidden", "%s can't open leases: people, service accounts and the silo itself can", id))
			return
		}
	}
	var req v1.LeaseOpenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || req.Port == "" {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "%s: want {\"port\": NAME, \"for\": DURATION}", t.lease))
		return
	}
	o, err := s.store.Get(ctx, store.Key{Kind: "Silo", Namespace: t.namespace, Name: t.name})
	if err != nil {
		writeErr(w, err)
		return
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		writeErr(w, err)
		return
	}
	silo := obj.(*v1.Silo)
	if silo.DeletionTimestamp != nil {
		writeErr(w, errf(http.StatusConflict, "Conflict", "silo %s is being deleted", silo.Name))
		return
	}
	if t.lease == "close" {
		l, err := s.leaseClose(ctx, silo, req.Port, who, whoType)
		if err != nil {
			writeErr(w, errf(http.StatusConflict, "Conflict", "%v", err))
			return
		}
		writeJSON(w, http.StatusOK, client.LeaseAnswer{Lease: *l})
		return
	}
	if !mayApprove && whoType == "user" {
		mayApprove = s.mayApproveExposure(ctx, who, silo)
	}
	out := s.leaseAsk(ctx, silo, leases.Ask{Port: req.Port, For: req.For, By: who, MayApprove: mayApprove}, whoType)
	if out.Err != nil {
		writeErr(w, errf(http.StatusUnprocessableEntity, "Invalid", "%v", out.Err))
		return
	}
	l := out.Lease
	if l == nil {
		l, _, err = s.getLease(ctx, silo.Namespace, leases.Name(silo.Name, req.Port))
		if err != nil {
			writeErr(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, client.LeaseAnswer{Lease: *l, Clamped: out.Clamped})
}

// exposureAttributes are RBAC's terms for the verb on a silo's exposure.
func (s *Server) exposureAttributes(ctx context.Context, a rbac.Attributes, verb, ns, silo string) rbac.Attributes {
	a.Verb, a.Resource, a.Namespace, a.Name, a.Labels = verb, v1.ResourceExposure, ns, silo, map[string]string{}
	if o, err := s.store.Get(ctx, store.Key{Kind: "Silo", Namespace: ns, Name: silo}); err == nil {
		if obj, _, err := v1.Decode(o.Data); err == nil && obj.GetObjectMeta().Labels != nil {
			a.Labels = obj.GetObjectMeta().Labels
		}
	}
	return a
}

// mayApproveExposure: does this person hold approve on the silo's exposure?
func (s *Server) mayApproveExposure(ctx context.Context, user string, silo *v1.Silo) bool {
	p, err := s.policy.Policy(ctx)
	if err != nil {
		return false
	}
	labels := silo.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	return p.Authorize(rbac.Attributes{User: user, Groups: GroupsFrom(ctx), Verb: v1.VerbApprove, Resource: v1.ResourceExposure,
		Namespace: silo.Namespace, Name: silo.Name, Labels: labels}).Allowed
}

// leaseAnswered updates the lease an expose approval was for, once a person answered it (or it was
// answered too late).
func (s *Server) leaseAnswered(ctx context.Context, a *v1.Approval, who, whoType string) {
	if a.Spec.Use != v1.ApprovalForExpose {
		return
	}
	name := leases.Name(a.Spec.Silo, a.Spec.Port)
	existing, rev, err := s.getLease(ctx, a.Namespace, name)
	if err != nil {
		return
	}
	l := leases.Answered(existing, a, s.clock.Now())
	if l == nil {
		return
	}
	if err := s.putLease(ctx, l, rev, existing); err != nil {
		return
	}
	ev := map[string]string{v1.ApprovalApproved: "lease-opened", v1.ApprovalDenied: "lease-denied"}[a.Status.Phase]
	if ev == "" {
		ev = "lease-expired"
	}
	s.auditLease(ev, who, whoType, a.Namespace, a.Spec.Silo, a.Spec.Port, a.Status.Phase == v1.ApprovalApproved, leaseWhy(l))
}

// SweepLeases closes leases whose time is up and drops asks that expired unanswered (the hosts
// already closed the ports at their time: this keeps `kvo get leases` true and the audit log
// complete), and removes the leases of silos that are gone.
func (s *Server) SweepLeases(ctx context.Context) error {
	objs, _, err := s.store.List(ctx, store.Selector{Kind: "Lease"})
	if err != nil {
		return err
	}
	silos, err := listAs[*v1.Silo](ctx, s.store, "Silo")
	if err != nil {
		return err
	}
	uids := map[string]string{}
	for _, si := range silos {
		uids[si.Namespace+"/"+si.Name] = si.UID
	}
	var all []*v1.Lease
	revs, byKey := map[string]int64{}, map[string]*v1.Lease{}
	for _, o := range objs {
		obj, _, err := v1.Decode(o.Data)
		if err != nil {
			continue
		}
		l := obj.(*v1.Lease)
		k := l.Namespace + "/" + l.Name
		if uids[l.Namespace+"/"+l.Spec.Silo] != l.Spec.SiloUID { // its silo is gone (or another one now)
			_, _ = s.store.Delete(ctx, store.Key{Kind: "Lease", Namespace: l.Namespace, Name: l.Name}, o.Revision)
			continue
		}
		all = append(all, l)
		revs[k], byKey[k] = o.Revision, l
	}
	for _, l := range leases.Sweep(all, s.clock.Now()) {
		k := l.Namespace + "/" + l.Name
		if err := s.putLease(ctx, l, revs[k], byKey[k]); err != nil {
			continue
		}
		ev := "lease-ended"
		if byKey[k].Status.Phase != v1.LeaseOpen || l.Status.Phase != v1.LeaseClosed {
			ev = "lease-expired"
		}
		s.auditLease(ev, "kevasod", "component", l.Namespace, l.Spec.Silo, l.Spec.Port, false, l.Status.Reason)
	}
	return nil
}
