package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"kevaso.com/core/internal/rbac"
	"kevaso.com/core/internal/store"
)

// Approvals (design §8.7) on the control plane. The broker writes them when a grant says a use
// needs a person's yes; people answer through POST …/approvals/NAME/approve or /deny, which needs
// the verb approve on the secret (by name or label). Nobody writes them through the plain API.

// SetApprovalLimits sets how long requests wait and how long access may last.
func (s *Server) SetApprovalLimits(l approvals.Limits) { s.approvalLimits = l.WithDefaults() }

func (s *Server) getApproval(ctx context.Context, ns, name string) (*v1.Approval, int64, error) {
	o, err := s.store.Get(ctx, store.Key{Kind: "Approval", Namespace: ns, Name: name})
	if err != nil {
		return nil, 0, err
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return nil, 0, err
	}
	return obj.(*v1.Approval), o.Revision, nil
}

// putApproval creates a (rev 0) or replaces it, keeping the stored object's identity.
func (s *Server) putApproval(ctx context.Context, a *v1.Approval, rev int64, old *v1.Approval) error {
	key := store.Key{Kind: "Approval", Namespace: a.Namespace, Name: a.Name}
	a.TypeMeta = meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Approval"}
	a.ResourceVersion = ""
	if old == nil {
		now := s.clock.Now().UTC().Truncate(time.Second)
		a.UID, a.CreationTimestamp, a.Generation = newUID(), &now, 1
	} else {
		a.UID, a.CreationTimestamp, a.Generation = old.UID, old.CreationTimestamp, old.Generation+1
		a.Labels, a.Annotations = old.Labels, old.Annotations
	}
	data, err := json.Marshal(a)
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

func (s *Server) auditApproval(event, user, typ string, a *v1.Approval, allowed bool, reason string) {
	if s.auth == nil || s.auth.Audit == nil {
		return
	}
	what := fmt.Sprintf("secret %s, grant %s", a.Spec.Secret, a.Spec.Grant)
	if a.Spec.Use == v1.ApprovalForExpose {
		what = "port " + a.Spec.Port
	}
	s.auth.Audit.Record(audit.Entry{Time: s.clock.Now(), Event: event, User: user, Type: typ,
		Verb: a.Spec.Use, Resource: "approvals", Namespace: a.Namespace, Name: a.Name, Allowed: allowed,
		Reason: fmt.Sprintf("silo %s, %s: %s", a.Spec.Silo, what, reason)})
}

// needsYes runs a use that its grant says needs a person's yes. allow: go ahead; otherwise resp
// is the answer (pending, or the reason it failed).
func (s *Server) needsYes(ctx context.Context, c approvals.Call) (allow bool, resp client.BrokerResponse, reason string) {
	name := approvals.Name(c.Silo, c.SiloUID, c.Use, c.Secret)
	existing, rev, err := s.getApproval(ctx, c.Namespace, name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, client.BrokerResponse{Error: "approval: try again"}, err.Error()
	}
	if c.Poll != "" && c.Poll != name {
		return false, client.BrokerResponse{Error: fmt.Sprintf("approval %q isn't this call's (%s)", c.Poll, name)}, "poll of another approval"
	}
	now := s.clock.Now()
	out := approvals.Decide(c, existing, s.approvalLimits, now)
	silo := "system:silo:" + c.Namespace + ":" + c.Silo
	if out.Store != nil {
		if err := s.putApproval(ctx, out.Store, rev, existing); err != nil {
			return false, client.BrokerResponse{Error: "approval: try again"}, "storing the approval: " + err.Error()
		}
		switch {
		case out.Store.Status.Phase == v1.ApprovalExpired:
			s.auditApproval("approval-expired", silo, "silo", out.Store, false, "nobody answered")
		case existing != nil && approvals.StateOf(existing, c.SiloUID, now) == approvals.Pending:
			s.auditApproval("approval-replaced", silo, "silo", out.Store, true, "asked again: "+out.Store.Spec.Summary)
		default:
			s.auditApproval("approval-requested", silo, "silo", out.Store, true, "asked: "+out.Store.Spec.Summary)
		}
	}
	switch {
	case out.Allow:
		return true, client.BrokerResponse{}, "approved by " + existing.Status.AnsweredBy + " until " + existing.Status.AccessUntil.UTC().Format(time.RFC3339)
	case out.Err != nil:
		return false, client.BrokerResponse{Error: fmt.Sprintf("approval %s: %v", name, out.Err)}, out.Err.Error()
	default:
		w := out.Wait
		return false, client.BrokerResponse{Pending: &client.ApprovalWait{Namespace: w.Namespace, Name: w.Name, ExpiresAt: w.Spec.ExpiresAt}},
			"waiting for approval " + w.Name
	}
}

// internal: kevasod's own components (in-process), the only ones that may write approvals
// through the API.
func internal(ctx context.Context) bool {
	id, ok := IdentityFrom(ctx)
	return ok && id == Component
}

// approvalCall is the approvals.Call for a broker request.
func approvalCall(call *brokerCall, req client.BrokerRequest, use, grant string) approvals.Call {
	c := approvals.Call{Namespace: call.silo.Namespace, Silo: call.silo.Name, SiloUID: call.silo.UID,
		Secret: req.Name, Use: use, Grant: grant, For: req.For, Wait: req.Wait, Poll: req.Approval}
	switch use {
	case v1.ApprovalForSecret:
		c.Summary = "read the value of " + req.Name
	case v1.ApprovalForSign:
		h := sha256.Sum256(req.Payload)
		c.PayloadHash = hex.EncodeToString(h[:])
		c.Summary = fmt.Sprintf("sign %d bytes with %s", len(req.Payload), req.Name)
		if req.Slot != nil {
			c.Summary += fmt.Sprintf(" for slot %d", *req.Slot)
		}
	case v1.ApprovalForInject:
		c.Destination = &v1.ApprovalDestination{Host: req.Host, Method: req.Method, Path: req.Path}
		c.Summary = fmt.Sprintf("add %s to %s https://%s%s", req.Name, req.Method, req.Host, req.Path)
	}
	return c
}

// askInject answers the gate: may this request to host get the secret injected?
func (s *Server) askInject(ctx context.Context, call *brokerCall, req client.BrokerRequest) (client.BrokerResponse, string, bool) {
	host := strings.ToLower(req.Host)
	for _, g := range call.grants {
		if !assured(g) {
			continue
		}
		for _, gs := range g.Spec.Secrets {
			if gs.Name != req.Name || gs.Delivery() != v1.DeliverInject || gs.To == nil || strings.ToLower(gs.To.Host) != host {
				continue
			}
			if !gs.NeedsApproval() {
				return client.BrokerResponse{}, "grant " + g.Name + " needs no approval", true
			}
			ok, resp, why := s.needsYes(ctx, approvalCall(call, req, v1.ApprovalForInject, g.Name))
			return resp, why, ok
		}
	}
	return client.BrokerResponse{Error: errNoSecret(req.Name).Error()}, "no grant injects this secret for " + host, false
}

// answerApproval serves POST …/approvals/NAME/approve and …/deny. RBAC (approve on the secret)
// was checked in wrap; here: only people, only pending requests, and the audit entry.
func (s *Server) answerApproval(w http.ResponseWriter, r *http.Request, t target) {
	if r.Method != http.MethodPost {
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "%s %s: POST to answer", r.Method, r.URL.Path))
		return
	}
	ctx := r.Context()
	who := "dev" // kevasod dev: no authentication
	whoType := "user"
	if s.auth != nil {
		id, _ := IdentityFrom(ctx)
		if !approvals.MayAnswer(id.Type) {
			writeErr(w, errf(http.StatusForbidden, "Forbidden", "%s can't answer approvals: only people can", id))
			return
		}
		who, whoType = id.Name, id.Type
	}
	var body client.ApprovalAnswer
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
			writeErr(w, errf(http.StatusBadRequest, "BadRequest", "answer: %v", err))
			return
		}
	}
	a, rev, err := s.getApproval(ctx, t.namespace, t.name)
	if err != nil {
		writeErr(w, err)
		return
	}
	answered, err := approvals.Answer(a, t.answer == "approve", who, body.Reason, s.clock.Now())
	if errors.Is(err, approvals.ErrTooLate) {
		if perr := s.putApproval(ctx, answered, rev, a); perr == nil {
			s.auditApproval("approval-expired", who, whoType, answered, false, "answered too late")
			s.leaseAnswered(ctx, answered, who, whoType)
		}
		writeErr(w, errf(http.StatusConflict, "Expired", "%v", err))
		return
	}
	if err != nil {
		writeErr(w, errf(http.StatusConflict, "Conflict", "%v", err))
		return
	}
	if err := s.putApproval(ctx, answered, rev, a); err != nil {
		writeErr(w, err)
		return
	}
	s.auditApproval("approval-"+answered.Status.Phase, who, whoType, answered, true, t.answer+" "+body.Reason)
	s.leaseAnswered(ctx, answered, who, whoType)
	o, err := s.store.Get(ctx, t.key())
	if err != nil {
		writeErr(w, err)
		return
	}
	b, err := render(o)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// approvalAttributes: answering an approval is the verb approve on the secret it asks for (so a
// role can let someone approve one secret, or the secrets with a label).
func (s *Server) approvalAttributes(ctx context.Context, a rbac.Attributes, t target) rbac.Attributes {
	a.Verb, a.Resource, a.Name, a.Labels = v1.VerbApprove, "secrets", "", nil
	appr, _, err := s.getApproval(ctx, t.namespace, t.name)
	if err != nil {
		a.Name = "\x00unknown" // matches no named rule; the handler answers 404
		return a
	}
	if appr.Spec.Use == v1.ApprovalForExpose { // a lease: approve on the silo's exposure (leases.go)
		return s.exposureAttributes(ctx, a, v1.VerbApprove, t.namespace, appr.Spec.Silo)
	}
	a.Name = appr.Spec.Secret
	a.Labels = s.secretLabels(ctx, target{kind: v1.KindInfo{Kind: "Secret", Plural: "secrets"}, namespace: t.namespace, name: appr.Spec.Secret})
	return a
}

// ExpireApprovals marks the pending approvals that ran out unanswered (the control plane calls it
// every few seconds, so `kvo get approvals` tells the truth).
func (s *Server) ExpireApprovals(ctx context.Context) error {
	objs, _, err := s.store.List(ctx, store.Selector{Kind: "Approval"})
	if err != nil {
		return err
	}
	var all []*v1.Approval
	revs := map[string]int64{}
	for _, o := range objs {
		obj, _, err := v1.Decode(o.Data)
		if err != nil {
			continue
		}
		a := obj.(*v1.Approval)
		all = append(all, a)
		revs[a.Namespace+"/"+a.Name] = o.Revision
	}
	byKey := map[string]*v1.Approval{}
	for _, a := range all {
		byKey[a.Namespace+"/"+a.Name] = a
	}
	for _, e := range approvals.Expire(all, s.clock.Now()) {
		k := e.Namespace + "/" + e.Name
		if err := s.putApproval(ctx, e, revs[k], byKey[k]); err == nil {
			s.auditApproval("approval-expired", "kevasod", "component", e, false, "nobody answered")
		}
	}
	return nil
}
