package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/claims"
	hostctl "kevaso.com/core/internal/controllers/host"
	siloctl "kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/rbac"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/internal/store"
)

// Moves (design §0.3). Admission checks a silo's onHostLoss against what its storage allows; a
// person moves a silo with POST …/silos/NAME/move (create on silos/move), which the control plane
// plans and applies to the silo's status. The hosts' agents do the rest: the old one stops it and
// lets go of its volumes, then the new one starts it.

// SetClasses gives the server the plugins' classes (what their storage allows).
func (s *Server) SetClasses(f func() map[string]scheduler.Class) { s.classes = f }

func (s *Server) classMap() map[string]scheduler.Class {
	if s.classes == nil {
		return nil
	}
	return s.classes()
}

// checkMovability: onHostLoss must be one the silo's storage allows (and a SiloSet's instances').
func (s *Server) checkMovability(t target, obj meta.Object) error {
	if t.status {
		return nil
	}
	var silo *v1.Silo
	switch o := obj.(type) {
	case *v1.Silo:
		silo = o
	case *v1.SiloSet:
		silo = o.Instance(0, false)
	default:
		return nil
	}
	if err := moves.CheckPolicy(silo, moves.Of(silo, s.classMap())); err != nil {
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: %v", t.kind.Kind, obj.GetObjectMeta().Name, err)
	}
	return nil
}

func listAs[T meta.Object](ctx context.Context, st store.Store, kind string) ([]T, error) {
	objs, _, err := st.List(ctx, store.Selector{Kind: kind})
	if err != nil {
		return nil, err
	}
	var out []T
	for _, o := range objs {
		obj, _, err := v1.Decode(o.Data)
		if err != nil {
			continue
		}
		if x, ok := obj.(T); ok {
			out = append(out, x)
		}
	}
	return out, nil
}

// moveSilo serves POST …/silos/NAME/move.
func (s *Server) moveSilo(w http.ResponseWriter, r *http.Request, t target) {
	if r.Method != http.MethodPost {
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "%s %s: POST a move", r.Method, r.URL.Path))
		return
	}
	var req moves.Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || req.To == "" {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "move: want {\"to\": HOST}"))
		return
	}
	// The person is asserting a fact about a machine: the old copy is off. That is separate
	// from moving the silo, and it is cluster-scoped. A plain move (neither flag) is unchanged.
	// The server may set ConfirmFenced itself later, when the Host object is already gone;
	// that is the deletion's confirmation, not this request's.
	if req.ConfirmFenced || req.Insist {
		if err := s.allowConfirmOff(r); err != nil {
			writeErr(w, err)
			return
		}
	}
	ctx := r.Context()
	for range 5 {
		cur, err := s.store.Get(ctx, t.key())
		if err != nil {
			writeErr(w, err)
			return
		}
		obj, _, err := v1.Decode(cur.Data)
		if err != nil {
			writeErr(w, err)
			return
		}
		silo := obj.(*v1.Silo)
		hosts, err := listAs[*v1.Host](ctx, s.store, "Host")
		if err != nil {
			writeErr(w, err)
			return
		}
		var from, to, source *v1.Host
		for _, h := range hosts {
			if h.Name == silo.Status.Host {
				from = h
			}
			if h.Name == req.To {
				to = h
			}
			if h.Name == silo.Status.MovingFrom {
				source = h
			}
		}
		if to == nil {
			writeErr(w, errf(http.StatusUnprocessableEntity, "Invalid", "move: there's no host %q", req.To))
			return
		}
		fromLost := from == nil
		if from != nil {
			fromLost, _ = hostctl.Lost(from)
		}
		if from == nil && silo.Status.Host != "" {
			// The Host object named by status.host is gone: deleting it confirmed that copy is
			// off, so a move does not ask for --confirm-fenced again for that host. It does not
			// confirm a lost status.movingFrom.
			req.HostDeleted = true
		}
		fits, err := s.fits(ctx, silo, to)
		if err != nil {
			writeErr(w, err)
			return
		}
		sourceLost := source == nil
		if source != nil {
			sourceLost, _ = hostctl.Lost(source)
		}
		if fromLost {
			// A fresh start claim of the current host says it is alive (review of the start claim,
			// item 1). HostDeleted is that host's confirmation, so the claim is checked the same
			// way; the flag passed to PlanMove is not ConfirmFenced.
			check := req
			if req.HostDeleted {
				check.ConfirmFenced = true
			}
			if err := moves.CheckFenced(silo, check, s.clock.Now()); err != nil {
				writeErr(w, errf(http.StatusConflict, "Conflict", "move %s/%s: %v", silo.Namespace, silo.Name, err))
				return
			}
		}
		plan, err := moves.PlanMove(silo, moves.Of(silo, s.classMap()), req, fromLost, sourceLost, fits)
		if err != nil {
			code := http.StatusUnprocessableEntity
			if errors.Is(err, moves.ErrMoving) {
				code = http.StatusConflict
			}
			writeErr(w, errf(code, "Invalid", "move %s/%s: %v", silo.Namespace, silo.Name, err))
			return
		}
		st := moves.Apply(silo.Status, plan)
		how := "with its data"
		if !plan.WithData {
			how = "as a fresh copy from its image"
		}
		meta.SetCondition(&st.Conditions, meta.Condition{Type: "Moved", Status: meta.ConditionTrue, Reason: "Moving",
			Message: "moving " + how + " from " + plan.From + " to " + plan.To, ObservedGeneration: silo.Generation}, s.clock.Now().UTC().Truncate(time.Second))
		if err := s.claimMove(ctx, silo, cur.Revision, to, &st); err != nil {
			writeErr(w, err)
			return
		}
		silo.Status = st
		silo.ResourceVersion = strconv.FormatInt(cur.Revision, 10)
		o, err := s.update(ctx, target{kind: t.kind, namespace: t.namespace, name: t.name, status: true, planned: true}, silo)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
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
		return
	}
	writeErr(w, errf(http.StatusConflict, "Conflict", "the silo kept changing; try again"))
}

// confirmOffDenied is the 403 for a move that asserts the old copy is off. It names the
// permission, so a person who can move a silo can see why --confirm-fenced was refused.
const confirmOffDenied = "saying the old copy is off (--confirm-fenced, and --insist with it) needs create on hosts/confirm-off. That permission is cluster-scoped and only cluster-admin has it by default. editor and admin keep plain moves (create on silos/move)"

// allowConfirmOff is the extra check for ConfirmFenced and Insist. A server with authentication
// off has no identity, and the existing move tests run that way: the flags are allowed. The admin
// socket and kevasod itself are allowed. A host is not. Everyone else needs create on
// hosts/confirm-off in the cluster (an empty namespace), which a namespace RoleBinding cannot grant.
func (s *Server) allowConfirmOff(r *http.Request) error {
	if s.auth == nil {
		return nil
	}
	id, ok := IdentityFrom(r.Context())
	if !ok {
		return errf(http.StatusForbidden, "Forbidden", "%s", confirmOffDenied)
	}
	if id == LocalAdmin || id == Component {
		return nil
	}
	if id.Type == "host" || s.policy == nil {
		return errf(http.StatusForbidden, "Forbidden", "%s", confirmOffDenied)
	}
	p, err := s.policy.Policy(r.Context())
	if err != nil {
		return err
	}
	d := p.Authorize(rbac.Attributes{
		User: id.Name, Groups: GroupsFrom(r.Context()),
		Verb: "create", Resource: rbac.ConfirmOffResource,
	})
	if !d.Allowed {
		return errf(http.StatusForbidden, "Forbidden", "%s", confirmOffDenied)
	}
	return nil
}

// placement is what the scheduler judges a silo's placement by: the other placed silos, and the
// environment (IPs, hosts, classes).
func (s *Server) placement(ctx context.Context, silo *v1.Silo) ([]*v1.Silo, scheduler.Env, error) {
	silos, err := listAs[*v1.Silo](ctx, s.store, "Silo")
	if err != nil {
		return nil, scheduler.Env{}, err
	}
	ipList, err := listAs[*v1.IP](ctx, s.store, "IP")
	if err != nil {
		return nil, scheduler.Env{}, err
	}
	hosts, err := listAs[*v1.Host](ctx, s.store, "Host")
	if err != nil {
		return nil, scheduler.Env{}, err
	}
	ipSets, err := listAs[*v1.IPSet](ctx, s.store, "IPSet")
	if err != nil {
		return nil, scheduler.Env{}, err
	}
	siloSets, err := listAs[*v1.SiloSet](ctx, s.store, "SiloSet")
	if err != nil {
		return nil, scheduler.Env{}, err
	}
	var placed []*v1.Silo
	for _, x := range silos {
		if x.Status.Host != "" && x.UID != silo.UID {
			placed = append(placed, x)
		}
	}
	env := scheduler.Env{IPs: ipList, Hosts: hosts, Classes: s.classMap(), Suffix: v1.ClusterSuffix(hosts), IPSets: ipSets, SiloSets: siloSets}
	if s.networking != nil {
		env.Networking = s.networking // the providers' reach: where their IPs and balancers reach a silo
	}
	return placed, env, nil
}

// fits is why host to can't take the silo ("" when it can), by the scheduler's own rules: the
// silo keeps its status.host while judged, so a balancer it has keeps it in that host's region.
func (s *Server) fits(ctx context.Context, silo *v1.Silo, to *v1.Host) (string, error) {
	placed, env, err := s.placement(ctx, silo)
	if err != nil {
		return "", err
	}
	return scheduler.MoveTo(silo, to, env.Hosts, placed, env)
}

// claimMove gives st (the silo's status once moved to host to) the service the silo has there,
// not the old host's node ports, and takes the same store-backed claims the scheduler takes
// before a placement is written (K-029; silo is as read, at revision rev). A node port another
// silo holds on to is avoided, as the silo controller does; a host port held is an error (422).
func (s *Server) claimMove(ctx context.Context, silo *v1.Silo, rev int64, to *v1.Host, st *v1.SiloStatus) error {
	placed, env, err := s.placement(ctx, silo)
	if err != nil {
		return err
	}
	as := *silo
	as.ResourceVersion = strconv.FormatInt(rev, 10)
	sched := as
	sched.Status = *st
	cl := &claims.Claims{Store: s.store}
	for range 5 {
		svc, err := scheduler.ServiceStatus(&sched, to, placed, env)
		if err != nil {
			return errf(http.StatusUnprocessableEntity, "Invalid", "move: %s can't take it: %v", to.Name, err)
		}
		st.Service = svc
		held, err := siloctl.ClaimPorts(ctx, cl, &as, *st)
		if err != nil {
			return err
		}
		if held == nil {
			return nil
		}
		if len(held.HostPorts) > 0 {
			var ports []string
			for p := range held.HostPorts {
				ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Proto))
			}
			slices.Sort(ports)
			return errf(http.StatusUnprocessableEntity, "Invalid", "move: %s can't take it: host port %s is held by another silo", to.Name, strings.Join(ports, ", "))
		}
		if env.Claimed == nil {
			env.Claimed = map[string]scheduler.Claimed{}
		}
		env.Claimed[to.Name] = *held // node ports held there: decide the service again without them
	}
	return errf(http.StatusConflict, "Conflict", "move: the node ports on %s kept being taken; try again", to.Name)
}
