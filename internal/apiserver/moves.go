package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/moves"
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
		var from, to *v1.Host
		for _, h := range hosts {
			switch h.Name {
			case silo.Status.Host:
				from = h
			case req.To:
				to = h
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
		fits, err := s.fits(ctx, silo, to)
		if err != nil {
			writeErr(w, err)
			return
		}
		plan, err := moves.PlanMove(silo, moves.Of(silo, s.classMap()), req, fromLost, fits)
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
		silo.Status = st
		silo.ResourceVersion = strconv.FormatInt(cur.Revision, 10)
		o, err := s.update(ctx, target{kind: t.kind, namespace: t.namespace, name: t.name, status: true}, silo)
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

// fits is why host to can't take the silo ("" when it can), by the scheduler's own rules.
func (s *Server) fits(ctx context.Context, silo *v1.Silo, to *v1.Host) (string, error) {
	silos, err := listAs[*v1.Silo](ctx, s.store, "Silo")
	if err != nil {
		return "", err
	}
	ipList, err := listAs[*v1.IP](ctx, s.store, "IP")
	if err != nil {
		return "", err
	}
	hosts, err := listAs[*v1.Host](ctx, s.store, "Host")
	if err != nil {
		return "", err
	}
	var placed []*v1.Silo
	for _, x := range silos {
		if x.Status.Host != "" && x.UID != silo.UID {
			placed = append(placed, x)
		}
	}
	c := *silo
	c.Status.Host = ""
	d, err := scheduler.ScheduleIn(&c, []*v1.Host{to}, placed, scheduler.Env{IPs: ipList, Hosts: hosts, Classes: s.classMap()})
	if err != nil {
		return "", err
	}
	if d.Host == to.Name {
		return "", nil
	}
	return d.Message(), nil
}
