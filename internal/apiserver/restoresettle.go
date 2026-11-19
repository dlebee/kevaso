package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/claims"
	"kevaso.com/core/internal/controllers/restore"
	siloctl "kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/store"
)

// restoreSettle serves POST …/silos/NAME/restore-settle.
// Only a cluster-admin may call it (authorizeRequest). It is not /move and not a status write:
// /move plans a handoff, and a status write cannot clear a handoff already stored.
func (s *Server) restoreSettle(w http.ResponseWriter, r *http.Request, t target) {
	if r.Method != http.MethodPost {
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "%s %s: POST restore-settle", r.Method, r.URL.Path))
		return
	}
	var req struct {
		To string `json:"to"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || req.To == "" {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "restore settle: want {\"to\": HOST}"))
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
		var gate *v1.RestoreGate
		gobj, err := s.store.Get(ctx, store.Key{Kind: "RestoreGate", Name: v1.RestoreGateName})
		if err == nil {
			decoded, _, derr := v1.Decode(gobj.Data)
			if derr != nil {
				writeErr(w, derr)
				return
			}
			gate = decoded.(*v1.RestoreGate)
		} else if !errors.Is(err, store.ErrNotFound) {
			writeErr(w, err)
			return
		}
		hosts, err := listAs[*v1.Host](ctx, s.store, "Host")
		if err != nil {
			writeErr(w, err)
			return
		}
		next, err := restore.DecideSettle(gate, silo, req.To, hosts)
		if err != nil {
			writeErr(w, errf(http.StatusConflict, "Conflict", "restore settle %s/%s: %v", silo.Namespace, silo.Name, err))
			return
		}
		if next.Host != "" && next.Host != silo.Status.Host {
			as := *silo
			as.ResourceVersion = strconv.FormatInt(cur.Revision, 10)
			held, err := siloctl.ClaimPorts(ctx, &claims.Claims{Store: s.store}, &as, next)
			if err != nil {
				writeErr(w, err)
				return
			}
			if held != nil {
				writeErr(w, errf(http.StatusUnprocessableEntity, "Invalid", "restore settle %s/%s: %s can't take its ports", silo.Namespace, silo.Name, next.Host))
				return
			}
		}
		silo.Status = next
		silo.ResourceVersion = strconv.FormatInt(cur.Revision, 10)
		_, err = s.update(ctx, target{kind: t.kind, namespace: t.namespace, name: t.name, status: true, planned: true}, silo) // restore settle clears a stored handoff
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		o, err := s.stampSettling(ctx, t)
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

// stampSettling records the revision of the placement on the silo. A holder's report counts
// only when that host's resourceVersion is newer, so a report from before the placement
// does not say the copy has stopped.
func (s *Server) stampSettling(ctx context.Context, t target) (store.Object, error) {
	var err error
	for range 5 {
		var cur store.Object
		cur, err = s.store.Get(ctx, t.key())
		if err != nil {
			return store.Object{}, err
		}
		obj, _, derr := v1.Decode(cur.Data)
		if derr != nil {
			return store.Object{}, derr
		}
		silo := obj.(*v1.Silo)
		if silo.Status.Restore == nil || silo.Status.Restore.SettlingTo == "" || silo.Status.Restore.Since != "" {
			return cur, nil
		}
		silo.Status.Restore.Since = strconv.FormatInt(cur.Revision, 10) // a report at or before this write has not been made since
		silo.ResourceVersion = strconv.FormatInt(cur.Revision, 10)
		var o store.Object
		o, err = s.update(ctx, target{kind: t.kind, namespace: t.namespace, name: t.name, status: true, planned: true}, silo)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		return o, err
	}
	if err == nil {
		err = store.ErrConflict
	}
	return store.Object{}, err
}
