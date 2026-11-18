package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/restore"
	"kevaso.com/core/internal/store"
)

// guardRestoreHost refuses to delete a host the open restore is still waiting on, unless the
// request carries ?confirmOff=true. That host may hold a copy the restored store does not list.
// A host outside the account, or a closed account, deletes as before.
func (s *Server) guardRestoreHost(ctx context.Context, name string, confirmOff bool) error {
	g, err := s.currentGate(ctx)
	if err != nil || g == nil {
		return err
	}
	silos, err := listAs[*v1.Silo](ctx, s.store, "Silo")
	if err != nil || !restore.AccountOpen(g, silos) || !restore.InAccount(g, name) || restore.ConfirmedOff(g, name) {
		return err
	}
	if !confirmOff { // a required host during an open restore is deleted only when confirmed off
		return errf(http.StatusConflict, "Conflict",
			"host %s has not reported in the restored history: not deleted. Confirm the machine is off or wiped with ?confirmOff=true", name)
	}
	return nil
}

// accountedHostDelete records a confirmed-off delete on the gate, so the account stops waiting
// for a host that is gone.
func (s *Server) accountedHostDelete(ctx context.Context, name string, confirmOff bool) {
	if confirmOff {
		s.noteConfirmedOff(ctx, name) // a confirmed-off host is accounted in the restored history
	}
}

func (s *Server) noteConfirmedOff(ctx context.Context, name string) {
	key := store.Key{Kind: "RestoreGate", Name: v1.RestoreGateName}
	for range 5 {
		o, err := s.store.Get(ctx, key)
		if err != nil {
			return
		}
		obj, _, err := v1.Decode(o.Data)
		if err != nil {
			return
		}
		g, ok := obj.(*v1.RestoreGate)
		if !ok || restore.ConfirmedOff(g, name) {
			return
		}
		g.Spec.ConfirmedOff = append(g.Spec.ConfirmedOff, name)
		g.ResourceVersion = ""
		b, err := json.Marshal(g)
		if err != nil {
			return
		}
		if _, err := s.store.Update(ctx, key, b, o.Revision); errors.Is(err, store.ErrConflict) {
			continue
		}
		return
	}
}

func (s *Server) currentGate(ctx context.Context) (*v1.RestoreGate, error) {
	o, err := s.store.Get(ctx, store.Key{Kind: "RestoreGate", Name: v1.RestoreGateName})
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return nil, err
	}
	g, _ := obj.(*v1.RestoreGate)
	return g, nil
}
