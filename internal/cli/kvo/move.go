package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/moves"
)

// move moves a silo to another host (design §0.3):
//
//	kvo move silo NAME --to HOST [--recreate] [--confirm-fenced [--insist]]
//
// With its data when its storage allows; --recreate starts a fresh copy from its image (only for
// onHostLoss: Recreate silos); --confirm-fenced is needed when its host is lost, once the old copy
// is provably stopped; --insist, with it, overrides the refusal while the host's start claim is
// fresh (it answered moments ago: only for a person who knows the old copy is off). Both flags
// need create on hosts/confirm-off, which is cluster-scoped and only cluster-admin has by default.
// editor and admin keep plain moves (create on silos/move).
//
// The server reads the silo and writes the move, and retries a store conflict itself. A 409
// from here is a refusal (the old copy is not provably stopped, or a move is already under way).
func move(ctx context.Context, c clientCaller, o opts, stdout io.Writer) error {
	if len(o.args) != 2 || o.moveTo == "" {
		return errors.New("move needs silo NAME --to HOST")
	}
	if k, err := kindOf(o.args[0]); err != nil || k.Kind != "Silo" {
		return errors.New("move works on silos")
	}
	ns := defaultNS(o)
	path := "/apis/kevaso/v1/namespaces/" + url.PathEscape(ns) + "/silos/" + url.PathEscape(o.args[1]) + "/move"
	var s v1.Silo
	if err := c.Call(ctx, http.MethodPost, path, moves.Request{To: o.moveTo, Recreate: o.recreate, ConfirmFenced: o.confirmFenced, Insist: o.insist}, &s); err != nil {
		if o.confirmFenced || o.insist {
			var ae *client.Error
			if errors.As(err, &ae) && ae.Code == http.StatusForbidden {
				return fmt.Errorf("%w\n\nsaying the old copy is off (--confirm-fenced, and --insist with it) needs create on hosts/confirm-off. That permission is cluster-scoped and only cluster-admin has it by default. editor and admin keep plain moves (create on silos/move)", err)
			}
		}
		return err
	}
	how := "with its data"
	if o.recreate {
		how = "as a fresh copy from its image"
	}
	wait := ""
	if s.Status.MovingFrom != "" {
		wait = "; " + s.Status.MovingFrom + " stops it first"
	}
	_, err := fmt.Fprintf(stdout, "silo/%s: moving to %s %s%s\n", s.Name, s.Status.Host, how, wait)
	return err
}

type clientCaller interface {
	Call(ctx context.Context, method, path string, in, out any) error
}
