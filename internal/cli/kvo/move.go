package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/moves"
)

// move moves a silo to another host (design §0.3):
//
//	kvo move silo NAME --to HOST [--recreate] [--confirm-fenced]
//
// With its data when its storage allows; --recreate starts a fresh copy from its image (only for
// onHostLoss: Recreate silos); --confirm-fenced is needed when its host is lost, once the old copy
// is provably stopped.
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
	if err := c.Call(ctx, http.MethodPost, path, moves.Request{To: o.moveTo, Recreate: o.recreate, ConfirmFenced: o.confirmFenced}, &s); err != nil {
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
