package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/login"
	"kevaso.com/core/internal/siloui"
	"kevaso.com/core/internal/transfer"
)

// siloUI is `kvo ui silo NAME`: a page on 127.0.0.1 with the silo's shell and files, open until
// kvo stops (Ctrl-C).
func siloUI(ctx context.Context, c *client.Client, o opts, stdout, stderr io.Writer) error {
	if len(o.args) != 2 {
		return errors.New("ui needs silo NAME")
	}
	if k, err := kindOf(o.args[0]); err != nil || k.Kind != "Silo" {
		return errors.New("ui works on silos: kvo ui silo NAME")
	}
	limit, err := o.limit()
	if err != nil {
		return err
	}
	ns, name := defaultNS(o), o.args[1]
	var s v1.Silo
	if err := c.Get(ctx, "Silo", ns, name, &s); err != nil {
		return err
	}
	srv := &siloui.Server{Silo: transfer.Silo{C: c, Namespace: ns, Name: name, Limit: limit}}
	l, url, err := srv.Listen()
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "silo %s/%s: %s\n(the link works once, from this machine; Ctrl-C stops it)\n", ns, name, url)
	if !o.noBrowser {
		if err := login.OpenBrowser(url); err != nil {
			_, _ = fmt.Fprintln(stderr, "kvo: couldn't open a browser:", err)
		}
	}
	return srv.Serve(ctx, l)
}
