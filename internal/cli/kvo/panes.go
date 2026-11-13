package kvo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

// Panes in the terminal (design §10.1): one way, opt-in. A silo's text is shown as plain text with
// every control character removed, so a silo can't move the cursor or rewrite the screen. HTML
// panes aren't rendered here: their bundle is for the panes app's sealed view, and
// `kvo pane bundle` only saves it to a file.
//
//	kvo pane watch SILO [-n NS]          follow a silo's panes
//	kvo pane bundle PANE -o FILE [-n NS] save an HTML pane's bundle, as it was uploaded

// plain makes silo text safe for a terminal: printable characters only, one line.
func plain(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r) || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == '‮' || r == '⁦' || r == '⁧' || r == '⁨' || r == '⁩' || r == '‪' || r == '‫' || r == '‭':
			// dropped: escapes and bidirectional overrides
		default:
			b.WriteRune(r)
		}
		if max > 0 && b.Len() >= max {
			return b.String() + "…"
		}
	}
	return b.String()
}

// paneLine is one pane, for people. The client draws the identity (namespace/silo) itself.
func paneLine(p *v1.Pane, now time.Time) string {
	parts := []string{p.Namespace + "/" + p.Spec.Silo, "[" + p.Spec.Pane + "]"}
	if p.Stale(now) {
		parts = append(parts, "(stale)")
	}
	switch p.Spec.Kind {
	case v1.PaneHTML:
		parts = append(parts, "html "+p.Spec.Bundle[:min(len(p.Spec.Bundle), 19)]+"… (open it in the panes app)")
	default:
		if p.Spec.State != "" {
			parts = append(parts, plain(p.Spec.State, 16))
		}
		if p.Spec.Progress != nil {
			parts = append(parts, fmt.Sprintf("%d%%", int(*p.Spec.Progress*100+0.5)))
		}
		if p.Spec.Title != "" {
			parts = append(parts, plain(p.Spec.Title, 80))
		}
		if p.Spec.Message != "" {
			parts = append(parts, "· "+plain(p.Spec.Message, 200))
		}
		for _, f := range p.Spec.Fields {
			parts = append(parts, plain(f.Label, 40)+"="+plain(f.Value, 80))
		}
	}
	return strings.Join(parts, " ")
}

func paneCommand(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	if len(o.args) != 2 {
		return errors.New("usage: kvo pane watch SILO | kvo pane bundle PANE -o FILE")
	}
	ns := defaultNS(o)
	switch o.args[0] {
	case "watch":
		silo := o.args[1]
		l, err := c.List(ctx, "Pane", ns)
		if err != nil {
			return err
		}
		show := func(raw json.RawMessage, gone bool) {
			obj, _, err := v1.Decode(raw)
			if err != nil {
				return
			}
			p := obj.(*v1.Pane)
			if p.Spec.Silo != silo {
				return
			}
			if gone {
				_, _ = fmt.Fprintf(stdout, "%s %s/%s [%s] gone\n", time.Now().Format("15:04:05"), ns, silo, p.Spec.Pane)
				return
			}
			_, _ = fmt.Fprintf(stdout, "%s %s\n", time.Now().Format("15:04:05"), paneLine(p, time.Now()))
		}
		for _, it := range l.Items {
			show(it, false)
		}
		ch, err := c.Watch(ctx, "Pane", ns, l.Metadata.ResourceVersion)
		if err != nil {
			return err
		}
		for ev := range ch {
			show(ev.Object, ev.Type == "DELETED")
		}
		return nil
	case "bundle":
		if o.output == "" || o.output == "-" {
			return errors.New("kvo pane bundle saves to a file: -o FILE (it's never printed)")
		}
		path := "/apis/kevaso/v1/namespaces/" + url.PathEscape(ns) + "/panes/" + url.PathEscape(o.args[1]) + "/bundle"
		b, err := c.Raw(ctx, http.MethodGet, path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(o.output, b, 0o600); err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "saved %d bytes to %s\n", len(b), o.output)
		return err
	}
	return fmt.Errorf("unknown pane command %q", o.args[0])
}
