package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/internal/login"
)

// Browser shows the sign-in page; tests replace it (they play the browser).
var Browser = login.OpenBrowser

// configCommand runs the commands that work on the kvo config: login, logout, ctx, ns.
func configCommand(ctx context.Context, cmd string, o opts, stdout, stderr io.Writer) error {
	path, err := kvoconfig.Path()
	if err != nil {
		return err
	}
	cfg, err := kvoconfig.Load(path)
	if err != nil {
		return err
	}
	switch cmd {
	case "login":
		return loginCmd(ctx, path, cfg, o, stdout, stderr)
	case "logout":
		name, c, err := cfg.Resolve(o.context)
		if err != nil {
			return err
		}
		if !c.Login {
			return fmt.Errorf("context %q uses a client certificate, not a kvo login session", name)
		}
		if err := kvoconfig.Tokens(path).Delete(name); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "signed out of %s\n", name)
		return nil
	case "ctx":
		if len(o.args) == 0 {
			names := make([]string, 0, len(cfg.Contexts))
			for n := range cfg.Contexts {
				names = append(names, n)
			}
			sort.Strings(names)
			tw := tabwriter.NewWriter(stdout, 0, 0, 3, ' ', 0)
			_, _ = fmt.Fprintln(tw, "CURRENT\tNAME\tSERVER\tNAMESPACE\tAUTH")
			for _, n := range names {
				c := cfg.Contexts[n]
				cur, auth := "", "certificate"
				if n == cfg.CurrentContext {
					cur = "*"
				}
				if c.Login {
					auth = "login"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", cur, n, c.Server, dash(c.Namespace), auth)
			}
			return tw.Flush()
		}
		if _, ok := cfg.Contexts[o.args[0]]; !ok {
			return fmt.Errorf("no context %q (kvo ctx lists them)", o.args[0])
		}
		cfg.CurrentContext = o.args[0]
		if err := cfg.Save(path); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "switched to %s\n", o.args[0])
		return nil
	case "ns":
		name, c, err := cfg.Resolve(o.context)
		if err != nil {
			return err
		}
		if len(o.args) == 0 {
			_, _ = fmt.Fprintln(stdout, defaultNS(opts{ctxNamespace: c.Namespace}))
			return nil
		}
		c.Namespace = o.args[0]
		cfg.Contexts[name] = c
		if err := cfg.Save(path); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "default namespace for %s is now %s\n", name, o.args[0])
		return nil
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func loginCmd(ctx context.Context, path string, cfg kvoconfig.Config, o opts, stdout, stderr io.Writer) error {
	var server, name string
	var caPEM []byte
	if len(o.args) > 0 { // a new cluster: pin its CA by the fingerprint the admin gave
		server = strings.TrimRight(o.args[0], "/")
		if !strings.HasPrefix(server, "https://") {
			server = "https://" + server
		}
		if o.ca == "" {
			return errors.New("kvo login SERVER needs --ca sha256:… (your admin has it, from kvoadm users invite)")
		}
		var err error
		if caPEM, err = login.FetchCA(ctx, server, o.ca); err != nil {
			return err
		}
		name = o.context
		if name == "" {
			u, _ := url.Parse(server)
			name = strings.NewReplacer(".", "-", ":", "-").Replace(u.Hostname())
			if _, port, _ := net.SplitHostPort(u.Host); port != "" && port != "6443" {
				name += "-" + port
			}
		}
	} else { // sign in again to an existing context
		var c kvoconfig.Context
		var err error
		if name, c, err = cfg.Resolve(o.context); err != nil {
			return err
		}
		if server, caPEM = c.Server, nil; c.CA != "" {
			if caPEM, err = os.ReadFile(c.CA); err != nil {
				return err
			}
		}
	}
	open := Browser
	if o.noBrowser {
		open = func(string) error { return nil }
	}
	tok, err := login.Login(ctx, server, caPEM, login.Options{
		Open: open,
		Say:  func(f string, a ...any) { _, _ = fmt.Fprintf(stderr, f+"\n", a...) },
	})
	if err != nil {
		return err
	}
	if err := login.Save(kvoconfig.Tokens(path), name, tok); err != nil {
		return err
	}
	if err := kvoconfig.AddLoginContext(path, name, server, caPEM); err != nil {
		return err
	}
	// Say who we are now.
	cfg, _ = kvoconfig.Load(path)
	c, _, err := cfg.Client(path, name)
	if err != nil {
		return err
	}
	var me client.WhoAmI
	if err := c.Call(ctx, http.MethodGet, "/auth/whoami", nil, &me); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "signed in to %s as %s (context %q)\n", server, me.Name, name)
	return nil
}

// auth runs kvo auth can-i / whoami. can-i exits 0 for yes and 1 for no, like kubectl.
func auth(ctx context.Context, c *client.Client, o opts, stdout io.Writer) (int, error) {
	if len(o.args) == 0 {
		return 0, errors.New("auth needs can-i or whoami")
	}
	switch o.args[0] {
	case "whoami":
		var me client.WhoAmI
		if err := c.Call(ctx, http.MethodGet, "/auth/whoami", nil, &me); err != nil {
			return 0, err
		}
		_, _ = fmt.Fprintf(stdout, "%s %s\n", me.Type, me.Name)
		if len(me.Groups) > 0 {
			_, _ = fmt.Fprintf(stdout, "groups: %s\n", strings.Join(me.Groups, ", "))
		}
		return 0, nil
	case "can-i":
		if len(o.args) != 3 {
			return 0, errors.New("auth can-i needs VERB RESOURCE[/NAME|/SUBRESOURCE]")
		}
		res, name, _ := strings.Cut(o.args[2], "/")
		k, err := kindOf(res)
		if err != nil {
			return 0, err
		}
		resource := k.Plural
		switch name {
		case "status", "exec", "token":
			resource, name = resource+"/"+name, ""
		}
		q := url.Values{"verb": {o.args[1]}, "resource": {resource}, "name": {name}}
		if k.Scope == v1.Namespaced {
			q.Set("namespace", defaultNS(o))
		}
		var ans client.CanIResponse
		if err := c.Call(ctx, http.MethodGet, "/auth/can-i?"+q.Encode(), nil, &ans); err != nil {
			return 0, err
		}
		if ans.Allowed {
			_, _ = fmt.Fprintf(stdout, "yes (%s)\n", ans.Reason)
			return 0, nil
		}
		_, _ = fmt.Fprintf(stdout, "no (%s)\n", ans.Reason)
		return 1, nil
	}
	return 0, fmt.Errorf("unknown auth command %q", o.args[0])
}
