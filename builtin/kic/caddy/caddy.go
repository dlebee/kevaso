// Package caddy is the ingress driver for stock Caddy (the official image, caddy:<version>): one
// Caddyfile with automatic HTTPS off (Kevaso brings the certificates), checked with caddy validate
// and taken in with caddy reload (Caddy's admin API on the silo's own localhost).
package caddy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"kevaso.com/core/sdk/kic"
)

// Where the driver puts things in the silo.
const (
	ConfigPath = "/etc/caddy/Caddyfile"
	CertDir    = "/etc/caddy/ingress"
)

// Driver is the Caddy driver.
type Driver struct{}

var options = []kic.Knob{
	{Name: "dial-timeout", Help: "to a backend (5s)", Valid: kic.Duration},
	{Name: "read-header-timeout", Help: "for a client's request headers (30s)", Valid: kic.Duration},
	{Name: "idle-timeout", Help: "a kept-alive client connection (2m)", Valid: kic.Duration},
}

var annotations = []kic.Knob{
	{Name: "dial-timeout", Valid: kic.Duration},
	{Name: "flush-interval", Help: "-1: stream responses as they come", Valid: kic.Matches(`-1|[0-9]{1,6}(ms|s)`, "-1 or a duration")},
	{Name: "ssl-redirect", Help: "false: also serve these routes on plain HTTP instead of redirecting", Valid: kic.Bool},
}

// Info implements kic.Driver.
func (Driver) Info() kic.Info {
	return kic.Info{Name: "caddy", Description: "stock Caddy: a Caddyfile, caddy validate, caddy reload", Image: "docker.io/library/caddy:2.8",
		Ports: []int{80, 443}, Options: options, Annotations: annotations}
}

func opt(s kic.State, name, def string) string {
	if v, ok := s.Options[name]; ok {
		return v
	}
	return def
}

// Render implements kic.Driver.
func (Driver) Render(s kic.State) (kic.Plan, error) {
	if err := kic.CheckState(s); err != nil {
		return kic.Plan{}, err
	}
	var b strings.Builder
	w := func(indent int, format string, a ...any) {
		b.WriteString(strings.Repeat("\t", indent))
		fmt.Fprintf(&b, format, a...)
		b.WriteByte('\n')
	}
	certFile := map[string]string{}
	var files []kic.File
	for _, c := range s.Certificates {
		data := append(append(append([]byte(nil), c.Chain...), '\n'), c.Key...)
		path := kic.ContentName(CertDir, data, ".pem")
		certFile[c.Name] = path
		files = append(files, kic.File{Path: path, Mode: 0o600, Data: data, Secret: true})
	}
	w(0, "# Rendered by Kevaso's caddy ingress driver for class %s: rewritten on every change.", s.Class)
	w(0, "{")
	w(1, "auto_https off")
	w(1, "admin localhost:2019")
	w(1, "persist_config off")
	w(1, "servers {")
	w(2, "timeouts {")
	w(3, "read_header %s", opt(s, "read-header-timeout", "30s"))
	w(3, "idle %s", opt(s, "idle-timeout", "2m"))
	w(2, "}")
	w(1, "}")
	w(0, "}")
	challenges := func(indent int) {
		for _, c := range s.Challenges {
			w(indent, "handle %s%s {", kic.ChallengePrefix, c.Token)
			w(indent+1, "respond \"%s\" 200", c.KeyAuthorization)
			w(indent, "}")
		}
		w(indent, "handle %s* {", kic.ChallengePrefix)
		w(indent+1, "respond 404")
		w(indent, "}")
	}
	matcher := func(path string) string {
		if path == "/" {
			return ""
		}
		return path + "* "
	}
	proxy := func(indent int, r kic.Route) {
		w(indent, "%s%s", kic.BlameMark, r.Ingress)
		w(indent, "handle %s{", matcher(r.Path))
		w(indent+1, "reverse_proxy %s {", hostPort(r.Backend))
		w(indent+2, "header_up X-Real-IP {remote_host}")
		if v, ok := r.Annotations["flush-interval"]; ok {
			w(indent+2, "flush_interval %s", v)
		}
		w(indent+2, "transport http {")
		w(indent+3, "dial_timeout %s", annotationOr(r, "dial-timeout", opt(s, "dial-timeout", "5s")))
		w(indent+2, "}")
		w(indent+1, "}")
		w(indent, "}")
		w(indent, kic.BlameEnd)
	}

	w(0, "# Any other host: ACME challenges, else nothing.")
	w(0, ":80 {")
	challenges(1)
	w(1, "handle {")
	w(2, "respond 404")
	w(1, "}")
	w(0, "}")
	hosts, byHost := kic.Hosts(s.Routes)
	for _, h := range hosts {
		routes := byHost[h]
		w(0, "http://%s {", h)
		challenges(1)
		for _, r := range routes {
			if r.TLS && r.Annotations["ssl-redirect"] != "false" {
				w(1, "handle %s{", matcher(r.Path))
				w(2, "redir https://{host}{uri} 308")
				w(1, "}")
				continue
			}
			proxy(1, r)
		}
		w(0, "}")
		cert, ok := kic.CertFor(s.Certificates, h)
		if !ok || !anyTLS(routes) {
			continue // no certificate yet: 443 has no site for it until it comes
		}
		w(0, "https://%s {", h)
		w(1, "%s%s", kic.BlameMark, cert.Ingress)
		w(1, "tls %s %s", certFile[cert.Name], certFile[cert.Name])
		w(1, kic.BlameEnd)
		for _, r := range routes {
			if r.TLS {
				proxy(1, r)
			}
		}
		w(0, "}")
	}
	return kic.Plan{
		Config: kic.File{Path: ConfigPath, Mode: 0o644, Data: []byte(b.String())},
		Files:  files,
		Dir:    CertDir,
		Check:  []string{"caddy", "validate", "--config", kic.ConfigToken, "--adapter", "caddyfile"},
		Reload: kic.Action{Exec: []string{"caddy", "reload", "--config", ConfigPath, "--adapter", "caddyfile"}},
	}, nil
}

func annotationOr(r kic.Route, name, def string) string {
	if v, ok := r.Annotations[name]; ok {
		return v
	}
	return def
}

func anyTLS(routes []kic.Route) bool {
	for _, r := range routes {
		if r.TLS {
			return true
		}
	}
	return false
}

func hostPort(b kic.Backend) string {
	if strings.Contains(b.Address, ":") {
		return "[" + b.Address + "]:" + strconv.Itoa(b.Port)
	}
	return b.Address + ":" + strconv.Itoa(b.Port)
}

var lineOf = regexp.MustCompile(`(?:Caddyfile(?:\.next)?):([0-9]+)`)

// Blame implements kic.Blamer: caddy validate says "… Caddyfile.next:LINE".
func (Driver) Blame(p kic.Plan, out string) []string {
	if m := lineOf.FindStringSubmatch(out); m != nil {
		n, _ := strconv.Atoi(m[1])
		return kic.MarkedBlame(p.Config.Data, n)
	}
	return nil
}

var (
	_ kic.Driver = Driver{}
	_ kic.Blamer = Driver{}
)
