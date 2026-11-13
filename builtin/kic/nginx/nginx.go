// Package nginx is the ingress driver for stock nginx (the official image, nginx:<version>): one
// nginx.conf, certificates beside it, checked with nginx -t and taken in with nginx -s reload.
package nginx

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"kevaso.com/core/sdk/kic"
)

// Where the driver puts things in the silo.
const (
	ConfigPath = "/etc/nginx/nginx.conf"
	CertDir    = "/etc/nginx/ingress"
)

// Driver is the nginx driver.
type Driver struct{}

var options = []kic.Knob{
	{Name: "user", Help: "the user worker processes run as (the image's: nginx)", Valid: kic.Name},
	{Name: "pid", Help: "the pid file the image's nginx uses, spelled exactly as its own nginx.conf does (" + DefaultPID + ")", Valid: kic.Path},
	{Name: "worker-connections", Help: "per worker (1024)", Valid: kic.Count},
	{Name: "client-max-body-size", Help: "largest request body (16m)", Valid: kic.Size},
	{Name: "proxy-connect-timeout", Help: "to a backend (5s)", Valid: kic.Duration},
	{Name: "proxy-read-timeout", Help: "between two reads from a backend (60s)", Valid: kic.Duration},
	{Name: "proxy-send-timeout", Help: "between two writes to a backend (60s)", Valid: kic.Duration},
	{Name: "http2", Help: "on 443 (nginx 1.25.1 or later): true or false (false)", Valid: kic.Bool},
}

var annotations = []kic.Knob{
	{Name: "proxy-body-size", Help: "largest request body on this Ingress's routes", Valid: kic.Size},
	{Name: "proxy-connect-timeout", Valid: kic.Duration},
	{Name: "proxy-read-timeout", Valid: kic.Duration},
	{Name: "proxy-send-timeout", Valid: kic.Duration},
	{Name: "ssl-redirect", Help: "false: also serve these routes on plain HTTP instead of redirecting", Valid: kic.Bool},
	{Name: "buffering", Help: "false: stream responses as they come (server-sent events)", Valid: kic.Bool},
}

// DefaultPID is the pid file of the stock image (docker.io/library/nginx:1.27's nginx.conf says
// /run/nginx.pid). It must be the same path, spelled the same way: on a reload to a config whose
// pid path differs, nginx writes the new file and deletes the old one, so /var/run/nginx.pid
// (the same file, through the /var/run → /run link) was deleted, the next nginx -t made it
// again empty, and every reload after the first failed ("invalid PID number").
const DefaultPID = "/run/nginx.pid"

// Info implements kic.Driver.
func (Driver) Info() kic.Info {
	return kic.Info{Name: "nginx", Description: "stock nginx: nginx.conf, nginx -t, nginx -s reload", Image: "docker.io/library/nginx:1.27",
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
		b.WriteString(strings.Repeat("    ", indent))
		fmt.Fprintf(&b, format, a...)
		b.WriteByte('\n')
	}
	certFile := map[string]string{} // certificate name → its file
	var files []kic.File
	for _, c := range s.Certificates {
		data := append(append(append([]byte(nil), c.Chain...), '\n'), c.Key...)
		path := kic.ContentName(CertDir, data, ".pem")
		certFile[c.Name] = path
		files = append(files, kic.File{Path: path, Mode: 0o600, Data: data, Secret: true})
	}

	w(0, "# Rendered by Kevaso's nginx ingress driver for class %s: rewritten on every change.", s.Class)
	w(0, "user %s;", opt(s, "user", "nginx"))
	w(0, "worker_processes auto;")
	w(0, "pid %s;", opt(s, "pid", DefaultPID))
	w(0, "error_log /var/log/nginx/error.log notice;")
	w(0, "events {")
	w(1, "worker_connections %s;", opt(s, "worker-connections", "1024"))
	w(0, "}")
	w(0, "http {")
	w(1, "access_log /var/log/nginx/access.log;")
	w(1, "server_tokens off;")
	w(1, "keepalive_timeout 65s;")
	w(1, "client_header_timeout 30s;")
	w(1, "client_body_timeout 60s;")
	w(1, "send_timeout 60s;")
	w(1, "client_max_body_size %s;", opt(s, "client-max-body-size", "16m"))
	w(1, "server_names_hash_bucket_size 128;")
	w(1, "proxy_http_version 1.1;")
	w(1, "proxy_connect_timeout %s;", opt(s, "proxy-connect-timeout", "5s"))
	w(1, "proxy_read_timeout %s;", opt(s, "proxy-read-timeout", "60s"))
	w(1, "proxy_send_timeout %s;", opt(s, "proxy-send-timeout", "60s"))
	w(1, "# WebSocket: pass Upgrade through, keep-alive otherwise.")
	w(1, "map $http_upgrade $connection_upgrade {")
	w(2, "default upgrade;")
	w(2, "'' '';")
	w(1, "}")
	w(1, "# The client's address, for the backend.")
	w(1, "proxy_set_header Host $host;")
	w(1, "proxy_set_header X-Real-IP $remote_addr;")
	w(1, "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
	w(1, "proxy_set_header X-Forwarded-Proto $scheme;")
	w(1, "proxy_set_header X-Forwarded-Host $host;")
	w(1, "proxy_set_header X-Forwarded-Port $server_port;")
	w(1, "proxy_set_header Upgrade $http_upgrade;")
	w(1, "proxy_set_header Connection $connection_upgrade;")
	w(1, "ssl_protocols TLSv1.2 TLSv1.3;")
	w(1, "ssl_prefer_server_ciphers off;")
	w(1, "ssl_session_cache shared:ingress:10m;")
	w(1, "ssl_session_timeout 1d;")
	w(1, "ssl_session_tickets off;")

	challenges := func(indent int) {
		for _, c := range s.Challenges {
			w(indent, "location = %s%s {", kic.ChallengePrefix, c.Token)
			w(indent+1, "default_type text/plain;")
			w(indent+1, "return 200 \"%s\";", c.KeyAuthorization)
			w(indent, "}")
		}
		w(indent, "location ^~ %s {", kic.ChallengePrefix)
		w(indent+1, "return 404;")
		w(indent, "}")
	}
	location := func(indent int, r kic.Route) {
		w(indent, "%s%s", kic.BlameMark, r.Ingress)
		w(indent, "location %s {", r.Path)
		if v, ok := r.Annotations["proxy-body-size"]; ok {
			w(indent+1, "client_max_body_size %s;", v)
		}
		for _, t := range []string{"connect", "read", "send"} {
			if v, ok := r.Annotations["proxy-"+t+"-timeout"]; ok {
				w(indent+1, "proxy_%s_timeout %s;", t, v)
			}
		}
		if r.Annotations["buffering"] == "false" {
			w(indent+1, "proxy_buffering off;")
		}
		w(indent+1, "proxy_pass http://%s;", hostPort(r.Backend))
		w(indent, "}")
		w(indent, kic.BlameEnd)
	}

	w(1, "# Any other host: ACME challenges, else nothing.")
	w(1, "server {")
	w(2, "listen 80 default_server;")
	w(2, "server_name _;")
	challenges(2)
	w(2, "location / {")
	w(3, "return 404;")
	w(2, "}")
	w(1, "}")
	w(1, "server {")
	w(2, "listen 443 ssl default_server;")
	w(2, "server_name _;")
	w(2, "ssl_reject_handshake on;")
	w(1, "}")

	hosts, byHost := kic.Hosts(s.Routes)
	for _, h := range hosts {
		routes := byHost[h]
		cert, hasCert := kic.CertFor(s.Certificates, h)
		w(1, "server {")
		w(2, "listen 80;")
		w(2, "server_name %s;", h)
		challenges(2)
		for _, r := range routes {
			if r.TLS && r.Annotations["ssl-redirect"] != "false" {
				w(2, "location %s {", r.Path)
				w(3, "return 308 https://$host$request_uri;")
				w(2, "}")
				continue
			}
			location(2, r)
		}
		w(1, "}")
		if !anyTLS(routes) || !hasCert {
			continue // no certificate yet: port 80 redirects, 443 refuses the handshake until it comes
		}
		w(1, "server {")
		w(2, "listen 443 ssl;")
		if opt(s, "http2", "false") == "true" {
			w(2, "http2 on;")
		}
		w(2, "server_name %s;", h)
		w(2, "%s%s", kic.BlameMark, cert.Ingress)
		w(2, "ssl_certificate %s;", certFile[cert.Name])
		w(2, "ssl_certificate_key %s;", certFile[cert.Name])
		w(2, kic.BlameEnd)
		for _, r := range routes {
			if r.TLS {
				location(2, r)
			}
		}
		w(1, "}")
	}
	w(0, "}")

	return kic.Plan{
		Config: kic.File{Path: ConfigPath, Mode: 0o644, Data: []byte(b.String())},
		Files:  files,
		Dir:    CertDir,
		Check:  []string{"nginx", "-t", "-q", "-c", kic.ConfigToken},
		Reload: kic.Action{Exec: []string{"nginx", "-s", "reload"}},
	}, nil
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
	if strings.Contains(b.Address, ":") { // IPv6
		return "[" + b.Address + "]:" + strconv.Itoa(b.Port)
	}
	return b.Address + ":" + strconv.Itoa(b.Port)
}

var lineOf = regexp.MustCompile(`:([0-9]+)\s*$`)

// Blame implements kic.Blamer: nginx -t says "… in FILE:LINE".
func (Driver) Blame(p kic.Plan, out string) []string {
	for _, l := range strings.Split(out, "\n") {
		if !strings.Contains(l, ConfigPath) {
			continue
		}
		if m := lineOf.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			n, _ := strconv.Atoi(m[1])
			if who := kic.MarkedBlame(p.Config.Data, n); who != nil {
				return who
			}
		}
	}
	return nil
}

var (
	_ kic.Driver = Driver{}
	_ kic.Blamer = Driver{}
)
