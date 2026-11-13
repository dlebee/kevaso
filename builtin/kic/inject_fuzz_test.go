package kic

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kic"
)

// FuzzRenderNoInjection: everything an Ingress's author (hosts, paths, annotations), an
// IngressClass's (options) or an ACME server (challenge tokens and key authorizations) controls
// goes into a proxy's configuration. For every built-in driver: whatever passes kic.Validate,
// as the agent checks before rendering, renders a configuration where no value breaks out of its
// directive: every line is one directive (or a block's opening or end, or a comment), its name one
// the driver writes, nginx's ending in one ;, no comment started mid-line, quotes balanced, and
// Kong's JSON valid with exactly the services and routes asked for.
//
//	go test ./builtin/kic -run '^$' -fuzz FuzzRenderNoInjection -fuzztime 60s
func FuzzRenderNoInjection(f *testing.F) {
	for _, s := range [][]string{
		{"app.example.com", "/", "10.64.2.7", "16m", "30s", "true", "tok_1", "tok_1.abc", "shop/web", "public"},
		{"app.example.com", "/api", "10.64.2.7", "1m; include /etc/passwd", "30s\n}", "x", "t", "k", "shop/web", "public"},
		{"*.example.com", "/a/b", "fd00::1", "-1", "5ms", "false", "t\"; evil", "k", "shop/web\nuser root;", "public\nuser root;"},
		{"a.b", "/x{", "10.0.0.1", "10m", "1h", "true", "t", "k #", "a/b", "c"},
		{"a.b", "/x;", "10.0.0.1:80", "10m", "1h", "true", "t", "k", "a/b # x", "c # y"},
		{"a.b", "/$host", "10.0.0.1", "10m", "1h", "{", "t", "k", "a/b", "c"},
	} {
		f.Add(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], uint8(0))
	}
	f.Add("app.example.com", "/", "10.64.2.7", "16m", "16m", "true", "t", "k", "shop/web\nuser root;", "public", uint8(0))
	f.Add("app.example.com", "/", "10.64.2.7", "30s", "30s", "30s", "t", "k", "shop/web", "public\n}\nimport /etc/x", uint8(1))
	drivers := Builtin()
	names := []string{"nginx", "caddy", "kong"}
	f.Fuzz(func(t *testing.T, host, path, addr, ann1, ann2, opt1, token, ka, ingress, class string, which uint8) {
		d := drivers[names[int(which)%len(names)]]
		info := d.Info()
		ann := map[string]string{}
		if n := len(info.Annotations); n > 0 {
			ann[info.Annotations[int(which/3)%n].Name] = ann1
			ann[info.Annotations[int(which/7)%n].Name] = ann2
		}
		opts := map[string]string{}
		if n := len(info.Options); n > 0 {
			opts[info.Options[int(which/5)%n].Name] = opt1
		}
		s := kic.State{Class: class, Options: opts,
			Routes: []kic.Route{
				{Ingress: ingress, Host: host, Path: path, Backend: kic.Backend{Address: addr, Port: 8080}, TLS: which&1 == 0, Annotations: ann},
				{Ingress: ingress, Host: host, Path: "/", Backend: kic.Backend{Address: "10.64.2.8", Port: 80}},
			},
			Certificates: []kic.Certificate{{Name: "shop/web-tls", Ingress: ingress, Hosts: []string{host}, Chain: []byte("CHAIN"), Key: []byte("KEY")}},
			Challenges:   []kic.Challenge{{Token: token, KeyAuthorization: ka}},
		}
		if kic.Validate(d, s) != nil {
			return
		}
		p, err := d.Render(s)
		if err != nil {
			return
		}
		cfg := string(p.Config.Data)
		if info.Name == "kong" {
			cfg = string(p.Reload.Call.Body)
		}
		if why := injected(info.Name, cfg, len(s.Routes)); why != "" {
			t.Fatalf("%s: %s\nstate: %+v\nconfig:\n%s", info.Name, why, s, cfg)
		}
		// Names (the Ingress's, the class's) go into comments: the same configuration with plain
		// names has as many lines.
		plain := s
		plain.Class, plain.Routes, plain.Certificates = "c", slices.Clone(s.Routes), slices.Clone(s.Certificates)
		for i := range plain.Routes {
			plain.Routes[i].Ingress = "ns/name"
		}
		plain.Certificates[0].Ingress = "ns/name"
		if q, err := d.Render(plain); err == nil && info.Name != "kong" && strings.Count(string(q.Config.Data), "\n") != strings.Count(cfg, "\n") {
			t.Fatalf("%s: the Ingress's or class's name (%q, %q) added lines:\n%s", info.Name, ingress, class, cfg)
		}
	})
}

var (
	nginxDirectives = []string{"user", "worker_processes", "pid", "error_log", "events", "worker_connections", "http", "access_log",
		"server_tokens", "keepalive_timeout", "client_header_timeout", "client_body_timeout", "send_timeout", "client_max_body_size",
		"server_names_hash_bucket_size", "proxy_http_version", "proxy_connect_timeout", "proxy_read_timeout", "proxy_send_timeout",
		"map", "default", "''", "proxy_set_header", "ssl_protocols", "ssl_prefer_server_ciphers", "ssl_session_cache",
		"ssl_session_timeout", "ssl_session_tickets", "server", "listen", "server_name", "location", "default_type", "return",
		"ssl_reject_handshake", "http2", "ssl_certificate", "ssl_certificate_key", "proxy_buffering", "proxy_pass"}
	caddyDirectives = []string{"{", "auto_https", "admin", "persist_config", "servers", "timeouts", "read_header", "idle", "handle",
		"respond", "reverse_proxy", "header_up", "flush_interval", "transport", "dial_timeout", "redir", "tls"}
	caddySite = regexp.MustCompile(`^(:80|https?://[^\s{}"#]+) \{$`)
	// Caddy's placeholders the driver writes, the only braces inside a line.
	caddyPlaceholders = strings.NewReplacer("{remote_host}", "", "{host}", "", "{uri}", "")
)

// injected says what's wrong with a rendered configuration ("" when nothing is).
func injected(driver, cfg string, routes int) string {
	if driver == "kong" {
		var d struct {
			Services []struct {
				Routes []json.RawMessage `json:"routes"`
			} `json:"services"`
		}
		if err := json.Unmarshal([]byte(cfg), &d); err != nil {
			return "Kong's config isn't JSON: " + err.Error()
		}
		if len(d.Services) != routes {
			return "Kong's config has the wrong number of services"
		}
		return ""
	}
	depth := 0
	for _, raw := range strings.Split(strings.TrimSuffix(cfg, "\n"), "\n") {
		l := strings.TrimSpace(raw)
		if strings.HasPrefix(l, "#") {
			continue // a comment is one line
		}
		if strings.Contains(l, "#") {
			return "a # mid-line (a comment would swallow the rest): " + l
		}
		if strings.Count(l, `"`)%2 != 0 {
			return "unbalanced quotes: " + l
		}
		if l == "}" {
			depth--
			if depth < 0 {
				return "a block closed that wasn't open"
			}
			continue
		}
		name := strings.Fields(l)[0]
		switch driver {
		case "nginx":
			body := strings.TrimSuffix(strings.TrimSuffix(l, ";"), "{")
			if strings.ContainsAny(body, ";{}") {
				return "a ; { or } inside a directive: " + l
			}
			switch {
			case strings.HasSuffix(l, "{"):
				depth++
			case !strings.HasSuffix(l, ";"):
				return "a directive that doesn't end: " + l
			}
			if !slices.Contains(nginxDirectives, name) {
				return "an unknown directive: " + name
			}
		case "caddy":
			body := caddyPlaceholders.Replace(strings.TrimSuffix(l, "{"))
			if strings.ContainsAny(body, "{}") || strings.Contains(l, ";") && name != "#" {
				return "a brace inside a line: " + l
			}
			if strings.HasSuffix(l, "{") {
				depth++
			}
			if !slices.Contains(caddyDirectives, name) && !caddySite.MatchString(l) {
				return "an unknown directive: " + name
			}
		}
	}
	if depth != 0 {
		return "blocks don't close"
	}
	return ""
}
