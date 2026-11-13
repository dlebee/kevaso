// Package kong is the ingress driver for stock Kong in DB-less mode (the official image, kong:<version>,
// with KONG_DATABASE=off): the whole declarative configuration goes to Kong's admin API in one
// POST /config. Kong checks it and swaps it in atomically, or refuses it and keeps what it had, so
// there are no files, no separate check and no reload: the call is all three.
package kong

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"kevaso.com/core/sdk/kic"
)

// Driver is the Kong driver.
type Driver struct{}

var options = []kic.Knob{
	{Name: "admin-port", Help: "where Kong's admin API listens in the silo (KONG_ADMIN_LISTEN; 8001)", Valid: kic.Count},
	{Name: "connect-timeout", Help: "to a backend (5s)", Valid: kic.Duration},
	{Name: "read-timeout", Help: "between two reads from a backend (60s)", Valid: kic.Duration},
	{Name: "write-timeout", Help: "between two writes to a backend (60s)", Valid: kic.Duration},
}

var annotations = []kic.Knob{
	{Name: "connect-timeout", Valid: kic.Duration},
	{Name: "read-timeout", Valid: kic.Duration},
	{Name: "write-timeout", Valid: kic.Duration},
	{Name: "strip-path", Help: "true: drop the matched path prefix before passing the request on", Valid: kic.Bool},
	{Name: "ssl-redirect", Help: "false: also serve these routes on plain HTTP instead of redirecting", Valid: kic.Bool},
}

// Info implements kic.Driver.
func (Driver) Info() kic.Info {
	return kic.Info{Name: "kong", Description: "stock Kong, DB-less: the declarative config through POST /config", Image: "docker.io/library/kong:3.7",
		Ports: []int{8000, 8443}, Options: options, Annotations: annotations}
}

type declarative struct {
	FormatVersion string        `json:"_format_version"`
	Services      []service     `json:"services,omitempty"`
	Routes        []route       `json:"routes,omitempty"` // service-less: the ACME answers
	Certificates  []certificate `json:"certificates,omitempty"`
}

type service struct {
	Name           string  `json:"name"`
	URL            string  `json:"url"`
	ConnectTimeout int64   `json:"connect_timeout"`
	ReadTimeout    int64   `json:"read_timeout"`
	WriteTimeout   int64   `json:"write_timeout"`
	Routes         []route `json:"routes,omitempty"`
}

type route struct {
	Name                    string   `json:"name"`
	Hosts                   []string `json:"hosts,omitempty"`
	Paths                   []string `json:"paths"`
	Protocols               []string `json:"protocols"`
	StripPath               bool     `json:"strip_path"`
	PreserveHost            bool     `json:"preserve_host"`
	HTTPSRedirectStatusCode int      `json:"https_redirect_status_code,omitempty"`
	Plugins                 []plugin `json:"plugins,omitempty"`
}

type plugin struct {
	Name   string         `json:"name"`
	Config map[string]any `json:"config"`
}

type certificate struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	SNIs []sni  `json:"snis"`
}

type sni struct {
	Name string `json:"name"`
}

func ms(v, def string) int64 {
	if v == "" {
		v = def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		d, _ = time.ParseDuration(def)
	}
	return d.Milliseconds()
}

// Name is a route's service name in Kong: its Ingress and its place in the State.
func Name(r kic.Route, i int) string {
	return strings.ReplaceAll(r.Ingress, "/", ".") + "." + strconv.Itoa(i)
}

// Render implements kic.Driver.
func (Driver) Render(s kic.State) (kic.Plan, error) {
	if err := kic.CheckState(s); err != nil {
		return kic.Plan{}, err
	}
	d := declarative{FormatVersion: "3.0"}
	for i, r := range s.Routes {
		protocols := []string{"http"}
		redirect := 0
		if r.TLS {
			protocols, redirect = []string{"https"}, 308 // plain HTTP is redirected by Kong itself
			if r.Annotations["ssl-redirect"] == "false" {
				protocols, redirect = []string{"http", "https"}, 0
			}
		}
		name := Name(r, i)
		d.Services = append(d.Services, service{
			Name:           name,
			URL:            "http://" + hostPort(r.Backend),
			ConnectTimeout: ms(r.Annotations["connect-timeout"], optOr(s, "connect-timeout", "5s")),
			ReadTimeout:    ms(r.Annotations["read-timeout"], optOr(s, "read-timeout", "60s")),
			WriteTimeout:   ms(r.Annotations["write-timeout"], optOr(s, "write-timeout", "60s")),
			Routes: []route{{Name: name, Hosts: []string{r.Host}, Paths: []string{r.Path}, Protocols: protocols,
				StripPath: r.Annotations["strip-path"] == "true", PreserveHost: true, HTTPSRedirectStatusCode: redirect}},
		})
	}
	for _, c := range s.Challenges {
		d.Routes = append(d.Routes, route{Name: "acme." + c.Token, Paths: []string{kic.ChallengePrefix + c.Token}, Protocols: []string{"http"},
			Plugins: []plugin{{Name: "request-termination", Config: map[string]any{"status_code": 200, "content_type": "text/plain", "body": c.KeyAuthorization}}}})
	}
	for _, c := range s.Certificates {
		cert := certificate{Cert: string(c.Chain), Key: string(c.Key)}
		for _, h := range c.Hosts {
			cert.SNIs = append(cert.SNIs, sni{Name: h})
		}
		d.Certificates = append(d.Certificates, cert)
	}
	body, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return kic.Plan{}, err
	}
	port, _ := strconv.Atoi(optOr(s, "admin-port", "8001"))
	return kic.Plan{Reload: kic.Action{Call: &kic.Call{Port: port, Method: "POST", Path: "/config", ContentType: "application/json", Body: body}}}, nil
}

func optOr(s kic.State, name, def string) string {
	if v, ok := s.Options[name]; ok {
		return v
	}
	return def
}

func hostPort(b kic.Backend) string {
	if strings.Contains(b.Address, ":") {
		return "[" + b.Address + "]:" + strconv.Itoa(b.Port)
	}
	return b.Address + ":" + strconv.Itoa(b.Port)
}

// Blame implements kic.Blamer: Kong's refusal names the entities it refused (flattened_errors).
func (Driver) Blame(p kic.Plan, out string) []string {
	var d declarative
	if p.Reload.Call == nil || json.Unmarshal(p.Reload.Call.Body, &d) != nil {
		return nil
	}
	seen := map[string]bool{}
	var who []string
	for _, sv := range d.Services {
		if strings.Contains(out, fmt.Sprintf("%q", sv.Name)) {
			i := strings.LastIndexByte(sv.Name, '.')
			ns, name, _ := strings.Cut(sv.Name[:i], ".")
			if ing := ns + "/" + name; !seen[ing] {
				seen[ing] = true
				who = append(who, ing)
			}
		}
	}
	return who
}

var (
	_ kic.Driver = Driver{}
	_ kic.Blamer = Driver{}
)
