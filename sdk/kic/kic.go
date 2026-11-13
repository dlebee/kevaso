// Package kic is the ingress driver interface (design §7.3): how Kevaso drives a stock proxy (nginx,
// Caddy, HAProxy, Kong…) from the outside, behind one small interface (next to the runtime, network
// and cert-controller interfaces).
//
// Kevaso keeps the rest: which routes, certificates and ACME challenges an ingress controller
// serves (State, computed by the control plane per IngressClass), and applying them (the agent of the
// controller silo's host writes the files into the silo, runs the check, and only then the reload).
// A driver does one thing: turn State into that proxy's own configuration and say how to check it
// and make it take effect (Plan). It is pure: the same State renders the same bytes, so "unchanged"
// means nothing is touched. The proxy is the vendor's image as shipped: it never calls Kevaso.
//
// An IngressClass names its driver (spec.controller.driver) and gives it options; an Ingress gives
// it knobs as annotations prefixed with the driver's name ("nginx/proxy-body-size"). Both are
// checked against what the driver declares (Info): an unknown one is refused, never ignored.
package kic

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

// State is the proxy-neutral desired state of one ingress controller. Every list is sorted (routes
// by host, then longest path first), so it is deterministic.
type State struct {
	Class        string            `json:"class"`
	Options      map[string]string `json:"options,omitempty"` // the class's spec.controller.options
	Routes       []Route           `json:"routes,omitempty"`
	Certificates []Certificate     `json:"certificates,omitempty"`
	Challenges   []Challenge       `json:"challenges,omitempty"` // ACME HTTP-01, served on port 80
}

// Route sends a host and path prefix to a backend.
type Route struct {
	Ingress string  `json:"ingress"` // namespace/name, for messages and blame
	Host    string  `json:"host"`    // lower case
	Path    string  `json:"path"`    // prefix, starts with /
	Backend Backend `json:"backend"`
	// TLS: served on 443 with the host's certificate, and port 80 redirects there.
	TLS bool `json:"tls,omitempty"`
	// Annotations are the Ingress's knobs for this driver, prefix stripped ("proxy-body-size").
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Backend is where a route goes: a silo's private address and port.
type Backend struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// Certificate is a certificate chain and its key for some hosts (PEM). Name is stable while the
// certificate lives (namespace/secret); its content changes on renewal.
type Certificate struct {
	Name    string   `json:"name"`
	Ingress string   `json:"ingress"`
	Hosts   []string `json:"hosts"`
	Chain   []byte   `json:"chain"`
	Key     []byte   `json:"key"`
}

// Challenge is a pending ACME HTTP-01 answer: GET /.well-known/acme-challenge/TOKEN on port 80, for
// any host, answers KeyAuthorization.
type Challenge struct {
	Token            string `json:"token"`
	KeyAuthorization string `json:"keyAuthorization"`
}

// ChallengePrefix is the path ACME HTTP-01 challenges are asked on.
const ChallengePrefix = "/.well-known/acme-challenge/"

// Plan is what a driver rendered: what to put where, how to check it, how to make it take effect.
type Plan struct {
	// Config is the proxy's main configuration. The agent writes it next to its path (Path+".next"),
	// runs Check on that, and only if it passes moves it into place and runs Reload. Empty Path: no
	// file (an admin-API driver: Reload carries everything).
	Config File `json:"config"`
	// Files support Config (certificates and keys). They live in Dir and are named by their content
	// (ContentName), so writing one before the check never changes a file the running config uses.
	Files []File `json:"files,omitempty"`
	// Dir is the folder Files live in. It is Kevaso's: after a good apply, anything else in it is
	// removed (a deleted certificate's key does not linger).
	Dir string `json:"dir,omitempty"`
	// Check is run inside the silo before anything takes effect; ConfigToken in it is the staged
	// config's path. Exit 0: good. Empty: the proxy checks on Reload itself (an admin API).
	Check []string `json:"check,omitempty"`
	// Reload makes the checked config take effect.
	Reload Action `json:"reload"`
}

// ConfigToken, in Check, is replaced by the staged config's path.
const ConfigToken = "{config}"

// File is one file in the silo.
type File struct {
	Path string      `json:"path"`
	Mode fs.FileMode `json:"mode"`
	Data []byte      `json:"data"`
	// Secret: the file holds a private key; the agent never logs its content.
	Secret bool `json:"secret,omitempty"`
}

// Action makes a config take effect: a command run in the silo, or a call to the proxy's admin API.
type Action struct {
	Exec []string `json:"exec,omitempty"`
	Call *Call    `json:"call,omitempty"`
}

// Call is an HTTP request to the proxy's admin API, on the silo's private address. A 2xx answer is
// success; anything else is a rejection (the proxy keeps what it had), its body the reason.
type Call struct {
	Port        int    `json:"port"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	ContentType string `json:"contentType,omitempty"`
	Body        []byte `json:"body,omitempty"`
}

// Knob is one option or annotation a driver understands.
type Knob struct {
	Name string
	Help string
	// Valid checks a value (nil: anything). Values reach a proxy's configuration, so a driver
	// checks every one it pastes in.
	Valid func(string) error
}

// Info describes a driver.
type Info struct {
	Name        string // also the annotation prefix: NAME/knob
	Description string
	Image       string // the vendor's image a default controller runs
	Ports       []int  // what it listens on (80 and 443, …)
	Options     []Knob // a class's spec.controller.options
	Annotations []Knob // an Ingress's NAME/knob annotations
}

// Driver renders State into a proxy's configuration. Render must be pure and deterministic.
type Driver interface {
	Info() Info
	// Render turns s (its options and annotations already checked against Info) into a Plan.
	Render(s State) (Plan, error)
}

// Blamer is a driver that can tell, from its check's output, which Ingresses caused a rejection.
type Blamer interface {
	Blame(p Plan, checkOutput string) []string
}

// Registry is the drivers a cluster knows, by name.
type Registry map[string]Driver

// Get returns the named driver.
func (r Registry) Get(name string) (Driver, error) {
	if d, ok := r[name]; ok {
		return d, nil
	}
	return nil, errors.New("kic: no ingress driver named " + name)
}

// CheckKnobs checks values against knobs: an unknown name or a bad value is refused. what names
// them in messages ("option", "annotation nginx/").
func CheckKnobs(knobs []Knob, values map[string]string, what string) error {
	byName := map[string]Knob{}
	for _, k := range knobs {
		byName[k.Name] = k
	}
	var problems []string
	for _, name := range sortedKeys(values) {
		k, ok := byName[name]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("unknown %s%s", what, name))
		case k.Valid != nil:
			if err := k.Valid(values[name]); err != nil {
				problems = append(problems, fmt.Sprintf("%s%s: %v", what, name, err))
			}
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// Annotations returns the annotations for the driver named name, prefix stripped.
func Annotations(name string, annotations map[string]string) map[string]string {
	var out map[string]string
	for k, v := range annotations {
		if knob, ok := strings.CutPrefix(k, name+"/"); ok {
			if out == nil {
				out = map[string]string{}
			}
			out[knob] = v
		}
	}
	return out
}

// What may reach a proxy's configuration unquoted: no space, quote, brace, semicolon or newline.
var (
	safeHost  = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
	safePath  = regexp.MustCompile(`^/[A-Za-z0-9._~%/-]*$`)
	safeToken = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	safeKA    = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	safeAddr  = regexp.MustCompile(`^[A-Za-z0-9.:-]+$`)
)

// CheckState refuses a State whose host names, paths, addresses or challenges hold anything but
// the characters they are made of, so no driver can be made to paste configuration in.
func CheckState(s State) error {
	for _, r := range s.Routes {
		switch {
		case !safeHost.MatchString(r.Host):
			return fmt.Errorf("ingress %s: host %q", r.Ingress, r.Host)
		case !safePath.MatchString(r.Path):
			return fmt.Errorf("ingress %s: path %q (letters, digits and ._~%%/- only)", r.Ingress, r.Path)
		case !safeAddr.MatchString(r.Backend.Address) || r.Backend.Port <= 0 || r.Backend.Port > 65535:
			return fmt.Errorf("ingress %s: backend %s:%d", r.Ingress, r.Backend.Address, r.Backend.Port)
		}
	}
	for _, c := range s.Certificates {
		for _, h := range c.Hosts {
			if !safeHost.MatchString(h) {
				return fmt.Errorf("certificate %s: host %q", c.Name, h)
			}
		}
	}
	for _, c := range s.Challenges {
		if !safeToken.MatchString(c.Token) || !safeKA.MatchString(c.KeyAuthorization) {
			return fmt.Errorf("ACME challenge %q: not a token and key authorization", c.Token)
		}
	}
	return nil
}

// Validate checks a State against d: its characters (CheckState), its options and every route's
// annotations.
func Validate(d Driver, s State) error {
	if err := CheckState(s); err != nil {
		return err
	}
	info := d.Info()
	if err := CheckKnobs(info.Options, s.Options, "option "); err != nil {
		return err
	}
	for _, r := range s.Routes {
		if err := CheckKnobs(info.Annotations, r.Annotations, "annotation "+info.Name+"/"); err != nil {
			return fmt.Errorf("ingress %s: %w", r.Ingress, err)
		}
	}
	return nil
}

// ContentName is a file name for data under dir: its content's hash plus ext, so a changed file is
// a new file.
func ContentName(dir string, data []byte, ext string) string {
	sum := sha256.Sum256(data)
	return strings.TrimSuffix(dir, "/") + "/" + hex.EncodeToString(sum[:8]) + ext
}

// Hash identifies a Plan: equal plans, equal hashes.
func (p Plan) Hash() string {
	h := sha256.New()
	put := func(b []byte) {
		_, _ = fmt.Fprintf(h, "%d:", len(b))
		_, _ = h.Write(b)
	}
	for _, f := range append([]File{p.Config}, p.Files...) {
		put([]byte(f.Path))
		put([]byte(f.Mode.String()))
		put(f.Data)
	}
	put([]byte(p.Dir))
	put([]byte(strings.Join(p.Check, "\x00")))
	put([]byte(strings.Join(p.Reload.Exec, "\x00")))
	if c := p.Reload.Call; c != nil {
		put([]byte(fmt.Sprintf("%d %s %s %s", c.Port, c.Method, c.Path, c.ContentType)))
		put(c.Body)
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

// Hosts groups routes by host, in State order (a helper for drivers).
func Hosts(routes []Route) ([]string, map[string][]Route) {
	var order []string
	by := map[string][]Route{}
	for _, r := range routes {
		if _, ok := by[r.Host]; !ok {
			order = append(order, r.Host)
		}
		by[r.Host] = append(by[r.Host], r)
	}
	return order, by
}

// CertFor is the certificate serving host: an exact name first, then a wildcard (*.example.com).
func CertFor(certs []Certificate, host string) (Certificate, bool) {
	for _, c := range certs {
		for _, h := range c.Hosts {
			if strings.EqualFold(h, host) {
				return c, true
			}
		}
	}
	if i := strings.IndexByte(host, '.'); i > 0 {
		wild := "*" + host[i:]
		for _, c := range certs {
			for _, h := range c.Hosts {
				if strings.EqualFold(h, wild) {
					return c, true
				}
			}
		}
	}
	return Certificate{}, false
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Blame markers: a driver writes BlameMark+"namespace/name" on the line before what an Ingress
// brought into a config, and BlameEnd after it, so MarkedBlame can tell which Ingress a config
// check's line number points into.
const (
	BlameMark = "# ingress "
	BlameEnd  = "# -"
)

// MarkedBlame is the Ingress whose marked section holds line (1-based) of data, if any.
func MarkedBlame(data []byte, line int) []string {
	lines := strings.Split(string(data), "\n")
	if line < 1 || line > len(lines) {
		return nil
	}
	for i := line - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == BlameEnd {
			return nil
		}
		if ing, ok := strings.CutPrefix(l, BlameMark); ok {
			return []string{ing}
		}
	}
	return nil
}

// Matches is a Knob check: the value matches pattern (anchored), described as what.
func Matches(pattern, what string) func(string) error {
	re := regexp.MustCompile(`^(?:` + pattern + `)$`)
	return func(v string) error {
		if !re.MatchString(v) {
			return fmt.Errorf("%q isn't %s", v, what)
		}
		return nil
	}
}

// Common Knob checks.
var (
	Size     = Matches(`[0-9]{1,9}[kKmMgG]?`, "a size (10m, 512k)")
	Duration = Matches(`[0-9]{1,6}(ms|s|m|h)`, "a duration (30s, 5m)")
	Count    = Matches(`[1-9][0-9]{0,6}`, "a positive number")
	Bool     = Matches(`true|false`, "true or false")
	Name     = Matches(`[A-Za-z0-9_.-]{1,64}`, "a name")
	Path     = Matches(`/[A-Za-z0-9._/-]{0,200}`, "an absolute path")
)
