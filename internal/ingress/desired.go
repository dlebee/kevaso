// Package ingress computes what an ingress controller serves (design §7.3) and applies it to a stock
// proxy from outside. Desire is pure: the control plane calls it per IngressClass with what the
// store holds, and the agent of each controller silo's host renders the result with the class's
// driver (sdk/kic) and applies it (apply.go).
package ingress

import (
	"encoding/pem"
	"fmt"
	"slices"
	"sort"
	"strings"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kic"
)

// Inputs is everything Desire looks at for one class.
type Inputs struct {
	Class     *v1.IngressClass
	Driver    kic.Driver // the class's driver; nil: not one this cluster knows
	Ingresses []*v1.Ingress
	// Silo returns a silo by namespace and name (nil: none).
	Silo func(namespace, name string) *v1.Silo
	// Bundle returns a TLS Secret's value (certificate chain, then key, PEM), nil if not issued yet.
	Bundle func(namespace, secret string) []byte
	// Challenges are the pending ACME HTTP-01 answers (token → key authorization).
	Challenges map[string]string
	// Routed says whether traffic may go to a silo now (design §0.6: routeWhen). Nil: it runs and
	// has an address. Probes plug their decision in here.
	Routed func(*v1.Silo) bool
}

// Desired is a class's desired state, and what was left out of it and why.
type Desired struct {
	Class  string    `json:"class"`
	Driver string    `json:"driver"`
	State  kic.State `json:"state"`
	// Problem: the class can't be served at all (an unknown driver, an option it refuses); State
	// is empty and nothing is applied.
	Problem string `json:"problem,omitempty"`
	// Refused are the Ingresses left out (namespace/name → why: an annotation the driver refuses,
	// a host or path it can't take). Their routes are not in State; the rest is.
	Refused map[string]string `json:"refused,omitempty"`
}

// Routed is the default Routed: the silo runs and has an address.
func Routed(s *v1.Silo) bool {
	return s != nil && s.Status.Address != "" && (s.Status.Phase == "" || s.Status.Phase == "Running")
}

// CheckIngress is what d refuses in ing (nil: nothing): its annotations for d, and host names or
// paths that can't go into a proxy's configuration.
func CheckIngress(d kic.Driver, ing *v1.Ingress) error {
	info := d.Info()
	if err := kic.CheckKnobs(info.Annotations, kic.Annotations(info.Name, ing.Annotations), "annotation "+info.Name+"/"); err != nil {
		return err
	}
	probe := kic.State{}
	for _, h := range ing.Spec.Hosts {
		for _, r := range ing.Spec.Rules {
			probe.Routes = append(probe.Routes, kic.Route{Ingress: ing.Namespace + "/" + ing.Name, Host: strings.ToLower(strings.TrimSuffix(h, ".")), Path: pathOf(r), Backend: kic.Backend{Address: "0.0.0.0", Port: 1}})
		}
	}
	return kic.CheckState(probe)
}

func pathOf(r v1.IngressRule) string {
	if r.Path == "" {
		return "/"
	}
	return r.Path
}

// Desire is the class's desired state. Pure and deterministic: Ingresses in name order, routes by
// host then longest path first (the first Ingress to claim a host and path keeps it), certificates
// by name, challenges by token.
func Desire(in Inputs) Desired {
	c := in.Class
	out := Desired{Class: c.Name, Driver: c.Spec.Controller.Driver, State: kic.State{Class: c.Name}}
	if in.Driver == nil {
		out.Problem = fmt.Sprintf("no ingress driver named %q", c.Spec.Controller.Driver)
		return out
	}
	info := in.Driver.Info()
	if err := kic.CheckKnobs(info.Options, c.Spec.Controller.Options, "option "); err != nil {
		out.Problem = err.Error()
		return out
	}
	if len(c.Spec.Controller.Options) > 0 {
		out.State.Options = map[string]string{}
		for k, v := range c.Spec.Controller.Options {
			out.State.Options[k] = v
		}
	}
	routed := in.Routed
	if routed == nil {
		routed = Routed
	}
	ings := append([]*v1.Ingress(nil), in.Ingresses...)
	sort.Slice(ings, func(i, j int) bool {
		return ings[i].Namespace+"/"+ings[i].Name < ings[j].Namespace+"/"+ings[j].Name
	})
	claimed := map[string]bool{} // host + " " + path
	certs := map[string]bool{}
	for _, ing := range ings {
		if ing.Spec.IngressClass != c.Name || ing.DeletionTimestamp != nil {
			continue
		}
		who := ing.Namespace + "/" + ing.Name
		if err := CheckIngress(in.Driver, ing); err != nil {
			if out.Refused == nil {
				out.Refused = map[string]string{}
			}
			out.Refused[who] = err.Error()
			continue
		}
		knobs := kic.Annotations(info.Name, ing.Annotations)
		tls := !ing.Spec.TLS.None
		for _, r := range ing.Spec.Rules {
			b, ok := backend(in, ing.Namespace, r.Silo, routed)
			if !ok {
				continue // the target or its port isn't there (yet), or it isn't routed to now
			}
			for _, h := range ing.Spec.Hosts {
				h = strings.ToLower(strings.TrimSuffix(h, "."))
				key := h + " " + pathOf(r)
				if claimed[key] {
					continue
				}
				claimed[key] = true
				out.State.Routes = append(out.State.Routes, kic.Route{Ingress: who, Host: h, Path: pathOf(r), Backend: b, TLS: tls, Annotations: knobs})
			}
		}
		if !tls || in.Bundle == nil {
			continue
		}
		secret := v1.TLSSecret(ing)
		name := ing.Namespace + "/" + secret
		if certs[name] {
			continue
		}
		chain, key := SplitBundle(in.Bundle(ing.Namespace, secret))
		if chain == nil || key == nil {
			continue // not issued yet
		}
		certs[name] = true
		hosts := make([]string, 0, len(ing.Spec.Hosts))
		for _, h := range ing.Spec.Hosts {
			hosts = append(hosts, strings.ToLower(strings.TrimSuffix(h, ".")))
		}
		sort.Strings(hosts)
		out.State.Certificates = append(out.State.Certificates, kic.Certificate{Name: name, Ingress: who, Hosts: hosts, Chain: chain, Key: key})
	}
	sort.SliceStable(out.State.Routes, func(i, j int) bool {
		a, b := out.State.Routes[i], out.State.Routes[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if len(a.Path) != len(b.Path) {
			return len(a.Path) > len(b.Path)
		}
		return a.Path < b.Path
	})
	sort.Slice(out.State.Certificates, func(i, j int) bool { return out.State.Certificates[i].Name < out.State.Certificates[j].Name })
	for t, ka := range in.Challenges {
		out.State.Challenges = append(out.State.Challenges, kic.Challenge{Token: t, KeyAuthorization: ka})
	}
	sort.Slice(out.State.Challenges, func(i, j int) bool { return out.State.Challenges[i].Token < out.State.Challenges[j].Token })
	if err := kic.CheckState(out.State); err != nil { // a challenge the driver can't take: leave them all out
		out.State.Challenges = nil
	}
	return out
}

// backend is a target silo's private address and the number of its named port.
func backend(in Inputs, ns string, t v1.IngressTarget, routed func(*v1.Silo) bool) (kic.Backend, bool) {
	if in.Silo == nil {
		return kic.Backend{}, false
	}
	s := in.Silo(ns, t.Name)
	if s == nil || s.Spec.Service == nil || !routed(s) || s.Status.Address == "" {
		return kic.Backend{}, false
	}
	for _, p := range s.Spec.Service.Ports {
		if p.Name == t.Port {
			return kic.Backend{Address: s.Status.Address, Port: p.Port}, true
		}
	}
	return kic.Backend{}, false
}

// SplitBundle splits a TLS Secret's value into its certificate chain and its private key (PEM);
// nil, nil if it has no certificate or no key.
func SplitBundle(bundle []byte) (chain, key []byte) {
	rest := bundle
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch {
		case b.Type == "CERTIFICATE":
			chain = append(chain, pem.EncodeToMemory(b)...)
		case strings.HasSuffix(b.Type, "PRIVATE KEY") && key == nil:
			key = pem.EncodeToMemory(b)
		}
	}
	if chain == nil || key == nil {
		return nil, nil
	}
	return chain, key
}

// HostWrite checks a worker host's write of an IngressClass's status: it may change only the
// entries of controller silos on itself (and the conditions, which it recomputes over them all).
func HostWrite(old, next v1.IngressClassStatus, host string) error {
	others := func(st v1.IngressClassStatus) map[string]v1.IngressControllerStatus {
		m := map[string]v1.IngressControllerStatus{}
		for _, e := range st.Controllers {
			if e.Host != host {
				m[e.Silo] = e
			}
		}
		return m
	}
	a, b := others(old), others(next)
	if len(a) != len(b) {
		return fmt.Errorf("host %s may only write the status of ingress controllers on it", host)
	}
	for k, e := range a {
		if f, ok := b[k]; !ok || fmt.Sprint(e) != fmt.Sprint(f) {
			return fmt.Errorf("host %s may not change the status of ingress controller %s on %s", host, k, e.Host)
		}
	}
	return nil
}

// Refused says why ing isn't served as it is on class, as a condition's reason and message ("" if
// it is): the class's driver refuses it (an annotation it doesn't know, a value it won't take), or a
// controller's proxy refused the latest configuration and blames it.
func Refused(drivers kic.Registry, class *v1.IngressClass, ing *v1.Ingress) (reason, msg string) {
	d, err := drivers.Get(class.Spec.Controller.Driver)
	if err != nil {
		return "NoDriver", fmt.Sprintf("ingress class %s names driver %q, which this cluster doesn't have", class.Name, class.Spec.Controller.Driver)
	}
	if err := CheckIngress(d, ing); err != nil {
		return "Refused", "driver " + d.Info().Name + " refuses it: " + err.Error()
	}
	who := ing.Namespace + "/" + ing.Name
	for _, e := range class.Status.Controllers {
		if e.Rejected != "" && slices.Contains(e.Blamed, who) {
			return "Rejected", fmt.Sprintf("controller %s refused the configuration with it (the last good one is still served): %s", e.Silo, e.Rejected)
		}
	}
	return "", ""
}
