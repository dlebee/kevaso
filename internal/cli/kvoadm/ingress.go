package kvoadm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	kicdrivers "kevaso.com/core/builtin/kic"
	"kevaso.com/core/sdk/kic"
)

// IngressOptions are kvoadm ingress install's flags.
type IngressOptions struct {
	Class  string // the IngressClass (default public)
	Driver string // nginx (default), caddy, kong
	Public bool   // reachable from the internet
	// HostPort: the proxy's ports open on its worker's address on this network (default external)
	// (a HostPort service, hostPort: { worker: … }); Provider instead puts them behind a load
	// balancer of that provider (a LoadBalancer service, loadBalancer: { provider: … }).
	HostPort string
	Provider string
	Image    string            // default: the driver's vendor image
	Runtime  string            // default docker
	Options  map[string]string // the driver's options
	Hosts    []v1.HostAssignment
	Context  string
}

func parseIngress(args []string) (IngressOptions, error) {
	o := IngressOptions{Class: "public", Driver: "nginx", Runtime: "docker"}
	if len(args) == 0 || args[0] != "install" {
		return o, errors.New("ingress install [--class NAME] [--driver nginx|caddy|kong] [--public] [--host-port internal|external | --provider PROVIDER] [--host NAME=NAMESPACE[,NAMESPACE]]… [--image REF] [--runtime NAME] [--option K=V]…")
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		val := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		var v string
		switch a {
		case "--class":
			o.Class, err = val()
		case "--driver":
			o.Driver, err = val()
		case "--public":
			o.Public = true
		case "--provider":
			o.Provider, err = val()
		case "--host-port":
			if o.HostPort, err = val(); err == nil && o.HostPort != v1.NetworkInternal && o.HostPort != v1.NetworkExternal {
				err = fmt.Errorf("--host-port %s: internal or external", o.HostPort)
			}
		case "--image":
			o.Image, err = val()
		case "--runtime":
			o.Runtime, err = val()
		case "--cluster":
			o.Context, err = val()
		case "--host":
			if v, err = val(); err == nil {
				err = o.addHost(v)
			}
		case "--option":
			if v, err = val(); err == nil {
				k, value, ok := strings.Cut(v, "=")
				if !ok {
					return o, fmt.Errorf("--option %s: want KEY=VALUE", v)
				}
				if o.Options == nil {
					o.Options = map[string]string{}
				}
				o.Options[k] = value
			}
		default:
			return o, fmt.Errorf("unknown flag %s", a)
		}
		if err != nil {
			return o, err
		}
	}
	switch {
	case o.HostPort != "" && o.Provider != "":
		return o, errors.New("--host-port or --provider, not both: the proxy's ports open on its host's address or on a load balancer")
	case o.HostPort == "" && o.Provider == "":
		o.HostPort = v1.NetworkExternal
	}
	return o, nil
}

// addHost records one --host NAME=NAMESPACE[,NAMESPACE]. NAME may be a suffix (*.example.com).
func (o *IngressOptions) addHost(v string) error {
	host, ns, ok := strings.Cut(v, "=")
	if !ok || strings.TrimSpace(host) == "" || strings.TrimSpace(ns) == "" {
		return fmt.Errorf("--host %s: want NAME=NAMESPACE[,NAMESPACE] (NAME may be a suffix *.example.com)", v)
	}
	host = v1.NormalizeDNS(host)
	if !v1.ValidHostPattern(host) {
		return fmt.Errorf("--host %s: %q is not a host name or a suffix *.example.com", v, host)
	}
	var nss []string
	seen := map[string]bool{}
	for _, n := range strings.Split(ns, ",") {
		n = strings.TrimSpace(n)
		if n == "" || strings.ContainsAny(n, " \t=") {
			return fmt.Errorf("--host %s: namespace %q is not a name", v, n)
		}
		if !seen[n] {
			seen[n] = true
			nss = append(nss, n)
		}
	}
	o.Hosts = addAssignment(o.Hosts, v1.HostAssignment{Host: host, Namespaces: nss})
	return nil
}

func addAssignment(hosts []v1.HostAssignment, a v1.HostAssignment) []v1.HostAssignment {
	for i := range hosts {
		if hosts[i].Host != a.Host {
			continue
		}
		seen := map[string]bool{}
		for _, n := range hosts[i].Namespaces {
			seen[n] = true
		}
		for _, n := range a.Namespaces {
			if !seen[n] {
				seen[n] = true
				hosts[i].Namespaces = append(hosts[i].Namespaces, n)
			}
		}
		return hosts
	}
	return append(hosts, a)
}

// IngressObjects are what kvoadm ingress install creates: the controller silo (the driver's
// vendor image, as shipped, its ports open on its host's address or a load balancer) and its
// IngressClass. Pure.
func IngressObjects(o IngressOptions, drivers kic.Registry) (*v1.Silo, *v1.IngressClass, error) {
	d, err := drivers.Get(o.Driver)
	if err != nil {
		names := make([]string, 0, len(drivers))
		for n := range drivers {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, nil, fmt.Errorf("no ingress driver %q (there are: %s)", o.Driver, strings.Join(names, ", "))
	}
	info := d.Info()
	if err := kic.CheckKnobs(info.Options, o.Options, "option "); err != nil {
		return nil, nil, err
	}
	image := o.Image
	if image == "" {
		image = info.Image
	}
	name := "ingress-" + o.Class
	var declared []v1.SiloPort
	var ports []v1.ServicePort
	for i, p := range info.Ports {
		pn := []string{"http", "https"}
		n := fmt.Sprintf("port-%d", p)
		if i < len(pn) {
			n = pn[i]
		}
		declared = append(declared, v1.SiloPort{Name: n, Port: p})
		ports = append(ports, v1.ServicePort{Port: n})
	}
	svc := v1.SiloService{Type: v1.ServiceHostPort, Ports: ports, HostPort: &v1.HostPortSource{Worker: o.HostPort}}
	if o.Provider != "" {
		svc = v1.SiloService{Type: v1.ServiceLoadBalancer, Ports: ports, LoadBalancer: &v1.LoadBalancerSpec{Provider: o.Provider}}
	}
	silo := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"},
		ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "kevaso-system", Labels: map[string]string{"kevaso.com/ingress-class": o.Class}},
		Spec: v1.SiloSpec{Runtime: o.Runtime, Container: &v1.ContainerSource{Image: image}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Ports: declared, Services: []v1.SiloService{svc}}}
	class := &v1.IngressClass{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IngressClass"}, ObjectMeta: meta.ObjectMeta{Name: o.Class},
		Spec: v1.IngressClassSpec{Public: o.Public, Hosts: o.Hosts, Controller: v1.IngressController{Driver: o.Driver, Options: o.Options, Namespace: "kevaso-system", Silo: name}}}
	return silo, class, nil
}

// ingressCmd runs kvoadm ingress install, as the cluster-admin of a cluster folder (--cluster): one
// command for an ingress class served by a stock proxy (design §7.3).
func ingressCmd(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) > 0 && args[0] == "assign" {
		return ingressAssign(ctx, args[1:], stdout)
	}
	o, err := parseIngress(args)
	if err != nil {
		return err
	}
	silo, class, err := IngressObjects(o, kicdrivers.Builtin())
	if err != nil {
		return err
	}
	c, _, err := adminClient(o.Context)
	if err != nil {
		return err
	}
	nsObj := &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "kevaso-system"}}
	for _, obj := range []meta.Object{nsObj, silo, class} {
		if err := c.Create(ctx, obj); err != nil && !client.IsAlreadyExists(err) {
			return fmt.Errorf("%s %s: %w", obj.GetTypeMeta().Kind, obj.GetObjectMeta().Name, err)
		} else if client.IsAlreadyExists(err) {
			if _, ok := obj.(*v1.IngressClass); ok && len(o.Hosts) > 0 {
				_, _ = fmt.Fprintf(stdout, "→ IngressClass %s is already there: left as it is. Add a host with: kvoadm ingress assign %s --host NAME=%s\n",
					obj.GetObjectMeta().Name, obj.GetObjectMeta().Name, o.Hosts[0].Namespaces[0])
			} else {
				_, _ = fmt.Fprintf(stdout, "→ %s %s is already there: left as it is\n", obj.GetTypeMeta().Kind, obj.GetObjectMeta().Name)
			}
			continue
		}
		_, _ = fmt.Fprintf(stdout, "→ %s %s\n", obj.GetTypeMeta().Kind, obj.GetObjectMeta().Name)
	}
	where := "on its host's " + o.HostPort + " IP"
	if o.Provider != "" {
		where = "behind a " + o.Provider + " address"
	}
	_, _ = fmt.Fprintf(stdout, "Ingress class %s: %s (%s) in silo kevaso-system/%s, %s. Kevaso writes its config from outside;\n",
		class.Name, o.Driver, silo.Spec.From(), silo.Name, where)
	_, _ = fmt.Fprintf(stdout, "see it with: kvo get ingressclass %s -o yaml\n", class.Name)
	if len(o.Hosts) == 0 {
		_, _ = fmt.Fprintf(stdout, "No host is assigned yet. An Ingress is refused until one is: kvoadm ingress assign %s --host NAME=NAMESPACE\n", class.Name)
		_, _ = fmt.Fprintf(stdout, "(NAME may be a suffix *.example.com), or set IngressClass.spec.hosts.\n")
	}
	return nil
}

// ingressAssign adds host assignments to an IngressClass that is already there.
func ingressAssign(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("ingress assign CLASS --host NAME=NAMESPACE[,NAMESPACE]… [--cluster NAME]")
	}
	var o IngressOptions
	o.Class = args[0]
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--host":
			if i+1 >= len(args) {
				return errors.New("--host needs NAME=NAMESPACE[,NAMESPACE]")
			}
			i++
			if err := o.addHost(args[i]); err != nil {
				return err
			}
		case "--cluster":
			if i+1 >= len(args) {
				return errors.New("--cluster needs a value")
			}
			i++
			o.Context = args[i]
		default:
			if name, value, ok := strings.Cut(a, "="); ok && name == "--host" {
				if err := o.addHost(value); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("unknown flag %s", a)
		}
	}
	if len(o.Hosts) == 0 {
		return errors.New("ingress assign CLASS --host NAME=NAMESPACE[,NAMESPACE]… [--cluster NAME]")
	}
	c, _, err := adminClient(o.Context)
	if err != nil {
		return err
	}
	var class v1.IngressClass
	if err := c.Get(ctx, "IngressClass", "", o.Class, &class); err != nil {
		return fmt.Errorf("IngressClass %s: %w", o.Class, err)
	}
	for _, h := range o.Hosts {
		class.Spec.Hosts = addAssignment(class.Spec.Hosts, h)
	}
	if err := c.Update(ctx, &class); err != nil {
		return fmt.Errorf("IngressClass %s: %w", o.Class, err)
	}
	for _, h := range o.Hosts {
		_, _ = fmt.Fprintf(stdout, "→ IngressClass %s assigns %s to %s\n", class.Name, h.Host, strings.Join(h.Namespaces, ", "))
	}
	return nil
}
