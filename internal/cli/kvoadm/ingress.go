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
	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/sdk/kic"
)

// IngressOptions are kvoadm ingress install's flags.
type IngressOptions struct {
	Class  string // the IngressClass (default public)
	Driver string // nginx (default), caddy, kong
	Public bool   // reachable from the internet
	// HostPort: the proxy's ports open on its host's address on this network (default external);
	// LBClass instead puts them behind a load balancer of that class.
	HostPort string
	LBClass  string
	Image    string            // default: the driver's vendor image
	Runtime  string            // default docker
	Options  map[string]string // the driver's options
	Context  string
}

func parseIngress(args []string) (IngressOptions, error) {
	o := IngressOptions{Class: "public", Driver: "nginx", Runtime: "docker"}
	if len(args) == 0 || args[0] != "install" {
		return o, errors.New("ingress install [--class NAME] [--driver nginx|caddy|kong] [--public] [--host-port internal|external | --lb-class CLASS] [--image REF] [--runtime NAME] [--option K=V]…")
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
		case "--lb-class":
			o.LBClass, err = val()
		case "--host-port":
			if o.HostPort, err = val(); err == nil && o.HostPort != v1.NetworkInternal && o.HostPort != v1.NetworkExternal {
				err = fmt.Errorf("--host-port %s: internal or external", o.HostPort)
			}
		case "--image":
			o.Image, err = val()
		case "--runtime":
			o.Runtime, err = val()
		case "--context":
			o.Context, err = val()
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
	case o.HostPort != "" && o.LBClass != "":
		return o, errors.New("--host-port or --lb-class, not both: the proxy's ports open on its host's address or on a load balancer")
	case o.HostPort == "" && o.LBClass == "":
		o.HostPort = v1.NetworkExternal
	}
	return o, nil
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
		sp := v1.ServicePort{Port: n, LoadBalancer: o.LBClass != ""}
		if o.HostPort != "" {
			sp.HostPort = []string{o.HostPort}
		}
		ports = append(ports, sp)
	}
	svc := &v1.SiloService{Ports: ports}
	if o.LBClass != "" {
		svc.LoadBalancer = &v1.LoadBalancerSpec{Class: o.LBClass}
	}
	silo := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"},
		ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "kevaso-system", Labels: map[string]string{"kevaso.com/ingress-class": o.Class}},
		Spec: v1.SiloSpec{Runtime: o.Runtime, Container: &v1.ContainerSource{Image: image}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Ports: declared, Service: svc}}
	class := &v1.IngressClass{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IngressClass"}, ObjectMeta: meta.ObjectMeta{Name: o.Class},
		Spec: v1.IngressClassSpec{Public: o.Public, Controller: v1.IngressController{Driver: o.Driver, Options: o.Options, Namespace: "kevaso-system", Silo: name}}}
	return silo, class, nil
}

// ingressCmd runs kvoadm ingress install, as a cluster-admin of the current kvo context: one
// command for an ingress class served by a stock proxy (design §7.3).
func ingressCmd(ctx context.Context, args []string, stdout io.Writer) error {
	o, err := parseIngress(args)
	if err != nil {
		return err
	}
	silo, class, err := IngressObjects(o, kicdrivers.Builtin())
	if err != nil {
		return err
	}
	path, err := kvoconfig.Path()
	if err != nil {
		return err
	}
	cfg, err := kvoconfig.Load(path)
	if err != nil {
		return err
	}
	c, _, err := cfg.Client(path, o.Context)
	if err != nil {
		return err
	}
	nsObj := &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "kevaso-system"}}
	for _, obj := range []meta.Object{nsObj, silo, class} {
		if err := c.Create(ctx, obj); err != nil && !client.IsAlreadyExists(err) {
			return fmt.Errorf("%s %s: %w", obj.GetTypeMeta().Kind, obj.GetObjectMeta().Name, err)
		} else if client.IsAlreadyExists(err) {
			_, _ = fmt.Fprintf(stdout, "→ %s %s is already there: left as it is\n", obj.GetTypeMeta().Kind, obj.GetObjectMeta().Name)
			continue
		}
		_, _ = fmt.Fprintf(stdout, "→ %s %s\n", obj.GetTypeMeta().Kind, obj.GetObjectMeta().Name)
	}
	where := "on its host's " + o.HostPort + " IP"
	if o.LBClass != "" {
		where = "behind a " + o.LBClass + " address"
	}
	_, _ = fmt.Fprintf(stdout, "Ingress class %s: %s (%s) in silo kevaso-system/%s, %s. Kevaso writes its config from outside;\n",
		class.Name, o.Driver, silo.Spec.From(), silo.Name, where)
	_, _ = fmt.Fprintf(stdout, "see it with: kvo get ingressclass %s -o yaml\n", class.Name)
	return nil
}
