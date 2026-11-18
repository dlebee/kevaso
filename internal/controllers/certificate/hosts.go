package certificate

import (
	"context"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
)

// unallowedHost is why this certificate's hosts may not be signed. An error reading the store is
// returned as an error (nothing is issued). A host that is an API server name, or that the
// namespace may not use, is a reason string.
func (c *Controller) unallowedHost(ctx context.Context, cert *v1.Certificate) (string, error) {
	classes, suffix, names, err := c.hostScope(ctx)
	if err != nil {
		return "", err
	}
	for _, h := range cert.Spec.Hosts {
		if why := v1.CertificateHostProblem(h, cert.Namespace, suffix, classes, names); why != "" {
			return why, nil
		}
	}
	return "", nil
}

func (c *Controller) hostScope(ctx context.Context) ([]*v1.IngressClass, string, []string, error) {
	names := append([]string{}, c.APINames...)
	if c.Store != nil {
		classes, err := listStored[*v1.IngressClass](ctx, c.Store, "IngressClass")
		if err != nil {
			return nil, "", nil, err
		}
		hosts, err := listStored[*v1.Host](ctx, c.Store, "Host")
		if err != nil {
			return nil, "", nil, err
		}
		for _, h := range hosts {
			names = append(names, v1.HostAPINames(h)...)
		}
		return classes, v1.ClusterSuffix(hosts), names, nil
	}
	var classes []*v1.IngressClass
	if c.Classes != nil {
		for _, o := range c.Classes.List() {
			if cl, ok := o.(*v1.IngressClass); ok {
				classes = append(classes, cl)
			}
		}
	}
	var hosts []*v1.Host
	if c.Hosts != nil {
		for _, o := range c.Hosts.List() {
			if h, ok := o.(*v1.Host); ok {
				hosts = append(hosts, h)
				names = append(names, v1.HostAPINames(h)...)
			}
		}
	}
	return classes, v1.ClusterSuffix(hosts), names, nil
}

func listStored[T any](ctx context.Context, st store.Store, kind string) ([]T, error) {
	objs, _, err := st.List(ctx, store.Selector{Kind: kind})
	if err != nil {
		return nil, err
	}
	var out []T
	for _, o := range objs {
		obj, _, err := v1.Decode(o.Data)
		if err != nil {
			return nil, err
		}
		typed, ok := obj.(T)
		if !ok {
			continue
		}
		out = append(out, typed)
	}
	return out, nil
}
