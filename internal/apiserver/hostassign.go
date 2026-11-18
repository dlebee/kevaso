package apiserver

import (
	"context"
	"net/http"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// checkHostAssignment refuses an Ingress or a Certificate whose host the namespace may not use.
// An Ingress host must be assigned to its namespace on that class. A Certificate host must be
// assigned on some class, or be one of the namespace's own service names. An API server name is
// refused for both. Objects already stored are left out when routes are built, and are not signed.
func (s *Server) checkHostAssignment(ctx context.Context, t target, obj meta.Object) error {
	if t.status {
		return nil
	}
	switch o := obj.(type) {
	case *v1.Ingress:
		class, err := s.ingressClass(ctx, o.Spec.IngressClass)
		if err != nil {
			return err
		}
		names, err := s.apiNameList(ctx)
		if err != nil {
			return err
		}
		for _, h := range o.Spec.Hosts {
			if why := v1.IngressHostProblem(h, t.namespace, class, names); why != "" { // an ingress host must be assigned to its namespace
				return errf(http.StatusUnprocessableEntity, "Invalid", "Ingress %s: %s", o.Name, why)
			}
		}
	case *v1.Certificate:
		classes, err := s.ingressClasses(ctx)
		if err != nil {
			return err
		}
		suffix, err := s.clusterSuffix(ctx)
		if err != nil {
			return err
		}
		names, err := s.apiNameList(ctx)
		if err != nil {
			return err
		}
		for _, h := range o.Spec.Hosts {
			if why := v1.CertificateHostProblem(h, t.namespace, suffix, classes, names); why != "" { // a certificate host must be one this namespace may use
				return errf(http.StatusUnprocessableEntity, "Invalid", "Certificate %s: %s", o.Name, why)
			}
		}
	}
	return nil
}

func (s *Server) ingressClass(ctx context.Context, name string) (*v1.IngressClass, error) {
	classes, err := s.ingressClasses(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range classes {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, errf(http.StatusUnprocessableEntity, "Invalid", "ingress class %q doesn't exist", name)
}

func (s *Server) ingressClasses(ctx context.Context) ([]*v1.IngressClass, error) {
	return listAs[*v1.IngressClass](ctx, s.store, "IngressClass")
}

func (s *Server) clusterSuffix(ctx context.Context) (string, error) {
	hosts, err := listAs[*v1.Host](ctx, s.store, "Host")
	if err != nil {
		return "", err
	}
	return v1.ClusterSuffix(hosts), nil
}

func (s *Server) apiNameList(ctx context.Context) ([]string, error) {
	names := append([]string{}, s.apiNames...)
	hosts, err := listAs[*v1.Host](ctx, s.store, "Host")
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		names = append(names, v1.HostAPINames(h)...)
	}
	return names, nil
}
