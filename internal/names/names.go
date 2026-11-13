// Package names is who owns a name, and what a name answers (design §7.0). A name belongs to a
// service (a silo's spec.service, named service.name or after the silo; or a standalone Service)
// or to a host; nothing else has one. A service name is unique in its namespace: admission refuses
// a second holder (Holder says who has it). Pure.
package names

import (
	v1 "kevaso.com/core/api/v1"
)

// Reserved says whether a namespace name is one of the networks (mesh, internal, external), which
// names use as a label of their own (SERVICE.NAMESPACE.NETWORK.kevaso).
func Reserved(namespace string) bool {
	for _, n := range v1.Networks {
		if namespace == n {
			return true
		}
	}
	return false
}

// Owner is who holds the service name name in namespace: a silo (its own service) or a
// standalone Service; both nil if nobody does. Objects being deleted hold nothing. Should two
// hold it anyway (admission refuses that), the Service wins.
func Owner(namespace, name string, silos []*v1.Silo, svcs []*v1.Service) (*v1.Silo, *v1.Service) {
	for _, sv := range svcs {
		if sv.Namespace == namespace && sv.Name == name && sv.DeletionTimestamp == nil {
			return nil, sv
		}
	}
	for _, s := range silos {
		if s.Namespace == namespace && s.DeletionTimestamp == nil && v1.ServiceName(s) == name {
			return s, nil
		}
	}
	return nil, nil
}

// Holder says who other than self (KIND/NAME, e.g. silo/api-blue) holds the service name name in
// namespace: "silo/NAME" or "service/NAME", or "" when nobody else does.
func Holder(namespace, name, self string, silos []*v1.Silo, svcs []*v1.Service) string {
	for _, sv := range svcs {
		if sv.Namespace == namespace && sv.Name == name && sv.DeletionTimestamp == nil && "service/"+sv.Name != self {
			return "service/" + sv.Name
		}
	}
	for _, s := range silos {
		if s.Namespace == namespace && s.DeletionTimestamp == nil && v1.ServiceName(s) == name && "silo/"+s.Name != self {
			return "silo/" + s.Name
		}
	}
	return ""
}
