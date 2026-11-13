package apiserver

import (
	"context"
	"fmt"
	"net/http"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
)

// Images and pulls (design §0.2): a silo's image fits its runtime's family (an Image or a built-in
// OS image for cloud-hypervisor, a registry reference for the rest), and a pull secret is named
// only by someone with use on it, only where Kevaso pulls the image itself, and only for the
// image's own registry. The credential reaches a host's agent alone (brokerPull), for silos placed
// on that host.

// checkImages is the guard for images and pull secrets on silos and sets, and for default pull
// secrets on Secrets.
func (s *Server) checkImages(ctx context.Context, t target, obj meta.Object) error {
	if t.status {
		return nil
	}
	switch o := obj.(type) {
	case *v1.Silo:
		var had *v1.ImagePull
		if prev, ok := s.stored(ctx, t).(*v1.Silo); ok {
			had = prev.Spec.ImagePull
		}
		return s.checkSiloImage(ctx, t.namespace, "Silo "+o.Name, o.Spec, had)
	case *v1.SiloSet:
		var had *v1.ImagePull
		if prev, ok := s.stored(ctx, t).(*v1.SiloSet); ok {
			had = prev.Spec.Template.ImagePull
		}
		return s.checkSiloImage(ctx, t.namespace, "SiloSet "+o.Name, o.InstanceSpec(), had)
	case *v1.Secret:
		return s.checkDefaultPull(ctx, t, o)
	}
	return nil
}

// stored is the object as it's stored now (nil on create).
func (s *Server) stored(ctx context.Context, t target) meta.Object {
	if t.name == "" {
		return nil
	}
	cur, err := s.store.Get(ctx, t.key())
	if err != nil {
		return nil
	}
	o, _, err := v1.Decode(cur.Data)
	if err != nil {
		return nil
	}
	return o
}

func (s *Server) checkSiloImage(ctx context.Context, ns, what string, spec v1.SiloSpec, had *v1.ImagePull) error {
	isImage := func(name string) bool {
		_, err := s.store.Get(ctx, store.Key{Kind: "Image", Namespace: ns, Name: name})
		return err == nil
	}
	if p := v1.ImageProblem(spec.Runtime, spec.Image, isImage); p != "" {
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s: %s", what, p)
	}
	pull := spec.ImagePull
	if pull == nil || pull.SecretRef == "" {
		return nil
	}
	rt := spec.Runtime
	switch {
	case v1.DiskRuntime(rt):
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s: imagePull is for registry images; %s boots an Image's disk", what, rt)
	case !v1.PullRuntime(rt):
		return errf(http.StatusUnprocessableEntity, "Invalid",
			"%s: imagePull isn't available on %s: OpenShell pulls images through its own gateway, whose CLI takes no registry credential, so Kevaso can't hand it one for a pull without leaving it in OpenShell's config (use a public image, or docker or podman)", what, rt)
	}
	sec := s.secretNamed(ctx, ns, pull.SecretRef)
	if sec == nil {
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s: imagePull.secretRef: no secret %q in namespace %s (kvo create secret %s --type registry …)", what, pull.SecretRef, ns, pull.SecretRef)
	}
	if sec.Spec.Type != v1.SecretRegistry {
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s: imagePull.secretRef: secret %s is type %s, not registry", what, sec.Name, dash(sec.Spec.Type, v1.SecretOpaque))
	}
	ref, err := v1.ParseImageRef(v1.PullRef(spec.Image))
	if err != nil {
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s: imagePull: %v", what, err)
	}
	if h, _ := v1.RegistryHost(sec.Spec.Server); h != ref.Registry {
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s: imagePull.secretRef: secret %s is for %s; the image is on %s", what, sec.Name, h, ref.Registry)
	}
	if had != nil && had.SecretRef == pull.SecretRef {
		return nil // named already: the writer changes something else
	}
	if err := s.canUseSecrets(ctx, ns, map[string][]string{pull.SecretRef: nil}); err != nil {
		return fmt.Errorf("%s: pulling with secret %s: %w", what, pull.SecretRef, err)
	}
	return nil
}

// checkDefaultPull: making a registry secret the namespace's default for its server hands it to
// every silo there, so it needs use on it (like naming it), and one server has one default.
func (s *Server) checkDefaultPull(ctx context.Context, t target, sec *v1.Secret) error {
	if sec.Spec.Type != v1.SecretRegistry {
		return nil
	}
	host, err := v1.RegistryHost(sec.Spec.Server)
	if err != nil {
		return errf(http.StatusUnprocessableEntity, "Invalid", "Secret %s: spec.server %q: %v", sec.Name, sec.Spec.Server, err)
	}
	if !sec.DefaultPull() {
		return nil
	}
	if prev, ok := s.stored(ctx, t).(*v1.Secret); !ok || !prev.DefaultPull() {
		if err := s.canUseSecrets(ctx, t.namespace, map[string][]string{sec.Name: nil}); err != nil {
			return fmt.Errorf("making %s the namespace's default pull secret for %s: %w", sec.Name, host, err)
		}
	}
	objs, _, err := s.store.List(ctx, store.Selector{Kind: "Secret", Namespace: t.namespace})
	if err != nil {
		return err
	}
	for _, o := range objs {
		other, _, err := v1.Decode(o.Data)
		if err != nil {
			continue
		}
		o2 := other.(*v1.Secret)
		if h, _ := v1.RegistryHost(o2.Spec.Server); o2.Name != sec.Name && o2.DefaultPull() && h == host {
			return errf(http.StatusConflict, "Conflict", "Secret %s: %s is already the default pull secret for %s in namespace %s (remove its %s label first)",
				sec.Name, o2.Name, host, t.namespace, v1.LabelDefaultPull)
		}
	}
	return nil
}

// brokerPull answers a host's agent asking for the credential to pull one of its silos' images
// (OpPullCredential, never forwarded from a silo). op.Name is the image; it must be the silo's.
// No credential applies: an empty answer.
func (s *Server) brokerPull(ctx context.Context, call *brokerCall, op client.BrokerRequest) (client.BrokerResponse, string, bool) {
	silo := call.silo
	if op.Name == "" || (op.Name != silo.Spec.Image && (silo.Status.Image == nil || op.Name != silo.Status.Image.Ref)) {
		return client.BrokerResponse{Error: "not this silo's image"}, "pull of " + op.Name + ": not the silo's image", false
	}
	if !v1.PullRuntime(silo.Spec.Runtime) {
		return client.BrokerResponse{}, "no pull credential: " + silo.Spec.Runtime + " pulls by itself", true
	}
	var all []*v1.Secret
	if silo.Spec.ImagePull == nil || silo.Spec.ImagePull.SecretRef == "" {
		objs, _, err := s.store.List(ctx, store.Selector{Kind: "Secret", Namespace: silo.Namespace})
		if err != nil {
			return client.BrokerResponse{Error: "try again"}, err.Error(), false
		}
		for _, o := range objs {
			if x, _, err := v1.Decode(o.Data); err == nil {
				all = append(all, x.(*v1.Secret))
			}
		}
	}
	name := v1.PullSecretFor(silo.Spec.ImagePull, op.Name, all)
	if name == "" {
		return client.BrokerResponse{}, "no pull secret for " + op.Name, true
	}
	refuse := func(why string) (client.BrokerResponse, string, bool) {
		return client.BrokerResponse{Error: "pull secret " + name + ": " + why}, why, false
	}
	ref, err := v1.ParseImageRef(v1.PullRef(op.Name))
	if err != nil {
		return refuse(err.Error())
	}
	sec := s.secretNamed(ctx, silo.Namespace, name)
	if sec == nil || sec.Spec.Type != v1.SecretRegistry {
		return refuse("no registry secret " + name + " in namespace " + silo.Namespace)
	}
	host, _ := v1.RegistryHost(sec.Spec.Server)
	if host != ref.Registry {
		return refuse("it's for " + host + "; the image is on " + ref.Registry)
	}
	if s.vault == nil {
		return refuse("this server has no KMS")
	}
	value, ver, err := s.vault.Value(ctx, sec)
	if err != nil {
		return refuse(err.Error())
	}
	return client.BrokerResponse{Registry: &client.RegistryCredential{Secret: name, Server: host, Username: sec.Spec.Username, Password: value}, Version: ver},
		fmt.Sprintf("pull credential %s (version %d) for %s", name, ver, op.Name), true
}

func dash(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// pullOf is a silo's pull secret, for privileges.
func pullOf(p *v1.ImagePull) string {
	if p == nil || p.SecretRef == "" {
		return ""
	}
	return "|pull:" + p.SecretRef
}
