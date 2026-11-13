package kvo

import (
	"errors"
	"fmt"
	"os"

	v1 "kevaso.com/core/api/v1"
)

// Images in kvo (design §0.2): a VMImage is a bootable disk; a container silo's container.image
// is a registry reference, which describe flags as mutable unless it's pinned by digest, next to the digest the
// host actually pulled.

// describePull adds a silo's pull lines: whether its image is pinned, what was pulled, and which
// secret pulls it.
func describePull(kv func(int, string, any), o *v1.Silo) {
	if !v1.RegistryRuntime(o.Spec.Runtime) || o.Spec.From() == "" {
		return
	}
	if note := MutableNote(o.Spec.From()); note != "" {
		kv(0, "Pinned", note)
	}
	if im := o.Status.Image; im != nil && im.Digest != "" {
		kv(0, "Pulled", im.Digest)
	}
	if p := o.Spec.Pull(); p != nil && p.SecretRef != "" {
		kv(0, "Pull secret", p.SecretRef)
	}
}

// MutableNote says why a registry image isn't immutable ("" when it's pinned by digest, or
// Kevaso's own). Pure.
func MutableNote(image string) string {
	if v1.BuiltinImage(image) {
		return "no: " + image + " is " + v1.PullRef(image) + ", a tag (mutable): pin a digest for immutability"
	}
	r, err := v1.ParseImageRef(image)
	if err != nil || r.Pinned() {
		return ""
	}
	tag := r.Tag
	if tag == "" {
		tag = "latest"
	}
	return "no: tag " + tag + " is mutable (it can move to another image); pin it by digest, " + r.Registry + "/" + r.Repository + "@sha256:…"
}

// diskOf is a VMImage version's disk, shortened.
func diskOf(v v1.VMImageVersion) string {
	if v.Disk == nil {
		return "-"
	}
	sum := v.Disk.SHA256
	if len(sum) > 12 {
		sum = sum[:12] + "…"
	}
	return v.Disk.URL + " (sha256 " + sum + ")"
}

// registryServer: on `kvo create secret --type registry`, --server is the registry's host, not
// the API server's (that one comes from --context or $KVO_SERVER there). --registry says it
// either way.
func registryServer(cmd string, o *opts) {
	if cmd == "create" && o.secret.typ == v1.SecretRegistry && o.secret.server == "" && o.serverFlag != "" {
		o.secret.server, o.server = o.serverFlag, ""
		if v := os.Getenv("KVO_SERVER"); v != "" {
			o.server = v
		}
	}
}

// registrySecret fills in a registry secret's server and user, and its default-pull label.
func registrySecret(s *v1.Secret, so secretOpts) error {
	if so.typ != v1.SecretRegistry {
		if so.server != "" || so.username != "" || so.defaultPull {
			return errors.New("--registry, --username and --default-pull are for --type registry")
		}
		return nil
	}
	if so.server == "" || so.username == "" {
		return errors.New("a registry secret needs --server HOST (e.g. ghcr.io) and --username U; the password or token comes from --from-file FILE or - (stdin)")
	}
	if so.generate {
		return errors.New("a registry secret's value is the registry's password or token: --from-file, not --generate")
	}
	host, err := v1.RegistryHost(so.server)
	if err != nil {
		return fmt.Errorf("--server %q: %w", so.server, err)
	}
	s.Spec.Server, s.Spec.Username = host, so.username
	if so.defaultPull {
		if s.Labels == nil {
			s.Labels = map[string]string{}
		}
		s.Labels[v1.LabelDefaultPull] = "true"
	}
	return nil
}

// sourceLabel names what a silo starts from, as its block says: a container image, a VM image (a
// VMImage), or a VM disk stated inline.
func sourceLabel(spec v1.SiloSpec) string {
	switch {
	case spec.VM != nil && spec.VM.Disk != nil:
		return "VM disk"
	case spec.VM != nil:
		return "VM image"
	case spec.Container != nil:
		return "Container image"
	}
	return "Starts from"
}
