package v1

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Images by runtime family, and pulling from private registries (design §0.2, "Image is for
// machine disks only" and "Private registries").
//
// A runtime either boots a disk (cloud-hypervisor: spec.image is an Image name, resolved to one of
// its versions' disks, or a built-in OS image) or runs a registry image (docker, podman and both
// OpenShell drivers, which take an OCI reference: spec.image is that reference, used as it is).
// Kevaso adds no catalogue on top of registries.

// BuiltinImages are Kevaso's own OS image names, which every runtime knows (cloud-hypervisor
// fetches its cloud image; container runtimes run docker.io/library/ubuntu:24.04 as a machine to
// exec into; OpenShell uses its default image).
var BuiltinImages = []string{"ubuntu-24.04"}

// BuiltinRegistryRefs are what the built-in OS images are on runtimes that run registry images.
var BuiltinRegistryRefs = map[string]string{"ubuntu-24.04": "docker.io/library/ubuntu:24.04"}

// PullRef is the registry reference a registry runtime pulls for spec.image ("" for none).
func PullRef(image string) string {
	if r, ok := BuiltinRegistryRefs[image]; ok {
		return r
	}
	return image
}

// BuiltinImage reports whether name is one of Kevaso's own OS images.
func BuiltinImage(name string) bool { return slices.Contains(BuiltinImages, name) }

// DiskRuntime reports whether a runtime boots a disk image (an Image's version or a built-in OS
// image) rather than a registry image.
func DiskRuntime(rt string) bool { return rt == "cloud-hypervisor" }

// RegistryRuntime reports whether a runtime runs registry images (OCI references), so it can
// pull from a private registry.
func RegistryRuntime(rt string) bool {
	return rt == "docker" || rt == "podman" || rt == "openshell" || rt == "openshell-container"
}

// PullRuntime reports whether Kevaso pulls the runtime's images itself, so it can hand the engine
// a credential for one pull (docker, podman). OpenShell pulls through its own gateway, whose CLI
// takes no credential (research E037: `sandbox create --from IMAGE|rootfs.tar` only).
func PullRuntime(rt string) bool { return rt == "docker" || rt == "podman" }

// DockerHub is how Docker Hub is named in references, secrets and status.
const DockerHub = "docker.io"

// ImageRef is a registry reference, split.
type ImageRef struct {
	Registry   string // host[:port]; docker.io when the reference names none
	Repository string // e.g. acme/api, library/nginx
	Tag        string // "" when there's none (the engine uses latest) or the reference has a digest only
	Digest     string // sha256:HEX, "" when not pinned
}

// Pinned reports whether the reference names an immutable digest (a tag can move).
func (r ImageRef) Pinned() bool { return r.Digest != "" }

func (r ImageRef) String() string {
	s := r.Registry + "/" + r.Repository
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

var (
	repoPart  = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	tagRE     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	digestRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hostRE    = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*(?::[0-9]{1,5})?$`)
	hubAlias  = map[string]bool{"index.docker.io": true, "registry-1.docker.io": true, "registry.hub.docker.com": true}
	errNoHost = fmt.Errorf("want a registry host, e.g. ghcr.io or registry.example.com:5000")
)

// ParseImageRef reads a registry reference the way docker and podman do: [HOST[:PORT]/]PATH[:TAG][@DIGEST].
// The first path part is a host when it has a '.' or a ':' or is localhost; otherwise the
// reference is on Docker Hub (a single name gets library/).
func ParseImageRef(ref string) (ImageRef, error) {
	var r ImageRef
	if ref == "" || strings.ContainsAny(ref, " \t\r\n") {
		return r, fmt.Errorf("%q isn't a registry reference", ref)
	}
	rest := ref
	if i := strings.Index(rest, "@"); i >= 0 {
		r.Digest, rest = rest[i+1:], rest[:i]
		if !digestRE.MatchString(r.Digest) {
			return r, fmt.Errorf("%q: the digest must be sha256: and 64 lowercase hex digits", ref)
		}
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.Contains(rest[i:], "/") {
		r.Tag, rest = rest[i+1:], rest[:i]
		if !tagRE.MatchString(r.Tag) {
			return r, fmt.Errorf("%q: tag %q isn't valid", ref, r.Tag)
		}
	}
	parts := strings.Split(rest, "/")
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		r.Registry, parts = strings.ToLower(parts[0]), parts[1:]
		if !hostRE.MatchString(r.Registry) {
			return r, fmt.Errorf("%q: registry %q isn't a host[:port]", ref, r.Registry)
		}
	}
	if r.Registry == "" || hubAlias[r.Registry] {
		r.Registry = DockerHub
		if len(parts) == 1 {
			parts = append([]string{"library"}, parts...)
		}
	}
	for _, p := range parts {
		if !repoPart.MatchString(p) {
			return r, fmt.Errorf("%q isn't a registry reference (repository names are lowercase letters, digits and . _ -)", ref)
		}
	}
	r.Repository = strings.Join(parts, "/")
	return r, nil
}

// RegistryHost normalises a registry secret's server: a host[:port], with Docker Hub's aliases
// (and a scheme or path pasted from docker login) reduced to docker.io.
func RegistryHost(server string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(server))
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	if i := strings.Index(h, "/"); i >= 0 {
		h = h[:i]
	}
	if hubAlias[h] {
		h = DockerHub
	}
	if !hostRE.MatchString(h) {
		return "", errNoHost
	}
	return h, nil
}

// ImageProblem says what's wrong with a silo's spec.image for its runtime ("" when nothing is).
// isImage reports whether an Image of that name exists in the silo's namespace.
func ImageProblem(runtime, image string, isImage func(name string) bool) string {
	if image == "" || BuiltinImage(image) {
		return ""
	}
	name, _ := SplitImage(image)
	switch {
	case DiskRuntime(runtime):
		if strings.ContainsAny(image, "/@") {
			return fmt.Sprintf("%s boots a disk: spec.image is an Image name (kvo get images) or a built-in OS image (%s), not a registry reference (%s)",
				runtime, strings.Join(BuiltinImages, ", "), image)
		}
	case RegistryRuntime(runtime):
		if isImage != nil && isImage(name) {
			return fmt.Sprintf("%s is an Image, a disk image for cloud-hypervisor; a %s silo's image is a registry reference, used as it is (e.g. ghcr.io/acme/api@sha256:…)",
				name, runtime)
		}
		if _, err := ParseImageRef(image); err != nil {
			return fmt.Sprintf("a %s silo's image is a registry reference: %v", runtime, err)
		}
	}
	return ""
}

// ── registry secrets ─────────────────────────────────────────────────────────

// SecretRegistry is a registry credential: spec.server and spec.username, with the password or
// token as the sealed value. Write-only by default, and never delivered to a silo: only a host's
// agent gets it, for one pull of an image of a silo placed there (spec.imagePull).
const SecretRegistry = "registry"

// LabelDefaultPull, "true" on a registry secret, makes it the namespace's pull secret for its
// server: every silo there pulling from that host uses it unless it names another.
const LabelDefaultPull = "kevaso.com/default-pull"

// ImagePull says how a silo's image is pulled.
type ImagePull struct {
	// SecretRef is a registry Secret in the silo's namespace (naming it needs use on it). Default:
	// the namespace's default pull secret for the image's registry, if there is one.
	SecretRef string `json:"secretRef,omitempty"`
}

// DefaultPull reports whether a secret is its namespace's default pull secret for its server.
func (s *Secret) DefaultPull() bool {
	return s.Spec.Type == SecretRegistry && s.Labels[LabelDefaultPull] == "true"
}

// PullSecretFor picks the secret a silo pulls ref with: the one it names, or the namespace's
// default for ref's registry (the first by name, if several claim it). secrets are the
// namespace's. "" when there's none.
func PullSecretFor(pull *ImagePull, ref string, secrets []*Secret) string {
	if pull != nil && pull.SecretRef != "" {
		return pull.SecretRef
	}
	r, err := ParseImageRef(PullRef(ref))
	if err != nil {
		return ""
	}
	best := ""
	for _, s := range secrets {
		if h, err := RegistryHost(s.Spec.Server); err == nil && s.DefaultPull() && h == r.Registry && (best == "" || s.Name < best) {
			best = s.Name
		}
	}
	return best
}
