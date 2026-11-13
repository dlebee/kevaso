package v1

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
)

func TestParseImageRef(t *testing.T) {
	d := "sha256:" + strings.Repeat("a1", 32)
	for _, tc := range []struct {
		in   string
		want ImageRef
		err  bool
	}{
		{in: "nginx", want: ImageRef{Registry: "docker.io", Repository: "library/nginx"}},
		{in: "nginx:1.27", want: ImageRef{Registry: "docker.io", Repository: "library/nginx", Tag: "1.27"}},
		{in: "acme/api:v2", want: ImageRef{Registry: "docker.io", Repository: "acme/api", Tag: "v2"}},
		{in: "ghcr.io/acme/api@" + d, want: ImageRef{Registry: "ghcr.io", Repository: "acme/api", Digest: d}},
		{in: "ghcr.io/acme/api:v1@" + d, want: ImageRef{Registry: "ghcr.io", Repository: "acme/api", Tag: "v1", Digest: d}},
		{in: "registry.example.com:5000/team/app", want: ImageRef{Registry: "registry.example.com:5000", Repository: "team/app"}},
		{in: "localhost/kevaso-pause:abc", want: ImageRef{Registry: "localhost", Repository: "kevaso-pause", Tag: "abc"}},
		{in: "index.docker.io/library/ubuntu:24.04", want: ImageRef{Registry: "docker.io", Repository: "library/ubuntu", Tag: "24.04"}},
		{in: "", err: true},
		{in: "Nginx", err: true},
		{in: "ghcr.io/acme/api@sha256:short", err: true},
		{in: "two words", err: true},
		{in: "nginx:bad tag", err: true},
	} {
		got, err := ParseImageRef(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("%q: accepted as %+v", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q: %+v %v, want %+v", tc.in, got, err, tc.want)
		}
	}
	if r, _ := ParseImageRef("nginx:1.27"); r.Pinned() {
		t.Error("a tag is pinned")
	}
	if r, _ := ParseImageRef("nginx@" + d); !r.Pinned() {
		t.Error("a digest isn't pinned")
	}
}

func TestRegistryHost(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io": "ghcr.io", "GHCR.io": "ghcr.io", "https://index.docker.io/v1/": "docker.io",
		"registry-1.docker.io": "docker.io", "registry.example.com:5000": "registry.example.com:5000",
	} {
		if got, err := RegistryHost(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "not a host", "-x.io"} {
		if _, err := RegistryHost(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Admission's image rule per runtime family: a disk runtime takes an Image name or a built-in OS
// image; a registry runtime a registry reference, never an Image name.
func TestImageProblem(t *testing.T) {
	images := map[string]bool{"geth": true}
	isImage := func(n string) bool { return images[n] }
	for _, tc := range []struct{ runtime, image, want string }{
		{"cloud-hypervisor", "geth:v1", ""},
		{"cloud-hypervisor", "ubuntu-24.04", ""},
		{"cloud-hypervisor", "not-yet", ""}, // may come later: the controller waits (ImageMissing)
		{"cloud-hypervisor", "ghcr.io/acme/api:v1", "boots a disk: spec.image is an Image name"},
		{"cloud-hypervisor", "nginx@sha256:" + strings.Repeat("0", 64), "not a registry reference"},
		{"docker", "geth:v1", "geth is an Image, a disk image for cloud-hypervisor"},
		{"podman", "geth", "registry reference"},
		{"openshell-container", "geth", "geth is an Image"},
		{"docker", "nginx:1.27", ""},
		{"docker", "ubuntu-24.04", ""},
		{"docker", "", ""},
		{"podman", "Bad/Name", "a podman silo's image is a registry reference"},
		{"openshell", "ghcr.io/acme/agent:v1", ""},
	} {
		got := ImageProblem(tc.runtime, tc.image, isImage)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s on %s: %q, want %q", tc.image, tc.runtime, got, tc.want)
		}
	}
}

func TestRegistrySecretShape(t *testing.T) {
	yes := true
	s := &Secret{Spec: SecretSpec{Type: SecretRegistry, Server: "ghcr.io", Username: "bot"}}
	if s.Readable() {
		t.Error("a registry secret is readable by default (it's write-only by default)")
	}
	s.Spec.ValueReadable = &yes
	if !s.Readable() {
		t.Error("valueReadable: true doesn't make it readable")
	}
	for _, m := range Deliveries {
		if s.Allows(m) {
			t.Errorf("a registry secret allows delivery %s to a silo", m)
		}
	}
}

func TestPullSecretFor(t *testing.T) {
	sec := func(name, server string, def bool) *Secret {
		s := &Secret{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: SecretSpec{Type: SecretRegistry, Server: server}}
		if def {
			s.Labels = map[string]string{LabelDefaultPull: "true"}
		}
		return s
	}
	all := []*Secret{sec("ghcr-b", "ghcr.io", true), sec("ghcr-a", "ghcr.io", true), sec("hub", "docker.io", true), sec("other", "quay.io", false),
		{ObjectMeta: meta.ObjectMeta{Name: "opaque", Labels: map[string]string{LabelDefaultPull: "true"}}, Spec: SecretSpec{Server: "quay.io"}}}
	for _, tc := range []struct {
		pull       *ImagePull
		ref, wants string
	}{
		{&ImagePull{SecretRef: "mine"}, "ghcr.io/acme/api", "mine"}, // named: that one
		{nil, "ghcr.io/acme/api:v1", "ghcr-a"},                      // the default, first by name
		{nil, "nginx:1.27", "hub"},                                  // Docker Hub
		{nil, "ubuntu-24.04", "hub"},                                // the built-in is on Docker Hub
		{nil, "quay.io/x/y", ""},                                    // not a default; an opaque secret never is
		{&ImagePull{}, "registry.example.com/x", ""},
	} {
		if got := PullSecretFor(tc.pull, tc.ref, all); got != tc.wants {
			t.Errorf("%v %s: %q, want %q", tc.pull, tc.ref, got, tc.wants)
		}
	}
}
