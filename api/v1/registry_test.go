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

// Admission for what a silo starts from (design §0.2): cloud-hypervisor takes vm:, the registry
// runtimes container:, and each refusal names the right block.
func TestSourceProblems(t *testing.T) {
	images := map[string]bool{"geth": true}
	isVMImage := func(n string) bool { return images[n] }
	sum := strings.Repeat("ab", 32)
	disk := &VMDisk{URL: "https://x/geth.img", SHA256: sum}
	ctr := func(image string) *ContainerSource { return &ContainerSource{Image: image} }
	type tc struct {
		name, runtime string
		container     *ContainerSource
		vm            *VMSource
		want          string // "" = accepted; else a part of the one problem
	}
	var cases []tc
	// Each runtime with each block.
	cases = append(cases,
		tc{"ch container", "cloud-hypervisor", ctr("nginx:1.27"), nil, "cloud-hypervisor runs a virtual machine: say what it boots in vm:"},
		tc{"ch vm.image", "cloud-hypervisor", nil, &VMSource{Image: "geth:v1"}, ""},
		tc{"ch vm.disk", "cloud-hypervisor", nil, &VMSource{Disk: disk}, ""},
		tc{"ch none", "cloud-hypervisor", nil, nil, ""},
	)
	for _, rt := range []string{"docker", "podman", "openshell", "openshell-container"} {
		cases = append(cases,
			tc{rt + " container", rt, ctr("ghcr.io/acme/api:v1"), nil, ""},
			tc{rt + " vm.image", rt, nil, &VMSource{Image: "geth:v1"}, rt + " runs an OCI image: say it in container:"},
			tc{rt + " vm.disk", rt, nil, &VMSource{Disk: disk}, rt + " runs an OCI image: say it in container:"},
			tc{rt + " none", rt, nil, nil, ""},
		)
	}
	cases = append(cases,
		// vm: exactly one of image and disk
		tc{"vm both", "cloud-hypervisor", nil, &VMSource{Image: "geth", Disk: disk}, "not both"},
		tc{"vm neither", "cloud-hypervisor", nil, &VMSource{}, "vm: needs image"},
		// vm.disk: https and a sha256
		tc{"vm.disk http", "cloud-hypervisor", nil, &VMSource{Disk: &VMDisk{URL: "http://x/geth.img", SHA256: sum}}, "vm.disk needs an https:// url"},
		tc{"vm.disk bad sha256", "cloud-hypervisor", nil, &VMSource{Disk: &VMDisk{URL: "https://x/geth.img", SHA256: "abc"}}, "64 hex digits"},
		tc{"vm.disk no sha256", "cloud-hypervisor", nil, &VMSource{Disk: &VMDisk{URL: "https://x/geth.img"}}, "64 hex digits"},
		// vm.image: a VMImage name, not a registry reference
		tc{"vm.image registry ref", "cloud-hypervisor", nil, &VMSource{Image: "ghcr.io/acme/api:v1"}, "not a registry reference (ghcr.io/acme/api:v1)"},
		tc{"vm.image digest", "cloud-hypervisor", nil, &VMSource{Image: "nginx@sha256:" + strings.Repeat("0", 64)}, "not a registry reference"},
		tc{"vm.image not yet there", "cloud-hypervisor", nil, &VMSource{Image: "not-yet"}, ""}, // may come later: the controller waits
		// container.image: a registry reference, never a VMImage's name
		tc{"container names a VMImage", "docker", ctr("geth:v1"), nil, "geth is a VMImage, a disk for cloud-hypervisor"},
		tc{"container names a VMImage, bare", "podman", ctr("geth"), nil, "geth is a VMImage"},
		tc{"container empty", "docker", ctr(""), nil, "container.image is required"},
		tc{"container bad ref", "podman", ctr("Bad/Name"), nil, "container.image is a registry reference"},
		// the built-in OS image, in both blocks
		tc{"built-in container", "docker", ctr("ubuntu-24.04"), nil, ""},
		tc{"built-in vm", "cloud-hypervisor", nil, &VMSource{Image: "ubuntu-24.04"}, ""},
	)
	for _, c := range cases {
		got := SourceProblems(SiloSpec{Runtime: c.runtime, Container: c.container, VM: c.vm}, isVMImage)
		switch {
		case c.want == "" && len(got) != 0:
			t.Errorf("%s: refused: %q", c.name, got)
		case c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want)):
			t.Errorf("%s: %q, want one problem with %q", c.name, got, c.want)
		}
	}
	// isVMImage nil: don't look, so a container image is never taken for a VMImage.
	if got := SourceProblems(SiloSpec{Runtime: "docker", Container: ctr("geth:v1")}, nil); len(got) != 0 {
		t.Errorf("nil lookup: %q", got)
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
