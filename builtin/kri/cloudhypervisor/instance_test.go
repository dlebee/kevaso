package cloudhypervisor

import (
	"context"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// The same guest host key on another host is a new instance, so cloud-init applies this host's
// address. A seed that reuses the key does not replace the guest's host keys. Without the mesh
// every host's gateway is 10.64.0.1; the host's own name still changes the id, and a reboot of
// the same host does not.
func TestInstanceIDFollowsTheHostAndAReusedKeyStays(t *testing.T) {
	id := kri.ID{Namespace: "dev", Name: "web", UID: "uid-web"}
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIReportedGuestKey000000000"
	if Gateway.String() != "10.64.0.1" {
		t.Fatalf("gateway %s, want the address every host has without the mesh", Gateway)
	}
	here := MetaData(id, pub, "hv1")
	there := MetaData(id, pub, "hv2")
	if here == there {
		t.Fatalf("the same guest key on another host kept the instance id:\n%s", here)
	}
	if MetaData(id, pub, "hv1") != here {
		t.Fatal("instance id is not stable for one host")
	}
	if !strings.HasPrefix(here, "instance-id: uid-web-") || !strings.Contains(here, "local-hostname: web\n") {
		t.Fatalf("meta-data:\n%s", here)
	}
	if MetaData(id, pub+"x", "hv1") == here {
		t.Fatal("a new guest key kept the instance id")
	}
	reused := UserData("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExecKey00000000000000000", "", pub)
	if !strings.Contains(reused, "ssh_deletekeys: false") || !strings.Contains(reused, "ssh_genkeytypes: []") || strings.Contains(reused, "ssh_keys:") {
		t.Fatalf("a reused key would replace the guest's host keys:\n%s", reused)
	}
	fresh := UserData("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExecKey00000000000000000", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n", pub)
	if !strings.Contains(fresh, "ssh_deletekeys: true") || !strings.Contains(fresh, "ssh_genkeytypes: []") || !strings.Contains(fresh, "ssh_keys:") {
		t.Fatalf("a new key was not installed:\n%s", fresh)
	}
}

// Two hosts that are not on the mesh share the gateway 10.64.0.1 and can be given the same
// guest key by a disk that travelled. The instance id each writes still differs, and writing
// it again on the same host does not.
func TestTwoHostsWithoutTheMeshGetDifferentInstanceIDs(t *testing.T) {
	ctx := context.Background()
	pub := testPub(t)
	dir := "/var/lib/kevaso/volumes/uid-web/disk.root"
	file := dir + "/" + RootImage
	makeHost := func(name string) (*Runtime, *fakeHost) {
		t.Helper()
		h := newFakeHost()
		if err := h.WriteFile(file, []byte("disk-bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		r := newRuntime(t, h)
		r.HostName = name
		sp := spec("web")
		sp.DiskHostPath = dir
		sp.GuestHostKey = pub
		if err := r.Create(ctx, sp); err != nil {
			t.Fatal(err)
		}
		return r, h
	}
	r1, h1 := makeHost("hv1")
	_, h2 := makeHost("hv2")
	meta := func(h *fakeHost) string {
		t.Helper()
		return string(h.files[NamesFor(id("web")).Dir+"/meta-data"])
	}
	here, there := meta(h1), meta(h2)
	if here == "" || here == there {
		t.Fatalf("two hosts without the mesh wrote one instance id:\n%s", here)
	}
	st, ok := r1.state(id("web"))
	if !ok || st.HostKey != pub {
		t.Fatalf("hv1 pinned %q (ok %v)", st.HostKey, ok)
	}
	if again := MetaData(id("web"), st.HostKey, "hv1"); again != here {
		t.Fatalf("the same host wrote a new instance id:\n%s\n%s", here, again)
	}
}
