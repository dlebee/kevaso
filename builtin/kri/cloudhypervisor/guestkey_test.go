package cloudhypervisor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testPub(t *testing.T) string {
	t.Helper()
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

// A disk that is already there keeps the guest host key the silo reports. A new disk gets a
// key of its own, installed into the guest. A host-local disk's key is not replaced.
func TestATravellingDiskTrustsTheReportedGuestKey(t *testing.T) {
	ctx := context.Background()
	pub := testPub(t)
	dir := "/var/lib/kevaso/volumes/uid-web/disk.root"
	file := dir + "/" + RootImage

	present := newFakeHost()
	if err := present.WriteFile(file, []byte("disk-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	rp := newRuntime(t, present)
	sp := spec("web")
	sp.DiskHostPath = dir
	sp.GuestHostKey = pub
	if err := rp.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	st, ok := rp.state(sp.ID)
	if !ok || st.HostKey != pub {
		t.Fatalf("pinned %q, want the reported key", st.HostKey)
	}
	ud := string(present.files[NamesFor(sp.ID).Dir+"/user-data"])
	if !strings.Contains(ud, "ssh_deletekeys: false") || !strings.Contains(ud, "ssh_genkeytypes: []") || strings.Contains(ud, "ssh_keys:") {
		t.Fatalf("the seed would replace the guest's host key:\n%s", ud)
	}
	if got := string(present.files[file]); got != "disk-bytes" {
		t.Fatalf("root image %q", got)
	}
	if key, ok := rp.GuestHostKey(sp.ID); !ok || key != pub {
		t.Fatalf("reported %q %v", key, ok)
	}

	missing := newFakeHost()
	missing.answer = func(cmd string) (string, error) {
		switch {
		case cmd == "test -e "+file:
			return "", errors.New("exit 1")
		case strings.HasPrefix(cmd, "systemctl is-active"):
			return "inactive", errors.New("exit 3")
		}
		return "", nil
	}
	rm := newRuntime(t, missing)
	sm := spec("web")
	sm.DiskHostPath = dir
	sm.GuestHostKey = pub
	if err := rm.Create(ctx, sm); err != nil {
		t.Fatal(err)
	}
	st, ok = rm.state(sm.ID)
	if !ok || st.HostKey == "" || st.HostKey == pub {
		t.Fatalf("a new disk pinned %q", st.HostKey)
	}
	ud = string(missing.files[NamesFor(sm.ID).Dir+"/user-data"])
	if !strings.Contains(ud, "ssh_deletekeys: true") || !strings.Contains(ud, "ssh_keys:") {
		t.Fatalf("a new disk was not given a host key:\n%s", ud)
	}

	local := newFakeHost()
	rl := newRuntime(t, local)
	sl := spec("web")
	if err := rl.Create(ctx, sl); err != nil {
		t.Fatal(err)
	}
	before, _ := rl.state(sl.ID)
	if err := rl.SetGuestHostKey(ctx, sl.ID, pub); err != nil {
		t.Fatal(err)
	}
	after, _ := rl.state(sl.ID)
	if after.HostKey != before.HostKey {
		t.Fatalf("a host-local disk's key changed from %q to %q", before.HostKey, after.HostKey)
	}

	again := testPub(t)
	beforeCmds := len(present.commands())
	if err := rp.SetGuestHostKey(ctx, sp.ID, again); err != nil {
		t.Fatal(err)
	}
	st, _ = rp.state(sp.ID)
	if st.HostKey != again {
		t.Fatalf("adopted %q, want %q", st.HostKey, again)
	}
	ud = string(present.files[NamesFor(sp.ID).Dir+"/user-data"])
	if !strings.Contains(ud, "ssh_deletekeys: false") || !strings.Contains(ud, "ssh_genkeytypes: []") || strings.Contains(ud, "ssh_keys:") {
		t.Fatalf("adopting a key replaced the guest's:\n%s", ud)
	}
	if got := string(present.files[file]); got != "disk-bytes" {
		t.Fatalf("adopting a key rewrote the root image: %q", got)
	}
	for _, c := range present.commands()[beforeCmds:] {
		if strings.Contains(c, "lvremove") || strings.Contains(c, "qemu-img") {
			t.Fatalf("adopting a key touched a disk: %s", c)
		}
	}
}
