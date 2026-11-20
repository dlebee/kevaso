package cloudhypervisor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	installed := st.HostKey
	if err := rm.SetGuestHostKey(ctx, sm.ID, pub); err != nil {
		t.Fatal(err)
	}
	st, _ = rm.state(sm.ID)
	if st.HostKey != installed {
		t.Fatalf("adopted %q over the key installed on a new image (%q)", st.HostKey, installed)
	}
	ud = string(missing.files[NamesFor(sm.ID).Dir+"/user-data"])
	if !strings.Contains(ud, "ssh_deletekeys: true") || !strings.Contains(ud, "ssh_keys:") {
		t.Fatalf("adopting rewrote the seed of a new image:\n%s", ud)
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

// A reset installs a new host key onto a new image. The key the silo reported before that
// is not adopted over it.
func TestAResetDoesNotAdoptTheKeyFromBefore(t *testing.T) {
	ctx := context.Background()
	pub := testPub(t)
	dir := "/var/lib/kevaso/volumes/uid-web/disk.root"
	file := dir + "/" + RootImage
	h := newFakeHost()
	if err := h.WriteFile(file, []byte("disk-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newRuntime(t, h)
	sp := spec("web")
	sp.DiskHostPath = dir
	sp.GuestHostKey = pub
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	if err := r.Reset(ctx, sp); err != nil {
		t.Fatal(err)
	}
	st, ok := r.state(sp.ID)
	if !ok || st.HostKey == "" || st.HostKey == pub || st.KeyFromDisk {
		t.Fatalf("reset pinned %q (from disk %v)", st.HostKey, st.KeyFromDisk)
	}
	installed := st.HostKey
	if err := r.SetGuestHostKey(ctx, sp.ID, pub); err != nil {
		t.Fatal(err)
	}
	st, _ = r.state(sp.ID)
	if st.HostKey != installed {
		t.Fatalf("adopted %q over the key a reset installed (%q)", st.HostKey, installed)
	}
}

// A kept copy that first made its image adopts a key once a reset on another host has
// replaced that image. Until then the key it installed stays.
func TestAResetElsewhereIsAdopted(t *testing.T) {
	ctx := context.Background()
	reported := testPub(t)
	dir := "/var/lib/kevaso/volumes/uid-web/disk.root"
	file := dir + "/" + RootImage
	h := newFakeHost()
	h.answer = func(cmd string) (string, error) {
		switch {
		case cmd == "test -e "+file:
			if _, ok := h.files[file]; !ok {
				return "", errors.New("exit 1")
			}
			return "", nil
		case strings.HasPrefix(cmd, "systemctl is-active"):
			return "inactive", errors.New("exit 3")
		}
		return "", nil
	}
	r := newRuntime(t, h)
	sp := spec("web")
	sp.DiskHostPath = dir
	sp.GuestHostKey = reported
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	st, ok := r.state(sp.ID)
	if !ok || st.HostKey == "" || st.HostKey == reported || st.KeyFromDisk || st.KeyImage == "" {
		t.Fatalf("create pinned %q (from disk %v, image %q)", st.HostKey, st.KeyFromDisk, st.KeyImage)
	}
	installed := st.HostKey
	if err := r.SetGuestHostKey(ctx, sp.ID, reported); err != nil {
		t.Fatal(err)
	}
	st, _ = r.state(sp.ID)
	if st.HostKey != installed {
		t.Fatalf("adopted %q while this copy still boots the image it made", st.HostKey)
	}
	// A write through the open file (the guest using its disk) keeps the inode.
	// A reset elsewhere renames a new file over root.raw, which does not.
	h.mu.Lock()
	h.files[file] = []byte("guest-wrote")
	h.mu.Unlock()
	if err := r.SetGuestHostKey(ctx, sp.ID, reported); err != nil {
		t.Fatal(err)
	}
	st, _ = r.state(sp.ID)
	if st.HostKey != installed {
		t.Fatalf("adopted %q after a write that left the same file in place", st.HostKey)
	}
	if got := string(h.files[file]); got != "guest-wrote" {
		t.Fatalf("root image %q", got)
	}
	if err := h.WriteFile(file, []byte("disk-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := len(h.commands())
	if err := r.SetGuestHostKey(ctx, sp.ID, reported); err != nil {
		t.Fatal(err)
	}
	st, _ = r.state(sp.ID)
	if st.HostKey != reported {
		t.Fatalf("pinned %q, want the key a reset elsewhere installed", st.HostKey)
	}
	ud := string(h.files[NamesFor(sp.ID).Dir+"/user-data"])
	if !strings.Contains(ud, "ssh_deletekeys: false") || strings.Contains(ud, "ssh_keys:") {
		t.Fatalf("adopting rewrote the guest's host key:\n%s", ud)
	}
	if got := string(h.files[file]); got != "disk-bytes" {
		t.Fatalf("adopting a key rewrote the root image: %q", got)
	}
	for _, c := range h.commands()[before:] {
		if strings.Contains(c, "lvremove") || strings.Contains(c, "qemu-img") {
			t.Fatalf("adopting a key touched a disk: %s", c)
		}
	}
}

// The root disk's folder is quota'd to the disk's size. Once root.raw is there,
// creating any other file in that folder fails. Making the VM still succeeds,
// and the key installed onto the image this copy just made is kept.
func TestCreateOnAFullRootDiskFolder(t *testing.T) {
	ctx := context.Background()
	reported := testPub(t)
	dir := "/var/lib/kevaso/volumes/uid-web/disk.root"
	file := dir + "/" + RootImage
	h := newFakeHost()
	h.answer = func(cmd string) (string, error) {
		switch {
		case cmd == "test -e "+file:
			if _, ok := h.files[file]; !ok {
				return "", errors.New("exit 1")
			}
			return "", nil
		case cmd == "mv -f "+file+".new "+file:
			// The image lands by rename and fills the folder. A new file beside it cannot.
			if _, ok := h.files[file]; !ok {
				h.files[file] = []byte("image")
			}
			return "", nil
		case strings.HasPrefix(cmd, "systemctl is-active"):
			return "inactive", errors.New("exit 3")
		}
		return "", nil
	}
	r := newRuntime(t, &quotaHost{fakeHost: h, dir: dir})
	sp := spec("web")
	sp.DiskHostPath = dir
	sp.GuestHostKey = reported
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	for p := range h.files {
		if filepath.Dir(p) == dir && filepath.Base(p) != RootImage {
			t.Fatalf("wrote %s into a root disk folder that root.raw already fills", p)
		}
	}
	if _, ok := h.files[file]; !ok {
		t.Fatal("root image was not put in place")
	}
	st, ok := r.state(sp.ID)
	if !ok || st.HostKey == "" || st.HostKey == reported || st.KeyImage == "" {
		t.Fatalf("create pinned %q (image %q)", st.HostKey, st.KeyImage)
	}
	installed := st.HostKey
	if err := r.SetGuestHostKey(ctx, sp.ID, reported); err != nil {
		t.Fatal(err)
	}
	st, _ = r.state(sp.ID)
	if st.HostKey != installed {
		t.Fatalf("adopted %q over the key installed on the image this copy just made", st.HostKey)
	}
}

// quotaHost is a disk.root whose quota is the disk's size: once root.raw is
// there, creating a file in the folder fails with EDQUOT.
type quotaHost struct {
	*fakeHost
	dir string
}

func (q *quotaHost) WriteFile(p string, data []byte, mode os.FileMode) error {
	if filepath.Dir(p) == q.dir {
		if _, err := q.ReadFile(p); errors.Is(err, os.ErrNotExist) {
			if _, rerr := q.ReadFile(filepath.Join(q.dir, RootImage)); rerr == nil {
				return &os.PathError{Op: "open", Path: p, Err: syscall.EDQUOT}
			}
		}
	}
	return q.fakeHost.WriteFile(p, data, mode)
}

func TestImageIdentityIsTheInodeAndItsBirth(t *testing.T) {
	same, err := imageIdentity([]string{"42", "0", "100"})
	wrote, err2 := imageIdentity([]string{"42", "0", "200"})
	if err != nil || err2 != nil || same != wrote || same != "42" {
		t.Fatalf("a write renamed the image: %q %q %v %v", same, wrote, err, err2)
	}
	born, err := imageIdentity([]string{"42", "7", "100"})
	reborn, err2 := imageIdentity([]string{"42", "8", "100"})
	if err != nil || err2 != nil || born == reborn || born != "42:7" {
		t.Fatalf("birth: %q %q %v %v", born, reborn, err, err2)
	}
	replaced, err := imageIdentity([]string{"43", "0", "100"})
	if err != nil || replaced == same {
		t.Fatalf("a replaced file kept its name: %q %v", replaced, err)
	}
}
