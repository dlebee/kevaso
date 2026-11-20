package cloudhypervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// rootFolder is a disk.root the tests can fill. quota means creating any new file in
// dir fails while root.raw is there: the folder's quota is the disk's size, and the
// real truncate reports that as text (exit 1), not as a Go errno. failConvert makes
// qemu-img convert fail, the way a killed convert does.
type rootFolder struct {
	quota       bool
	failConvert bool
	fullMessage string
}

func (f *rootFolder) script(h *fakeHost, dir, file string) {
	if f.fullMessage == "" {
		f.fullMessage = "Disk quota exceeded"
	}
	h.answer = func(cmd string) (string, error) {
		switch {
		case strings.HasPrefix(cmd, "test -e "):
			p := strings.TrimPrefix(cmd, "test -e ")
			if _, ok := h.files[p]; !ok {
				return "", errors.New("exit 1")
			}
			return "", nil
		case strings.HasPrefix(cmd, "systemctl is-active"):
			return "inactive", errors.New("exit 3")
		case strings.HasPrefix(cmd, "systemctl show"):
			return "MainPID=0\n", nil
		case strings.HasPrefix(cmd, "rm "):
			for _, a := range strings.Fields(cmd)[1:] {
				if strings.HasPrefix(a, "-") {
					continue
				}
				delete(h.files, a)
				delete(h.meta, a)
			}
			return "", nil
		case strings.HasPrefix(cmd, "truncate "):
			fields := strings.Fields(cmd)
			return f.admit(h, dir, file, fields[len(fields)-1])
		case strings.HasPrefix(cmd, "qemu-img convert"):
			fields := strings.Fields(cmd)
			dst := fields[len(fields)-1]
			if _, ok := h.files[dst]; !ok {
				if msg, err := f.admit(h, dir, file, dst); err != nil {
					return msg, err
				}
			}
			if f.failConvert {
				return "", errors.New("signal: killed")
			}
			return "", nil
		}
		return "", nil
	}
}

// admit creates a new file, or refuses it when the folder is already full.
func (f *rootFolder) admit(h *fakeHost, dir, file, target string) (string, error) {
	if _, ok := h.files[target]; ok {
		return "", nil
	}
	if f.quota {
		if _, filled := h.files[file]; filled && filepath.Dir(target) == dir {
			return "truncate: cannot open '" + target + "' for writing: " + f.fullMessage, errors.New("exit 1")
		}
	}
	h.files[target] = []byte("fresh-image")
	h.meta[target] = h.freshFile()
	return "", nil
}

func newTravellingRoot(t *testing.T, h *fakeHost, dir, file string) (*Runtime, kri.Spec) {
	t.Helper()
	if err := h.WriteFile(file, []byte("old-disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newRuntime(t, h)
	sp := spec("web")
	sp.DiskHostPath = dir
	if err := r.Create(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	return r, sp
}

func cmdExact(cmds []string, want string) int {
	for i, c := range cmds {
		if c == want || hostCmd(c) == want {
			return i
		}
	}
	return -1
}

func cmdSuffix(cmds []string, prefix, suffix string) int {
	for i, c := range cmds {
		for _, line := range []string{c, hostCmd(c)} {
			if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, suffix) {
				return i
			}
		}
	}
	return -1
}

func imageIno(h *fakeHost, file string) (uint64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m, ok := h.meta[file]
	return m.ino, ok
}

// A travelling root whose folder cannot hold a second full image still resets: the new
// image is tried beside the old one, and only the quota failure removes the old one.
// The file that lands has a new inode, so a kept copy sees the reset as a new image.
func TestResetOnAFullRootDiskFolder(t *testing.T) {
	ctx := context.Background()
	dir := "/var/lib/kevaso/volumes/uid-web/disk.root"
	file := dir + "/" + RootImage
	h := newFakeHost()
	folder := &rootFolder{quota: true}
	folder.script(h, dir, file)
	r, sp := newTravellingRoot(t, h, dir, file)
	before, ok := imageIno(h, file)
	if !ok || before == 0 {
		t.Fatal("the old image has no inode")
	}
	st, ok := r.state(sp.ID)
	if !ok || st.KeyImage == "" {
		t.Fatal("create did not record the image it boots")
	}
	oldKey := st.KeyImage
	at := len(h.commands())
	if err := r.Reset(ctx, sp); err != nil {
		t.Fatal(err)
	}
	cmds := h.commands()[at:]
	tr := cmdSuffix(cmds, "truncate ", " "+file+".new")
	rm := cmdExact(cmds, "rm -f "+file)
	if tr < 0 || rm < 0 || tr > rm {
		t.Fatalf("the new image was not tried beside the old one before it was removed: %v", cmds)
	}
	for _, c := range cmds {
		if strings.Contains(c, "rm ") && strings.Contains(c, dir) && c != "rm -f "+file && c != "rm -f "+file+".new" {
			t.Fatalf("reset removed more than the root image: %s", c)
		}
	}
	got, err := h.ReadFile(file)
	if err != nil || string(got) != "fresh-image" {
		t.Fatalf("root image %q %v", got, err)
	}
	if _, err := h.ReadFile(file + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the image beside the disk was left behind: %v", err)
	}
	after, ok := imageIno(h, file)
	if !ok || after == 0 || after == before {
		t.Fatalf("reset kept inode %d (%d)", after, before)
	}
	st, ok = r.state(sp.ID)
	if !ok || st.KeyImage == "" || st.KeyImage == oldKey {
		t.Fatalf("key image %q, was %q", st.KeyImage, oldKey)
	}
	h.mu.Lock()
	m := h.meta[file]
	h.mu.Unlock()
	if st.KeyImage != fmt.Sprintf("%d:%d", m.ino, m.btime) {
		t.Fatalf("key image %q is not the new file %d:%d", st.KeyImage, m.ino, m.btime)
	}
}

// A convert that fails for some other reason leaves the old image, and the next
// start boots it. The folder being full is the only reason the old image is given up.
func TestATravellingRootIsKeptWhenTheNewImageFails(t *testing.T) {
	ctx := context.Background()
	dir := "/var/lib/kevaso/volumes/uid-web/disk.root"
	file := dir + "/" + RootImage
	h := newFakeHost()
	folder := &rootFolder{failConvert: true}
	folder.script(h, dir, file)
	r, sp := newTravellingRoot(t, h, dir, file)
	n := NamesFor(sp.ID)
	err := r.Reset(ctx, sp)
	if err == nil || !errors.Is(err, errRootKept) {
		t.Fatalf("reset: %v", err)
	}
	got, rerr := h.ReadFile(file)
	if rerr != nil || string(got) != "old-disk" {
		t.Fatalf("root image %q %v", got, rerr)
	}
	if b, _ := h.ReadFile(n.Dir + "/silo.json"); strings.Contains(string(b), `"remake"`) {
		t.Fatalf("a reset that removed nothing left its mark: %s", b)
	}
	if _, err := h.ReadFile(file + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a half-written image was left beside the disk: %v", err)
	}
	before := len(h.commands())
	if err := r.Start(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	cmds := h.commands()[before:]
	if indexOf(cmds, "qemu-img convert") >= 0 || cmdExact(cmds, "rm -f "+file) >= 0 {
		t.Fatalf("the next start made the disk afresh: %v", cmds)
	}
	if cmdExact(cmds, "systemctl start "+n.Unit) < 0 {
		t.Fatalf("the old disk was not booted: %v", cmds)
	}
}

// The old image was removed because the folder was full, and the new one then failed.
// Nothing bootable is left, the failure is reported, and a retry builds the image.
func TestAResetThatLosesTheOldImageDoesNotBootAHalfOne(t *testing.T) {
	ctx := context.Background()
	dir := "/var/lib/kevaso/volumes/uid-web/disk.root"
	file := dir + "/" + RootImage
	h := newFakeHost()
	folder := &rootFolder{quota: true, failConvert: true}
	folder.script(h, dir, file)
	r, sp := newTravellingRoot(t, h, dir, file)
	n := NamesFor(sp.ID)
	st, ok := r.state(sp.ID)
	if !ok || st.KeyImage == "" {
		t.Fatal("create did not record the image it boots")
	}
	oldKey := st.KeyImage
	err := r.Reset(ctx, sp)
	if err == nil || errors.Is(err, errRootKept) || !strings.Contains(err.Error(), "nothing boots until a retry finishes it") {
		t.Fatalf("reset: %v", err)
	}
	if _, err := h.ReadFile(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a half-written root image was left to boot: %v", err)
	}
	if _, err := h.ReadFile(file + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a half-written image was left beside the disk: %v", err)
	}
	if b, _ := h.ReadFile(n.Dir + "/silo.json"); !strings.Contains(string(b), `"remake"`) {
		t.Fatalf("the failed reset dropped its mark: %s", b)
	}
	st, _ = r.state(sp.ID)
	if st.KeyImage != oldKey {
		t.Fatalf("a failed reset renamed the image it boots: %q", st.KeyImage)
	}
	before := len(h.commands())
	err = r.Start(ctx, sp.ID)
	if err == nil || !strings.Contains(err.Error(), "half-made disk") {
		t.Fatalf("start: %v", err)
	}
	if cmdExact(h.commands()[before:], "systemctl start "+n.Unit) >= 0 {
		t.Fatalf("the VM booted with no finished disk: %v", h.commands()[before:])
	}
	if _, err := h.ReadFile(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("start left a root image: %v", err)
	}
	folder.failConvert = false
	if err := r.Reset(ctx, sp); err != nil {
		t.Fatal(err)
	}
	got, rerr := h.ReadFile(file)
	if rerr != nil || string(got) != "fresh-image" {
		t.Fatalf("retry root image %q %v", got, rerr)
	}
	if _, err := h.ReadFile(file + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the retry left the image beside the disk: %v", err)
	}
	st, ok = r.state(sp.ID)
	if !ok || st.KeyImage == "" || st.KeyImage == oldKey || st.Remake != nil {
		t.Fatalf("retry key image %q (was %q), remake set", st.KeyImage, oldKey)
	}
}

// An LVM root is still replaced as a logical volume. The file-image path is not used.
func TestAnLVMResetStillReplacesTheRootVolume(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("web")
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	before := len(h.commands())
	if err := r.Reset(ctx, sp); err != nil {
		t.Fatal(err)
	}
	cmds := h.commands()[before:]
	rm, create := indexOf(cmds, "lvremove"), indexOf(cmds, "lvcreate")
	if rm < 0 || create < rm {
		t.Fatalf("LVM reset: %v", cmds)
	}
	if cmdSuffix(cmds, "truncate ", "") >= 0 || strings.Contains(strings.Join(cmds, "\n"), "root.raw") {
		t.Fatalf("an LVM reset rewrote a root image file: %v", cmds)
	}
	if !h.lvs[n.LV] {
		t.Fatal("the root LV is gone")
	}
}

func TestSpaceExhaustedIsQuotaOrNoSpace(t *testing.T) {
	for _, err := range []error{
		fmt.Errorf("open: %w", syscall.EDQUOT),
		fmt.Errorf("open: %w", syscall.ENOSPC),
		errors.New("exit status 1: Disk quota exceeded"),
		errors.New("exit status 1: No space left on device"),
	} {
		if !spaceExhausted(err) {
			t.Fatalf("%v is not a full folder", err)
		}
	}
	if spaceExhausted(errors.New("signal: killed")) || spaceExhausted(nil) {
		t.Fatal("a killed convert is a full folder")
	}
}
