package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// A volume taken out of the spec keeps its LV (applyLayout never removes one). The copy still
// holds storage of its own, so a later delete of the copy would lvremove it.
func TestHasHostStorageSeesAVolumeLeftOutOfTheSpec(t *testing.T) {
	ctx := context.Background()
	dir := "/var/lib/kevaso/volumes/uid-web/disk.root"
	h := newFakeHost()
	if err := h.WriteFile(dir+"/"+RootImage, []byte("disk-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newRuntime(t, h)
	sp := spec("web")
	sp.DiskHostPath = dir
	sp.Volumes = []kri.Volume{{Name: "data", MountPath: "/data", SizeBytes: 1 << 30}}
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	lv := LayoutFor(n, sp.Volumes, sp.DiskHostPath).Disks[0].LV
	if h.lvs[n.LV] {
		t.Fatal("a travelling root was given a root LV")
	}
	if !h.lvs[lv] {
		t.Fatalf("volume LV %s was not made", lv)
	}
	if _, err := r.SetVolumes(ctx, sp.ID, nil); err != nil {
		t.Fatal(err)
	}
	if !h.lvs[lv] {
		t.Fatal("a volume taken out of the spec lost its LV")
	}
	own, err := r.HasHostStorage(ctx, sp.ID)
	if err != nil || !own {
		t.Fatalf("HasHostStorage %v %v, want the LV kept on this host", own, err)
	}
	if err := r.Delete(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.commands() {
		if strings.Contains(c, "lvremove") && strings.Contains(c, lv) {
			return
		}
	}
	t.Fatal("Delete did not lvremove the volume left out of the spec: the copy must be kept instead")
}

// A root LV is this host's disk, and it is not a volume LV. A handoff removes it. A volume
// LV, including one no longer in the spec, is.
func TestHasHostVolumeIgnoresTheRootDisk(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("web")
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	if !h.lvs[n.LV] {
		t.Fatal("the root LV was not made")
	}
	own, err := r.HasHostVolume(ctx, sp.ID)
	if err != nil || own {
		t.Fatalf("HasHostVolume %v %v, want the root LV left out", own, err)
	}
	stored, err := r.HasHostStorage(ctx, sp.ID)
	if err != nil || !stored {
		t.Fatalf("HasHostStorage %v %v, want the root LV", stored, err)
	}
	h.lvs[n.LV+"-data"] = true
	own, err = r.HasHostVolume(ctx, sp.ID)
	if err != nil || !own {
		t.Fatalf("HasHostVolume %v %v, want the volume LV", own, err)
	}
}

func TestHasHostStorageDoesNotTreatAFailedListAsNoDisk(t *testing.T) {
	h := newFakeHost()
	h.answer = func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "lvs ") {
			return "", errors.New("lvs failed")
		}
		return "", nil
	}
	r := newRuntime(t, h)
	own, err := r.HasHostStorage(context.Background(), id("web"))
	if err == nil || own {
		t.Fatalf("a failed lvs was taken as no disk: %v %v", own, err)
	}
}
