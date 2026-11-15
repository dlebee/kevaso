package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// K-111: a local volume's LV that is there with no state of this host's (silo.json lost) is an
// earlier copy's data, whose owner can't be proven from here, as its root volume would be: the
// silo isn't made over it, and nothing of it is removed, by a Create or by the clean-up of one
// that fails. The root on a mount class's folder or on an LV alike.
func TestACreateNeverRemovesALocalVolumeItDidNotMake(t *testing.T) {
	for _, rootOnMount := range []bool{false, true} {
		h := newFakeHost()
		r := newRuntime(t, h)
		sp := spec("db")
		sp.Volumes = []kri.Volume{{Name: "data", MountPath: "/data", SizeBytes: 1 << 30}}
		if rootOnMount {
			sp.DiskHostPath = "/var/lib/kevaso/volumes/uid-db/root"
		}
		dataLV := LayoutFor(NamesFor(sp.ID), sp.Volumes, sp.DiskHostPath).Disks[0].LV
		h.lvs[dataLV] = true // an earlier copy's data volume; its state is gone
		h.answer = func(cmd string) (string, error) {
			if strings.HasPrefix(cmd, "cloud-localds") {
				return "", errors.New("cut") // a step of the Create fails: its clean-up runs
			}
			if strings.HasPrefix(cmd, "systemctl is-active") {
				return "inactive", errors.New("exit 3")
			}
			f := strings.Fields(cmd)
			out, err := h.lv(f[0], f[1:])
			return string(out), err
		}
		err := r.Create(context.Background(), sp)
		if !h.lvs[dataLV] {
			t.Fatalf("root on a mount class %v: the data volume %s of an earlier copy was removed (Create: %v)", rootOnMount, dataLV, err)
		}
		if err == nil || !strings.Contains(err.Error(), dataLV) {
			t.Fatalf("root on a mount class %v: Create over an earlier copy's data volume: %v, want a refusal naming %s", rootOnMount, err, dataLV)
		}
		for _, c := range h.commands() {
			if strings.HasPrefix(c, "lvremove") {
				t.Fatalf("root on a mount class %v: %s", rootOnMount, c)
			}
		}
	}
}
