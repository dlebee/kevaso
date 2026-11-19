package cloudhypervisor

import (
	"strings"
	"testing"
)

func TestGuestFormatsOnlyAnEmptyDisk(t *testing.T) {
	n := NamesFor(id("web"))
	sc := GuestMountScript(LayoutFor(n, vmVolumes(), ""))
	if !strings.Contains(sc, "-s PTTYPE") {
		t.Fatalf("the guest formats a disk without asking whether it has a partition table:\n%s", sc)
	}
	if !strings.Contains(sc, `if [ "$rc" -eq 2 ] && [ -z "$p" ]; then mkfs.ext4 -q -m 0 "$d"`) {
		t.Fatalf("mkfs is not limited to an empty probe:\n%s", sc)
	}
}
