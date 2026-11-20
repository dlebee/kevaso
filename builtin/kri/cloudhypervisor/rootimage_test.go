package cloudhypervisor

import (
	"context"
	"strings"
	"testing"
)

// Deleting a silo on this host removes this host's state. A root image on a travelling
// class is the volume's: it stays, including while the silo runs on another host.
func TestDeleteLeavesATravellingRootImage(t *testing.T) {
	ctx := context.Background()
	dir := "/var/lib/kevaso/volumes/uid-web/disk.root"
	file := dir + "/" + RootImage
	h := newFakeHost()
	if err := h.WriteFile(file, []byte("disk-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newRuntime(t, h)
	sp := spec("web")
	sp.DiskHostPath = dir
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	if got := string(h.files[file]); got != "disk-bytes" {
		t.Fatalf("root image after delete: %q", got)
	}
	if _, err := h.ReadFile(NamesFor(sp.ID).Dir + "/silo.json"); err == nil {
		t.Fatal("this host's state was kept")
	}
	lv := NamesFor(sp.ID).LV
	for _, c := range h.commands() {
		if strings.Contains(c, "lvremove") && strings.Contains(c, lv) && !strings.Contains(c, lv+"-") {
			t.Fatalf("removed a root volume: %s", c)
		}
	}
}
