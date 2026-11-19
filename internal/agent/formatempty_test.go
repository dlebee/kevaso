package agent

import (
	"context"
	"strings"
	"testing"
)

func TestAPartitionTableIsNotFormatted(t *testing.T) {
	const dev, dir = "/dev/disk/by-id/scsi-0Linode_Volume_v", "/var/lib/kevaso/volumes/u/data"
	h := &fakeHost{codes: map[string]int{"mountpoint": 1, "blkid": 0}, out: map[string]string{"blkid": "PTTYPE=dos\n"}}
	err := (&Agent{Host: h}).mount(context.Background(), "", dev, dir)
	if err == nil || !strings.Contains(err.Error(), "not formatting") || h.did("mkfs") || h.did("mount ") {
		t.Fatalf("a partition table was formatted or mounted: %v %v", err, h.ran)
	}
	// Exit 2 with a partition table is not an empty disk either.
	h = &fakeHost{codes: map[string]int{"mountpoint": 1, "blkid": 2}, out: map[string]string{"blkid": "PTTYPE=dos\n"}}
	err = (&Agent{Host: h}).mount(context.Background(), "", dev, dir)
	if err == nil || !strings.Contains(err.Error(), "not formatting") || h.did("mkfs") {
		t.Fatalf("exit 2 with a partition table: %v %v", err, h.ran)
	}
	// A filesystem is kept even when a partition table is named beside it.
	h = &fakeHost{codes: map[string]int{"mountpoint": 1, "blkid": 0}, out: map[string]string{"blkid": "TYPE=ext4\nPTTYPE=dos\n"}}
	if err := (&Agent{Host: h}).mount(context.Background(), "", dev, dir); err != nil || h.did("mkfs") {
		t.Fatalf("an ext4 disk with a partition table: %v %v", err, h.ran)
	}
}

func TestProviderVolumesAreMountedWithoutSpecialFiles(t *testing.T) {
	const dev, dir = "/dev/disk/by-id/scsi-0Linode_Volume_v", "/var/lib/kevaso/volumes/u/data"
	h := &fakeHost{codes: map[string]int{"mountpoint": 1, "blkid": 2}, out: map[string]string{"blkid": ""}}
	if err := (&Agent{Host: h}).mount(context.Background(), "", dev, dir); err != nil {
		t.Fatal(err)
	}
	if !h.did("mount -o noatime,nosuid,nodev " + dev + " " + dir) {
		t.Fatalf("mount: %v", h.ran)
	}
}
