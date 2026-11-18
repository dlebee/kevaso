package cloudhypervisor

import (
	"context"
	"encoding/binary"
	"errors"
	"path"
	"strings"
	"testing"
)

func qcow2(virtual uint64, mutate func([]byte)) []byte {
	b := make([]byte, 104)
	copy(b[0:4], "QFI\xfb")
	binary.BigEndian.PutUint32(b[4:], 3)
	binary.BigEndian.PutUint32(b[20:], 16)
	binary.BigEndian.PutUint64(b[24:], virtual)
	binary.BigEndian.PutUint32(b[100:], 104)
	if mutate != nil {
		mutate(b)
	}
	return b
}

func TestImageFormats(t *testing.T) {
	img := path.Join(ImagesDir, "sample.img")
	put := func(b []byte) {
		t.Helper()
		h := newFakeHost()
		h.files[img] = b
		format, _, err := inspectImage(h, img)
		if err != nil {
			t.Fatalf("accepted image refused: %v", err)
		}
		if format == "" {
			t.Fatal("no format")
		}
	}
	put([]byte("a raw disk that is not a known container"))
	put(qcow2(1<<20, nil))
	put(qcow2(1<<20, func(b []byte) { binary.BigEndian.PutUint64(b[72:], qcow2Dirty) }))
	put(qcow2(1<<20, func(b []byte) { binary.BigEndian.PutUint64(b[72:], qcow2Compression|qcow2ExtendedL2) }))

	v2 := make([]byte, 72)
	copy(v2[0:4], "QFI\xfb")
	binary.BigEndian.PutUint32(v2[4:], 2)
	binary.BigEndian.PutUint32(v2[20:], 16)
	binary.BigEndian.PutUint64(v2[24:], 1<<20)
	put(v2)

	refuse := func(b []byte, want string) {
		t.Helper()
		h := newFakeHost()
		h.files[img] = b
		format, _, err := inspectImage(h, img)
		if err == nil || !strings.Contains(err.Error(), want) || format != "" {
			t.Fatalf("bytes refused as %q: format %q err %v", want, format, err)
		}
	}
	refuse(qcow2(1<<20, func(b []byte) {
		binary.BigEndian.PutUint64(b[8:], 104)
		binary.BigEndian.PutUint32(b[16:], 4)
	}), "backing file")
	refuse(qcow2(1<<20, func(b []byte) { binary.BigEndian.PutUint32(b[16:], 8) }), "backing file")
	refuse(qcow2(1<<20, func(b []byte) { binary.BigEndian.PutUint64(b[72:], qcow2ExternalData) }), "external data file")
	refuse(qcow2(1<<20, func(b []byte) { binary.BigEndian.PutUint64(b[72:], qcow2Corrupt) }), "corrupt")
	refuse(qcow2(1<<20, func(b []byte) { binary.BigEndian.PutUint64(b[72:], 1<<10) }), "does not accept")
	refuse(qcow2(1<<20, func(b []byte) { binary.BigEndian.PutUint32(b[32:], 1) }), "encrypted")
	refuse(qcow2(1<<20, func(b []byte) { binary.BigEndian.PutUint32(b[32:], 2) }), "encrypted")
	refuse(qcow2(1<<20, func(b []byte) { binary.BigEndian.PutUint32(b[4:], 1) }), "version")
	refuse(qcow2(1<<20, func(b []byte) { binary.BigEndian.PutUint32(b[20:], 8) }), "cluster_bits")
	refuse(append(qcow2(1<<20, nil), ext(0x44415441, []byte("data.img"))...), "external data file")
	refuse(append(qcow2(1<<20, nil), ext(0xe2792aca, []byte("qcow2"))...), "backing file")
	refuse(append(qcow2(1<<20, nil), ext(0x0537be77, []byte("x"))...), "encrypted")
	refuse([]byte("QFI\xfb"), "truncated")
	refuse([]byte("KDMVrest"), "VMDK")
	refuse([]byte("# Disk DescriptorFile\nversion=1\n"), "VMDK")
	refuse([]byte("conectix"), "VHD")
	refuse([]byte("vhdxfile"), "VHDX")
	refuse([]byte("QED\x00"), "QED")
	vdi := make([]byte, 0x40+len("<<< Oracle VM VirtualBox Disk Image >>>"))
	copy(vdi[0x40:], "<<< Oracle VM VirtualBox Disk Image >>>")
	refuse(vdi, "VDI")
	refuse([]byte("WithoutFreeSpace"), "parallels")

	// A feature-name extension is the header describing itself, and is kept.
	put(append(qcow2(1<<20, nil), ext(0x6803f857, []byte("dirty"))...))
}

func ext(typ uint32, data []byte) []byte {
	b := make([]byte, 8+len(data))
	binary.BigEndian.PutUint32(b[0:], typ)
	binary.BigEndian.PutUint32(b[4:], uint32(len(data)))
	copy(b[8:], data)
	if extra := len(b) % 8; extra != 0 {
		b = append(b, make([]byte, 8-extra)...)
	}
	return b
}

func TestABackingFileImageIsNotConverted(t *testing.T) {
	h := newFakeHost()
	r := newRuntime(t, h)
	img := path.Join(ImagesDir, "ubuntu-24.04-aarch64.img")
	h.files[img] = qcow2(1<<20, func(b []byte) {
		binary.BigEndian.PutUint64(b[8:], 104)
		binary.BigEndian.PutUint32(b[16:], 11)
	})
	err := r.Create(context.Background(), spec("web"))
	if err == nil || !strings.Contains(err.Error(), "backing file") {
		t.Fatalf("create: %v", err)
	}
	if indexOf(h.commands(), "qemu-img") >= 0 {
		t.Fatalf("qemu-img ran for a refused image: %v", h.commands())
	}
	if indexOf(h.commands(), "lvcreate") >= 0 {
		t.Fatalf("an LV was made for a refused image: %v", h.commands())
	}
}

func TestAnExternalDataFileIsRefused(t *testing.T) {
	h := newFakeHost()
	img := path.Join(ImagesDir, "sample.img")
	h.files[img] = qcow2(1<<20, func(b []byte) { binary.BigEndian.PutUint64(b[72:], qcow2ExternalData) })
	_, _, err := inspectImage(h, img)
	if err == nil || !strings.Contains(err.Error(), "external data file") {
		t.Fatalf("%v", err)
	}
}

func TestAnEncryptedImageIsRefused(t *testing.T) {
	h := newFakeHost()
	img := path.Join(ImagesDir, "sample.img")
	h.files[img] = qcow2(1<<20, func(b []byte) { binary.BigEndian.PutUint32(b[32:], 2) })
	_, _, err := inspectImage(h, img)
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("%v", err)
	}
}

func TestVMDKIsRefused(t *testing.T) {
	h := newFakeHost()
	img := path.Join(ImagesDir, "sample.img")
	h.files[img] = []byte("KDMVrest-of-a-descriptor")
	_, _, err := inspectImage(h, img)
	if err == nil || !strings.Contains(err.Error(), "VMDK") {
		t.Fatalf("%v", err)
	}
}

func TestAnImageLargerThanTheDiskIsRefused(t *testing.T) {
	h := newFakeHost()
	r := newRuntime(t, h)
	img := path.Join(ImagesDir, "ubuntu-24.04-aarch64.img")
	h.files[img] = qcow2((20<<30)+1, nil)
	err := r.Create(context.Background(), spec("web"))
	if err == nil || !strings.Contains(err.Error(), "does not fit") {
		t.Fatalf("create: %v", err)
	}
	if indexOf(h.commands(), "qemu-img") >= 0 {
		t.Fatalf("qemu-img ran: %v", h.commands())
	}
}

func TestConvertPinsTheFormatAndSeesOnlyTheImage(t *testing.T) {
	h := newFakeHost()
	r := newRuntime(t, h)
	img := path.Join(ImagesDir, "ubuntu-24.04-aarch64.img")
	h.files[img] = qcow2(1<<20, nil)
	if err := r.Create(context.Background(), spec("web")); err != nil {
		t.Fatal(err)
	}
	i := indexOf(h.commands(), "qemu-img convert -f qcow2 ")
	if i < 0 {
		t.Fatalf("no pinned convert: %v", h.commands())
	}
	c := h.commands()[i]
	for _, want := range []string{
		"User=" + ImgUser,
		"BindReadOnlyPaths=" + img,
		"BindsTo=kevasod.service",
		"PrivateDevices=yes",
		"DevicePolicy=closed",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("convert lacks %s: %s", want, c)
		}
	}
	if strings.Contains(c, "--slice=system.slice") {
		t.Errorf("convert is in the pool scope: %s", c)
	}
	if !strings.Contains(c, "DeviceAllow=/dev/"+VG+"/") {
		t.Errorf("the target device is not the one device allowed: %s", c)
	}
	chmod, back := indexOf(h.commands(), "chmod 0640 "+img), indexOf(h.commands(), "chmod 0600 "+img)
	if chmod < 0 || back < chmod || i < chmod || i > back {
		t.Fatalf("the image is not group-readable only for the convert: %v", h.commands())
	}
}

func TestRootDiskIsNotWrittenBesideTheVolume(t *testing.T) {
	h := newFakeHost()
	h.answer = func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "mountpoint ") {
			return "not a mount", errors.New("exit 1")
		}
		if strings.HasPrefix(cmd, "systemctl is-active") {
			return "inactive", errors.New("exit 3")
		}
		return "", nil
	}
	r := newRuntime(t, h)
	sp := spec("web")
	sp.DiskHostPath = "/var/lib/kevaso/volumes/uid/disk.root"
	err := r.Create(context.Background(), sp)
	if err == nil || !strings.Contains(err.Error(), "not a mount") {
		t.Fatalf("create: %v", err)
	}
	if indexOf(h.commands(), "qemu-img") >= 0 {
		t.Fatalf("the disk was written beside the volume: %v", h.commands())
	}
}
