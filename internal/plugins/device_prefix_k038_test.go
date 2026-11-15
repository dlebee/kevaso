package plugins

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// K-038 at use: a plugin registered from its socket may answer AttachVolume only with a device
// under the prefix its manifest declares, the manifest kvoadm plugin install stored on the host
// (Manifests/NAME/kevaso-plugin.json, root's); with none declared, every device answer is refused
// and the error says what to do. A clean path elsewhere (the host's own disk) is refused too.
func TestDevicesOutsideThePluginsPrefixAreRefused(t *testing.T) {
	dir, _ := os.MkdirTemp("", "kpd")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	etc := filepath.Join(dir, "etc")
	r := &Registry{Dir: filepath.Join(dir, "run"), Manifests: etc}
	d := &devicePlugin{Conn: kplugintest.New()}
	serveNamed(t, filepath.Join(dir, "run", "fake", "plugin.sock"), d)
	r.scan(context.Background(), r.Dir)
	p, _, ok := r.Storage(kplugintest.ClassBlock)
	if !ok {
		t.Fatal("never registered")
	}
	attach := func(dev string) error {
		d.device = dev
		_, err := p.Conn.AttachVolume(context.Background(), kplugin.Attachment{Class: kplugintest.ClassBlock, Handle: "vol-1"})
		return err
	}
	// No manifest stored: refused, saying how to declare one.
	if err := attach("/dev/disk/by-id/fake-vol-1"); !errors.Is(err, ErrBadAnswer) || !strings.Contains(err.Error(), "devicePrefixes") {
		t.Fatalf("no prefix declared: %v", err)
	}
	_ = os.MkdirAll(filepath.Join(etc, "fake"), 0o700)
	_ = os.WriteFile(filepath.Join(etc, "fake", kplugin.ManifestFile), []byte(`{"name":"fake","devicePrefixes":["/dev/disk/by-id/fake-"]}`), 0o600)
	if err := attach("/dev/disk/by-id/fake-vol-1"); err != nil {
		t.Fatalf("its own device: %v", err)
	}
	for _, dev := range []string{"/dev/sda1", "/dev/vdb", "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi0"} {
		if err := attach(dev); !errors.Is(err, ErrBadAnswer) || !strings.Contains(err.Error(), "plugin fake: AttachVolume vol-1") {
			t.Errorf("%s passed on: %v", dev, err)
		}
	}
}
