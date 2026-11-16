package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// A device under /dev/disk/by-id/ is not enough to mount: the host's own disks are named
// there too. When this host has the volume's plugin, only a device under that plugin's
// declared prefix is formatted or mounted.
func TestMountRefusesAHostDiskNamedUnderByID(t *testing.T) {
	dir, err := os.MkdirTemp("", "kvol")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	etc := filepath.Join(dir, "etc")
	if err := os.MkdirAll(filepath.Join(etc, "fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `{"name":"fake","devicePrefixes":["/dev/disk/by-id/fake-"]}`
	if err := os.WriteFile(filepath.Join(etc, "fake", kplugin.ManifestFile), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "run", "fake", kplugin.ControllerSocket)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveErr <- kplugin.Serve(ctx, sock, kplugintest.New())
	}()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		select {
		case err := <-serveErr:
			t.Fatalf("plugin socket: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("plugin socket never appeared at %s", sock)
		}
		time.Sleep(10 * time.Millisecond)
	}
	reg := &plugins.Registry{Dir: filepath.Join(dir, "run"), Manifests: etc, Every: time.Hour}
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	go reg.Run(runCtx)
	deadline = time.Now().Add(2 * time.Second)
	for {
		if _, _, ok := reg.Storage(kplugintest.ClassBlock); ok || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, _, ok := reg.Storage(kplugintest.ClassBlock); !ok {
		t.Fatal("plugin never registered")
	}

	const dirPath = "/var/lib/kevaso/volumes/u/data"
	hostDisk := "/dev/disk/by-id/nvme-eui.0123456789abcdef"
	h := &fakeHost{codes: map[string]int{"mountpoint": 1, "blkid": 2}}
	a := &Agent{Host: h, Nodes: reg}
	if err := a.mount(context.Background(), kplugintest.ClassBlock, hostDisk, dirPath); err == nil || err == errNoDevice {
		t.Fatalf("host disk: %v", err)
	}
	for _, cmd := range []string{"test", "blkid", "mkfs", "mount "} {
		if h.did(cmd) {
			t.Errorf("host disk ran %s: %v", cmd, h.ran)
		}
	}

	own := "/dev/disk/by-id/fake-vol-1"
	h = &fakeHost{codes: map[string]int{"mountpoint": 1, "blkid": 2}}
	a.Host = h
	if err := a.mount(context.Background(), kplugintest.ClassBlock, own, dirPath); err != nil {
		t.Fatalf("the plugin's device: %v", err)
	}
	if !h.did("mkfs") {
		t.Fatalf("the plugin's device was not formatted: %v", h.ran)
	}
}
