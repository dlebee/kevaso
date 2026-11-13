// Command hostdir is a test provider plugin for the end-to-end tests: one storage class, hostdir,
// of reach mount and topology global, whose volumes are folders under a root folder on the host
// (shared between hosts by whatever the test sets up, e.g. NFS). It stands in for a network
// file system (JuiceFS) where the tests need a real mount class without one:
//
//	hostdir serve --socket /run/kevaso-plugins/hostdir/plugin.sock --config FILE   controller side
//	hostdir node  --socket /run/kevaso-plugins/hostdir/node.sock  --config FILE   node side
//
// The controller side makes and deletes ROOT/volumes/UID/NAME; the node side bind-mounts that
// folder where kevasod asks. Both need the credential "token" (LoadCredential), which stands in
// for a storage key: the tests check it never reaches a silo. Not for production.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"kevaso.com/core/sdk/kplugin"
)

// Class is the one storage class.
const Class = "hostdir"

// Config is the plugin's settings.
type Config struct {
	Root string `json:"root"` // e.g. /srv/hostdir
}

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "serve" && os.Args[1] != "node") {
		fmt.Fprintln(os.Stderr, "usage: hostdir serve|node --socket PATH --config FILE")
		os.Exit(2)
	}
	side := os.Args[1]
	fs := flag.NewFlagSet(side, flag.ExitOnError)
	socket := fs.String("socket", "", "where kevasod finds this side")
	cfgFile := fs.String("config", "", "settings (JSON)")
	_ = fs.Parse(os.Args[2:])
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, side, *socket, *cfgFile)
	stop()
	if err != nil {
		log.Printf("hostdir: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, side, socket, cfgFile string) error {
	b, err := os.ReadFile(cfgFile)
	if err != nil {
		return err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	if !filepath.IsAbs(cfg.Root) {
		return fmt.Errorf("root %q: want an absolute folder", cfg.Root)
	}
	tok, err := os.ReadFile(filepath.Join(os.Getenv("CREDENTIALS_DIRECTORY"), "token"))
	if err != nil || len(strings.TrimSpace(string(tok))) == 0 {
		return fmt.Errorf("no credential token (LoadCredential=token:FILE): %v", err)
	}
	p := &Plugin{Root: cfg.Root}
	log.Printf("hostdir %s side on %s, root %s (token of %d bytes)", side, socket, cfg.Root, len(strings.TrimSpace(string(tok))))
	if side == "node" {
		return kplugin.Serve(ctx, socket, &Node{p})
	}
	return kplugin.Serve(ctx, socket, p)
}

// Plugin is the controller side.
type Plugin struct{ Root string }

// Info implements kplugin.Plugin.
func (p *Plugin) Info(context.Context) (kplugin.Info, error) {
	return kplugin.Info{Name: "hostdir", Version: "0.0.0-test", Protocol: kplugin.Protocol,
		Storage: []kplugin.Class{{Name: Class, Description: "a folder on a shared root (tests only)",
			Topology: kplugin.TopologyGlobal, Reach: kplugin.ReachMount}}}, nil
}

// handle is a volume's ID as a relative folder: UID/NAME, nothing that could leave the root.
var handle = regexp.MustCompile(`^[a-z0-9-]+/[a-z0-9.-]+$`)

func (p *Plugin) dir(h string) (string, error) {
	if !handle.MatchString(h) || strings.Contains(h, "..") {
		return "", fmt.Errorf("handle %q", h)
	}
	return filepath.Join(p.Root, "volumes", h), nil
}

// EnsureVolume implements kplugin.Volumes: the volume's folder, made once.
func (p *Plugin) EnsureVolume(_ context.Context, v kplugin.Volume) (kplugin.VolumeStatus, error) {
	d, err := p.dir(v.ID)
	if err != nil {
		return kplugin.VolumeStatus{}, err
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		return kplugin.VolumeStatus{}, err
	}
	// The unit's umask (0077) would leave it root's alone: a volume's root is open like a disk's.
	if err := os.Chmod(d, 0o755); err != nil {
		return kplugin.VolumeStatus{}, err
	}
	log.Printf("volume %s at %s", v.ID, d)
	return kplugin.VolumeStatus{Handle: v.ID, SizeBytes: v.SizeBytes}, nil
}

// AttachVolume implements kplugin.Volumes (never called for a mount class).
func (p *Plugin) AttachVolume(context.Context, kplugin.Attachment) (kplugin.AttachmentStatus, error) {
	return kplugin.AttachmentStatus{}, kplugin.ErrUnsupported
}

// DetachVolume implements kplugin.Volumes (never called for a mount class).
func (p *Plugin) DetachVolume(context.Context, kplugin.Attachment) error {
	return kplugin.ErrUnsupported
}

// DeleteVolume implements kplugin.Volumes.
func (p *Plugin) DeleteVolume(_ context.Context, ref kplugin.VolumeRef) error {
	d, err := p.dir(ref.Handle)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(d); err != nil {
		return err
	}
	_ = os.Remove(filepath.Dir(d)) // the silo's folder, once it holds no other volume
	log.Printf("volume %s deleted", ref.Handle)
	return nil
}

// Node is the node side: bind mounts.
type Node struct{ p *Plugin }

// Info implements kplugin.Plugin.
func (n *Node) Info(ctx context.Context) (kplugin.Info, error) { return n.p.Info(ctx) }

// MountVolume implements kplugin.Node.
func (n *Node) MountVolume(_ context.Context, m kplugin.NodeMount) error {
	src, err := n.p.dir(m.Handle)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(m.Path) {
		return fmt.Errorf("path %q", m.Path)
	}
	if mounted(m.Path) {
		return nil
	}
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("volume %s: %w", m.Handle, err)
	}
	if err := os.MkdirAll(m.Path, 0o755); err != nil {
		return err
	}
	if err := bind(src, m.Path); err != nil {
		return fmt.Errorf("bind %s at %s: %w", src, m.Path, err)
	}
	log.Printf("mounted %s at %s", m.Handle, m.Path)
	return nil
}

// UnmountVolume implements kplugin.Node. A folder still in use (virtiofsd, a container) is busy:
// the error says so and kevasod asks again.
func (n *Node) UnmountVolume(_ context.Context, m kplugin.NodeMount) error {
	if !mounted(m.Path) {
		return nil
	}
	if err := unbind(m.Path); err != nil && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("unmount %s: %w", m.Path, err)
	}
	log.Printf("unmounted %s", m.Path)
	return nil
}

// mounted reports whether something is mounted at path (the host's mount table).
func mounted(path string) bool {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fs := strings.Fields(sc.Text()); len(fs) > 4 && unescape(fs[4]) == filepath.Clean(path) {
			return true
		}
	}
	return false
}

// unescape undoes mountinfo's octal escapes (\040 for a space).
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var c int
			if _, err := fmt.Sscanf(s[i+1:i+4], "%o", &c); err == nil {
				b.WriteByte(byte(c))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
