package kplugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// ManifestFile is what a plugin's package calls its manifest.
const ManifestFile = "kevaso-plugin.json"

// Manifest is what a plugin's package says each of its sides needs from a host (kevaso-plugin.json).
// `kvoadm plugin install --manifest FILE` reads it, shows it to the operator, and writes a unit
// that grants exactly that: by default (nothing asked) a side is a dynamic user with no
// capabilities, no devices, a read-only system and a mount namespace of its own.
type Manifest struct {
	Name       string `json:"name"`
	Controller Needs  `json:"controller,omitempty"`
	Node       Needs  `json:"node,omitempty"`
	// DevicePrefixes are where the devices of its attached volumes are: every device it answers
	// AttachVolume with starts with one (DevicePrefixProblem says which prefixes may be declared).
	// kvoadm stores the manifest on the host and kevasod refuses any other device answer; a plugin
	// with no prefix declared can't attach volumes (K-038).
	DevicePrefixes []string `json:"devicePrefixes,omitempty"`
}

// Needs is what one side needs beyond the default.
type Needs struct {
	// Root: it runs as root (uid 0) instead of a dynamic user, e.g. to mount file systems.
	Root bool `json:"root,omitempty"`
	// Capabilities it keeps (everything else is dropped), e.g. CAP_SYS_ADMIN to mount.
	Capabilities []string `json:"capabilities,omitempty"`
	// Devices it opens (read-write), e.g. /dev/fuse; no other device is reachable.
	Devices []string `json:"devices,omitempty"`
	// HostMounts: the mounts it makes must be the host's (kevasod, container runtimes and virtiofsd
	// see them), so it gets no mount namespace of its own, and with it none of the hardening that
	// needs one (read-only system, private /tmp): the price of mounting for others. Needs Root.
	HostMounts bool `json:"hostMounts,omitempty"`
	// WritePaths are folders it writes (its state, caches); the rest of the system is read-only to
	// it. Not with HostMounts (nothing is read-only then). Only the plugin's own folders may be
	// named (WritePathProblem), and the operator grants them like any other privilege.
	WritePaths []string `json:"writePaths,omitempty"`
	// Socket is the side's socket in Dir/NAME (default plugin.sock for the controller side,
	// node.sock for the node side): kevasod only looks there.
	Socket string `json:"socket,omitempty"`
}

// Privileged reports whether the side asks for more than the default, i.e. what the operator must
// grant: a folder to write is one of those (it is handed to the plugin's user).
func (n Needs) Privileged() bool {
	return n.Root || len(n.Capabilities) > 0 || len(n.Devices) > 0 || n.HostMounts || len(n.WritePaths) > 0
}

// Mounts reports whether the side may mount file systems (CAP_SYS_ADMIN).
func (n Needs) Mounts() bool {
	for _, c := range n.Capabilities {
		if c == "CAP_SYS_ADMIN" {
			return true
		}
	}
	return false
}

// Summary says in a few lines what the side gets, for the operator.
func (n Needs) Summary() []string {
	var out []string
	if n.Root {
		out = append(out, "runs as root (uid 0)")
	} else {
		out = append(out, "runs as its own dynamic user")
	}
	if len(n.Capabilities) > 0 {
		out = append(out, "capabilities: "+strings.Join(n.Capabilities, " ")+" (all others dropped)")
	} else {
		out = append(out, "no capabilities")
	}
	if len(n.Devices) > 0 {
		out = append(out, "devices: "+strings.Join(n.Devices, " ")+" (no others)")
	}
	if n.HostMounts {
		out = append(out, "the host's mount namespace: its mounts are the host's, and the host's files aren't read-only to it")
	} else if len(n.WritePaths) > 0 {
		for _, p := range n.WritePaths {
			out = append(out, "writes "+p+" (made for it if missing)")
		}
		out = append(out, "the rest is read-only")
	}
	return out
}

var (
	capName    = regexp.MustCompile(`^CAP_[A-Z_]+$`)
	deviceName = regexp.MustCompile(`^/dev/[a-z0-9/_-]+$`)
)

// WriteRoots are the folders plugin data lives in. A plugin NAME may write exactly
// ROOT/kevaso-plugin-NAME or ROOT/kevaso-provider-NAME for the first three, and /srv/NAME: never a
// folder deeper (the plugin owns the one above it and could make it a symlink before its next
// start), never a system folder or Kevaso's own (/var/lib/kevaso, /etc/kevaso), never another
// plugin's.
var WriteRoots = []string{"/var/lib", "/var/cache", "/var/log", "/srv"}

// WritePathProblem says why plugin name may not be given folder p to write, or nil.
func WritePathProblem(name, p string) error {
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsAny(p, " \t\n\r\"'\\%$;") {
		return fmt.Errorf("write path %q: a clean absolute folder", p)
	}
	dir, base := path.Split(p)
	if dir != "" {
		dir = strings.TrimSuffix(dir, "/")
	}
	for _, root := range WriteRoots {
		if dir != root {
			continue
		}
		mine := []string{"kevaso-plugin-" + name, "kevaso-provider-" + name}
		if root == "/srv" {
			mine = []string{name}
		}
		for _, m := range mine {
			if base == m {
				return nil
			}
		}
	}
	return fmt.Errorf("write path %q: plugin %s may write only its own folder: %s", p, name, strings.Join(OwnWritePaths(name), ", "))
}

// OwnWritePaths are the folders plugin name may ask to write.
func OwnWritePaths(name string) []string {
	var out []string
	for _, root := range WriteRoots[:3] {
		out = append(out, root+"/kevaso-plugin-"+name, root+"/kevaso-provider-"+name)
	}
	return append(out, "/srv/"+name)
}

// Check says what's wrong with plugin name's needs on one side.
func (n Needs) Check(name, side string) error {
	for _, c := range n.Capabilities {
		if !capName.MatchString(c) {
			return fmt.Errorf("%s: capability %q (like CAP_SYS_ADMIN)", side, c)
		}
	}
	for _, d := range n.Devices {
		if !deviceName.MatchString(d) || path.Clean(d) != d {
			return fmt.Errorf("%s: device %q (a path under /dev)", side, d)
		}
	}
	for _, p := range n.WritePaths {
		if err := WritePathProblem(name, p); err != nil {
			return fmt.Errorf("%s: %w", side, err)
		}
	}
	switch {
	case n.HostMounts && !n.Root:
		return fmt.Errorf("%s: hostMounts needs root", side)
	case n.HostMounts && len(n.WritePaths) > 0:
		return fmt.Errorf("%s: writePaths with hostMounts: nothing is read-only in the host's mount namespace", side)
	case n.Socket != "" && n.Socket != ControllerSocket && n.Socket != NodeSocket:
		return fmt.Errorf("%s: socket %q: %s or %s (kevasod looks for nothing else)", side, n.Socket, ControllerSocket, NodeSocket)
	}
	return nil
}

// ParseManifest reads and checks a manifest.
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields() // a need this kvoadm doesn't know must not be silently dropped
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("plugin manifest: %w", err)
	}
	if m.Name == "" {
		return Manifest{}, errors.New("plugin manifest: no name")
	}
	if err := m.Controller.Check(m.Name, "controller"); err != nil {
		return Manifest{}, fmt.Errorf("plugin manifest: %w", err)
	}
	if err := m.Node.Check(m.Name, "node"); err != nil {
		return Manifest{}, fmt.Errorf("plugin manifest: %w", err)
	}
	for _, p := range m.DevicePrefixes {
		if err := DevicePrefixProblem(p); err != nil {
			return Manifest{}, fmt.Errorf("plugin manifest: %w", err)
		}
	}
	return m, nil
}
