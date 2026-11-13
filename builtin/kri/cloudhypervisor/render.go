package cloudhypervisor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strings"
	"sync"

	"kevaso.com/core/sdk/kri"
)

// Paths and names on the host. The VMM's user can reach only its own silo's directory; the control
// plane's data (/var/lib/kevaso) is inaccessible to it.
const (
	SilosDir  = "/var/lib/kevaso-silos"
	ImagesDir = "/var/lib/kevaso-images"
	BinDir    = "/opt/kevaso/cloud-hypervisor"
	VMMUser   = "kevaso-vmm"
	VG        = "kevaso"
	ThinPool  = "silos"
	Bridge    = "kvbr0"
	// ExecUser is who Exec logs in as: root, with the host's exec key only (no password, no
	// other key). Not a user with sudo: sudo would log every command line to the guest's
	// journal and hand it to the command as SUDO_COMMAND.
	ExecUser   = "root"
	unitPrefix = "kevaso-silo-"
)

// Network is the silos' private network on this host: the mesh gives each host its own /24
// (10.64.<index>.0/24); a host without the mesh uses 10.64.0.0/24. Set it with SetNetwork before
// Install.
var Network = netip.MustParsePrefix("10.64.0.0/24")

// Gateway is the host's address on the bridge: the subnet's first address.
var Gateway = netip.MustParseAddr("10.64.0.1")

// SetNetwork sets this host's silo subnet (one Cloud Hypervisor runtime per kevasod).
func SetNetwork(p netip.Prefix) {
	Network = p.Masked()
	Gateway = Network.Addr().Next()
}

// short is a stable 10-hex-digit name for a silo: device names (TAP: 15 chars max), LVs, units.
func short(id kri.ID) string {
	h := sha256.Sum256([]byte(id.Namespace + "/" + id.Name + "/" + id.UID))
	return hex.EncodeToString(h[:5])
}

// Names are everything a silo owns on the host.
type Names struct {
	Short  string
	Dir    string // its directory (state, seed, serial log)
	Tap    string
	LV     string // logical volume name in VG
	Unit   string // systemd unit
	Socket string // VMM API socket
}

// NamesFor returns a silo's names.
func NamesFor(id kri.ID) Names {
	s := short(id)
	return Names{
		Short:  s,
		Dir:    SilosDir + "/" + s,
		Tap:    "kvt" + s,
		LV:     "kv-" + s,
		Unit:   unitPrefix + s + ".service",
		Socket: "/run/" + unitPrefix + s + "/ch.sock",
	}
}

// MAC is a locally administered address derived from the silo.
func MAC(id kri.ID) string {
	h := sha256.Sum256([]byte("mac/" + id.Namespace + "/" + id.Name + "/" + id.UID))
	return fmt.Sprintf("52:4b:%02x:%02x:%02x:%02x", h[0], h[1], h[2], h[3])
}

// AllocateIP picks the lowest free address in Network (skipping the network, gateway and broadcast).
func AllocateIP(used []string) (netip.Addr, error) {
	taken := map[netip.Addr]bool{Gateway: true}
	for _, u := range used {
		if a, err := netip.ParseAddr(u); err == nil {
			taken[a] = true
		}
	}
	last := lastAddr(Network)
	for a := Network.Addr().Next(); a.Compare(last) < 0; a = a.Next() {
		if !taken[a] {
			return a, nil
		}
	}
	return netip.Addr{}, errors.New("no free silo address on this host")
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	bits := p.Bits()
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			if i*8+j >= bits {
				b[i] |= 1 << (7 - j)
			}
		}
	}
	return netip.AddrFrom4(b)
}

// UserData is the cloud-init config: no users of its own and no passwords; root's only key is the
// host's exec key (what Exec logs in with), and SSH host keys we generated (so Exec can pin them).
//
// Root logs in directly (key only, sshd's prohibit-password) rather than through a sudo user, so a
// kvo exec command line isn't logged by sudo (the guest's journal) nor put in SUDO_COMMAND. What
// still sees it, inside the guest: the command's own argv in /proc (ps) while it runs; sshd at
// LogLevel DEBUG; an audit daemon recording execve, if the image has one. On the host and in the
// control plane it is in no log (it travels in the exec stream's header and the SSH channel).
func UserData(execPub, hostPriv, hostPub string) string {
	indent := func(s string) string {
		return "      " + strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n      ")
	}
	return `#cloud-config
users: []
disable_root: false
ssh_pwauth: false
ssh_deletekeys: true
ssh_genkeytypes: []
ssh_keys:
  ed25519_private: |
` + indent(hostPriv) + `
  ed25519_public: ` + strings.TrimSpace(hostPub) + `
growpart: { mode: auto, devices: ["/"] }
# A disk that moved here holds the last host's exec key: replace it at every boot, before ssh lets
# anyone in, instead of only in the final stage (write_files below, deferred).
bootcmd:
  - [sh, -c, ` + yamlQuote(BootKeysScript(execPub)) + `]
write_files:
  # Root logs in with a key only, never a password.
  - path: /etc/ssh/sshd_config.d/10-kevaso.conf
    content: "PermitRootLogin prohibit-password\n"
    permissions: "0644"
  # Only this host's exec key, also on a disk that moved here (written last, so nothing adds to it).
  - path: /root/.ssh/authorized_keys
    content: "` + strings.TrimSpace(execPub) + `\n"
    owner: root:root
    permissions: "0600"
    defer: true
`
}

// BootKeysScript leaves only execPub in root's authorized_keys.
func BootKeysScript(execPub string) string {
	f := "/root/.ssh/authorized_keys"
	return "install -d -m 0700 /root/.ssh && printf '%s\\n' " + shellQuote([]string{strings.TrimSpace(execPub)}) +
		" > " + f + ".new && chmod 0600 " + f + ".new && mv -f " + f + ".new " + f
}

// yamlQuote is s as a double-quoted YAML string.
func yamlQuote(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b) // JSON strings are YAML double-quoted strings
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSpace(b.String())
}

// MetaData is cloud-init's instance identity. Each new seed (a create, a reset, a create on
// another host for a disk that moved) is a new instance, so cloud-init applies this host's keys,
// address and host key to a disk that has booted before.
func MetaData(id kri.ID, hostPub string) string {
	h := sha256.Sum256([]byte(hostPub))
	return "instance-id: " + id.UID + "-" + hex.EncodeToString(h[:4]) + "\nlocal-hostname: " + id.Name + "\n"
}

// NetworkConfig gives the guest its static address on the bridge, and the host's DNS on the
// gateway, which answers private names (NAME.NAMESPACE.kevaso, or NAME in the same namespace).
func NetworkConfig(mac string, ip netip.Addr, namespace string) string {
	return fmt.Sprintf(`version: 2
ethernets:
  nic0:
    match: { macaddress: "%s" }
    set-name: eth0
    addresses: [%s/%d]
    routes: [{ to: default, via: %s }]
    nameservers: { addresses: [%s], search: [%s.kevaso, kevaso] }
`, mac, ip, Network.Bits(), Gateway, Gateway, namespace)
}

// Unit is the VMM's systemd unit for a silo with no volumes and its disk on a thin LV.
func Unit(n Names, cpus int, memMiB int64, firmware, mac string) string {
	return UnitFor(n, cpus, memMiB, firmware, mac, Layout{})
}

// UnitFor is the VMM's systemd unit: Cloud Hypervisor as an unprivileged user, with the lockdown
// research E010 proved (no capabilities, NoNewPrivileges, system-call filter, only /dev/kvm,
// /dev/net/tun and its own disks, nothing of the control plane reachable). Its volumes (ADR 0006)
// add their LVs (and nothing else of the host's devices) and their virtiofsd sockets, which sit in
// its own directory; a root disk on a mount class's folder adds that one folder.
func UnitFor(n Names, cpus int, memMiB int64, firmware, mac string, l Layout) string {
	disk := l.RootDisk(n)
	var b strings.Builder
	w := func(s string) { b.WriteString(s + "\n") }
	w("[Unit]")
	w("Description=Kevaso silo " + n.Short + " (Cloud Hypervisor)")
	w("After=network-online.target")
	w("")
	w("[Service]")
	w("User=" + VMMUser)
	w("Group=" + VMMUser)
	w("SupplementaryGroups=kvm")
	w("RuntimeDirectory=" + strings.TrimSuffix(n.Unit, ".service"))
	w("RuntimeDirectoryMode=0700")
	w("ExecStartPre=+/bin/chown " + VMMUser + " " + disk)
	for _, d := range l.Disks {
		w("ExecStartPre=+/bin/chown " + VMMUser + " " + d.Device())
	}
	args := []string{"--api-socket", n.Socket, "--firmware", firmware, "--cpus", "boot=" + fmt.Sprint(cpus)}
	args = append(args, VMMArgs(n, l, memMiB)...)
	args = append(args, "--net", "tap="+n.Tap+",mac="+mac, "--serial", "file="+n.Dir+"/serial.log", "--console", "off")
	w("ExecStart=" + BinDir + "/cloud-hypervisor " + strings.Join(args, " "))
	w("Restart=no")
	w("NoNewPrivileges=yes")
	w("CapabilityBoundingSet=")
	w("AmbientCapabilities=")
	w("ProtectSystem=strict")
	w("ProtectHome=yes")
	w("PrivateTmp=yes")
	w("# Only its own silo directory: another silo's broker socket can't even be seen (connecting to a")
	w("# unix socket works on a read-only mount, so hiding them is what keeps a VMM from posing as another).")
	w("TemporaryFileSystem=" + SilosDir)
	w("BindPaths=" + n.Dir)
	if l.RootFile != "" {
		// Of kevasod's folder only the root disk's (a mount class's volume): the rest stays empty.
		w("TemporaryFileSystem=/var/lib/kevaso:ro")
		w("BindPaths=" + path.Dir(l.RootFile))
		w("InaccessiblePaths=/root -" + ImagesDir)
	} else {
		w("InaccessiblePaths=/var/lib/kevaso /root -" + ImagesDir)
	}
	w("DevicePolicy=closed")
	w("DeviceAllow=/dev/kvm rw")
	w("DeviceAllow=/dev/net/tun rw")
	if l.RootFile == "" {
		w("DeviceAllow=" + disk + " rw")
	}
	for _, d := range l.Disks {
		w("DeviceAllow=" + d.Device() + " rw")
	}
	for _, line := range []string{"ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes",
		"ProtectClock=yes", "ProtectHostname=yes", "ProtectProc=invisible", "ProcSubset=pid", "RestrictSUIDSGID=yes", "RestrictRealtime=yes",
		"LockPersonality=yes", "RestrictNamespaces=yes", "RestrictAddressFamilies=AF_UNIX AF_NETLINK", "UMask=0077"} {
		w(line)
	}
	return b.String()
}

// shellQuote quotes argv for the guest's shell (Exec runs `env KEVASO_EXEC=… argv` as root).
func shellQuote(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}

// ContainersDir is where the container runtimes (docker, podman) keep their silos: they share the
// bridge, so its addresses, with the VMs.
const ContainersDir = "/var/lib/kevaso-containers"

// IPMu serializes address allocation among the runtimes of one host (hold it from AllocateIP until
// the new silo's state, with its address, is saved).
var IPMu sync.Mutex

// UsedIPs reads the addresses every silo on this host holds, VMs and containers.
func UsedIPs(h Host) []string {
	var out []string
	for _, pattern := range []string{SilosDir + "/*/silo.json", ContainersDir + "/*/state.json"} {
		paths, _ := h.Glob(pattern)
		for _, p := range paths {
			b, err := h.ReadFile(p)
			if err != nil {
				continue
			}
			var s struct {
				IP string `json:"ip"`
			}
			if json.Unmarshal(b, &s) == nil && s.IP != "" {
				out = append(out, s.IP)
			}
		}
	}
	sort.Strings(out)
	return out
}
