package cloudhypervisor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"kevaso.com/core/sdk/kri"
)

// Paths and names on the host. The VMM's user can reach only its own silo's directory; the control
// plane's data (/var/lib/kevaso) is inaccessible to it.
const (
	SilosDir   = "/var/lib/kevaso-silos"
	ImagesDir  = "/var/lib/kevaso-images"
	BinDir     = "/opt/kevaso/cloud-hypervisor"
	VMMUser    = "kevaso-vmm"
	VG         = "kevaso"
	ThinPool   = "silos"
	Bridge     = "kvbr0"
	GuestUser  = "kevaso"
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
	// Vsock is the VM's vsock device on the host. A guest connecting to the host (CID 2) on port P
	// makes Cloud Hypervisor connect to Vsock_P: that socket belongs to this silo only (E014).
	Vsock string
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
		Vsock:  SilosDir + "/" + s + "/vsock.sock",
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

// UserData is the cloud-init config: one sudo user whose only key is the host's exec key, no
// passwords, and SSH host keys we generated (so Exec can pin them).
func UserData(execPub, hostPriv, hostPub string) string {
	indent := func(s string) string {
		return "      " + strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n      ")
	}
	return `#cloud-config
users:
  - name: ` + GuestUser + `
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys: ["` + strings.TrimSpace(execPub) + `"]
disable_root: true
ssh_pwauth: false
ssh_deletekeys: true
ssh_genkeytypes: []
ssh_keys:
  ed25519_private: |
` + indent(hostPriv) + `
  ed25519_public: ` + strings.TrimSpace(hostPub) + `
growpart: { mode: auto, devices: ["/"] }
`
}

// MetaData is cloud-init's instance identity.
func MetaData(id kri.ID) string {
	return "instance-id: " + id.UID + "\nlocal-hostname: " + id.Name + "\n"
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

// Unit is the VMM's systemd unit: Cloud Hypervisor as an unprivileged user, with the lockdown
// research E010 proved (no capabilities, NoNewPrivileges, system-call filter, only /dev/kvm,
// /dev/net/tun and its own disk, nothing of the control plane reachable).
func Unit(n Names, cpus int, memMiB int64, firmware, mac string) string {
	disk := "/dev/" + VG + "/" + n.LV
	return `[Unit]
Description=Kevaso silo ` + n.Short + ` (Cloud Hypervisor)
After=network-online.target

[Service]
User=` + VMMUser + `
Group=` + VMMUser + `
SupplementaryGroups=kvm
RuntimeDirectory=` + strings.TrimSuffix(n.Unit, ".service") + `
RuntimeDirectoryMode=0700
ExecStartPre=+/bin/chown ` + VMMUser + ` ` + disk + `
ExecStart=` + BinDir + `/cloud-hypervisor --api-socket ` + n.Socket + ` --firmware ` + firmware + ` \
  --cpus boot=` + fmt.Sprint(cpus) + ` --memory size=` + fmt.Sprint(memMiB) + `M \
  --disk path=` + disk + `,image_type=raw --disk path=` + n.Dir + `/seed.img,readonly=on,image_type=raw \
  --net tap=` + n.Tap + `,mac=` + mac + ` --vsock cid=3,socket=` + n.Vsock + ` \
  --serial file=` + n.Dir + `/serial.log --console off
Restart=no
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
# Only its own silo directory: another silo's broker socket can't even be seen (connecting to a
# unix socket works on a read-only mount, so hiding them is what keeps a VMM from posing as another).
TemporaryFileSystem=` + SilosDir + `
BindPaths=` + n.Dir + `
InaccessiblePaths=/var/lib/kevaso /root -` + ImagesDir + `
DevicePolicy=closed
DeviceAllow=/dev/kvm rw
DeviceAllow=/dev/net/tun rw
DeviceAllow=` + disk + ` rw
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
UMask=0077
`
}

// shellQuote quotes argv for the guest's shell (Exec runs `sudo -n -- argv`).
func shellQuote(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}

// usedIPs reads the addresses other silos hold.
func usedIPs(states []State) []string {
	var out []string
	for _, s := range states {
		out = append(out, s.IP)
	}
	sort.Strings(out)
	return out
}
