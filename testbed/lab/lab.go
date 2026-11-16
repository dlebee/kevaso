// Package lab describes one worktree lab: three nested node VMs on the lab host (one system
// node, two workers), or in pair mode two machine VMs (m1 and m2) with Kevaso not installed,
// a private /24, and the nftables rules that publish SSH, the API and the two-machine
// tests' ports on the host's public address. kvlab (cmd/kvlab) is what creates and deletes
// them. This package is the part that can be checked without a machine: names, slots, ports,
// and the text of every file and rule the lab writes.
//
// Everything a lab creates is prefixed kvl-NAME-. The base image and libvirt's default network
// are not, and a lab never names them.
package lab

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	// MaxLabs is how many labs fit on the host at once (one /24 and one port block each).
	MaxLabs = 6
	// HostThreads is the lab host's hardware threads (the EPYC from E046). The labs share them.
	HostThreads = 32
	// MaxName is the longest lab name. It is one DNS label, so the VM names stay short.
	MaxName = 12
	// PortBase is the start of the forwarded-port space. Slot N uses 21000+N*100.
	PortBase = 21000
	// StateRoot is the lab host's directory of per-lab keys and slot files.
	StateRoot = "/root/kvl"
	// ImageDir holds the base image and every lab disk.
	ImageDir = "/var/lib/libvirt/images"
	// BaseImage is the Ubuntu 24.04 cloud image the node disks overlay. It is not a lab's.
	BaseImage = ImageDir + "/e046-base-noble.img"
	// Table is the only nftables table the lab tool owns.
	Table = "inet kvl"
	// DNSDomain is the domain libvirt's dnsmasq serves for every lab.
	DNSDomain = "lab.test"
)

// ErrBadName, ErrExists, ErrCap and ErrKevasod are why lab-up refuses.
var (
	ErrBadName = errors.New("bad lab name")
	ErrExists  = errors.New("lab already exists")
	ErrCap     = errors.New("lab cap reached")
	ErrKevasod = errors.New("kevasod is active on the lab host")
	ErrBadSlot = errors.New("bad lab slot")
)

// nameRE is one lowercase DNS label of at most MaxName characters: a letter, then letters,
// digits and hyphens, not ending in a hyphen.
var nameRE = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,10}[a-z0-9])?$`)

// ValidName reports whether name may be a lab. It is the only check between a name and a
// shell word, so it rejects anything that is not a short label.
func ValidName(name string) error {
	if nameRE.MatchString(name) && len(name) <= MaxName {
		return nil
	}
	return fmt.Errorf("%w %q: want a lowercase DNS label of at most %d characters (a letter, then letters, digits or hyphens, not ending in a hyphen)", ErrBadName, name, MaxName)
}

// Node is one VM in a lab.
type Node struct {
	Role        string // sys, w1, w2, or in a pair lab m1, m2
	VCPU        int
	MemoryMiB   int
	DiskGiB     int
	Octet       int    // host address in the lab /24
	SSHOff      int    // added to the slot's port base: the forwarded SSH port
	SpareSerial string // a second empty virtio disk; the guest sees /dev/disk/by-id/virtio-SERIAL
}

// SpareSerial is m2's second disk. It is stable so the pair env can name it, and short enough
// for a virtio-blk serial (20 characters).
const SpareSerial = "kvlspare"

// SpareByID is that disk in the guest, the path KEVASO_METAL2_SPARE_DISK gets.
const SpareByID = "/dev/disk/by-id/virtio-" + SpareSerial

// SpareDiskGiB is the spare disk's size. It is empty: no partition, no filesystem.
const SpareDiskGiB = 20

// Nodes is the cluster: the system node, then the two workers.
func Nodes() []Node {
	return []Node{
		{Role: "sys", VCPU: 2, MemoryMiB: 4096, DiskGiB: 20, Octet: 10, SSHOff: 22},
		{Role: "w1", VCPU: 4, MemoryMiB: 8192, DiskGiB: 40, Octet: 11, SSHOff: 23},
		{Role: "w2", VCPU: 4, MemoryMiB: 8192, DiskGiB: 40, Octet: 12, SSHOff: 24},
	}
}

// PairVCPU is the vCPU count of each machine in a pair lab. The real machines have 16 and 32
// threads. A guest keeps one CPU for the host, so 4 vCPU leaves 3 for silos, and the two-machine
// tests place five one-CPU silos on one machine. 8 leaves 7.
//
// PairVCPUMin is 6: those five silos, plus the CPU the host keeps. PairVCPUMax is half of
// HostThreads, so the two machines of one lab use the whole EPYC and no more. Six pair labs at
// the default is 96 vCPUs on 32 threads; a smaller count is for when several labs run at once.
const (
	PairVCPU    = 8
	PairVCPUMin = 6
	PairVCPUMax = HostThreads / 2
)

// ValidPairVCPU reports whether n may be the vCPU count of each pair-lab machine.
func ValidPairVCPU(n int) error {
	if n < PairVCPUMin || n > PairVCPUMax {
		return fmt.Errorf("pair vcpu %d: want %d to %d (a machine keeps one CPU for itself, and the two-machine tests place five one-CPU silos on one machine; %d on each of two machines is the EPYC's %d threads)",
			n, PairVCPUMin, PairVCPUMax, PairVCPUMax, HostThreads)
	}
	return nil
}

// PairNodes is a pair lab: two machines at PairVCPU. m2 has the spare disk.
// Kevaso is not installed on either; the metal tests install it themselves.
func PairNodes() []Node { return pairNodes(PairVCPU) }

// PairNodesWith is PairNodes with vcpu on each machine.
func PairNodesWith(vcpu int) ([]Node, error) {
	if err := ValidPairVCPU(vcpu); err != nil {
		return nil, err
	}
	return pairNodes(vcpu), nil
}

func pairNodes(vcpu int) []Node {
	return []Node{
		{Role: "m1", VCPU: vcpu, MemoryMiB: 8192, DiskGiB: 40, Octet: 10, SSHOff: 22},
		{Role: "m2", VCPU: vcpu, MemoryMiB: 8192, DiskGiB: 40, Octet: 11, SSHOff: 23, SpareSerial: SpareSerial},
	}
}

// AllNodes is every VM a destroy removes: a node lab's three and a pair lab's two. A lab has
// one of those sets. The names from the other are absent, and destroying them does nothing.
func AllNodes() []Node {
	return append(append([]Node{}, Nodes()...), PairNodes()...)
}

// PairDial is a TCP port the two-machine tests open from the Mac on a machine's external
// address. The guest keeps Port (an Ingress on :80 inside the VM stays on 80). The lab host
// publishes it at 21000+slot*100+Off, and the tests dial that (KEVASO_METAL_PORT_<Port>),
// which is Port when the variable is unset. SSH is not here; KEVASO_METAL_HOST carries the
// forwarded SSH port. The API is not here either: each lab publishes it on Ports.API.
// Off stays clear of 22, 23, 24 and APIOff, the offsets a normal lab already uses.
type PairDial struct {
	Role string
	Port int // on the machine
	Off  int // added to the slot's port base
}

// PairDials is every port pair mode publishes on the lab host's public address, other than
// SSH and the API. 80 and 443 are TestMetal2Ingress; 443 is also the long soak's certificate
// check from the Mac. 18160 is the long soak's lease, on machine 1. 18200 and 18201 are
// TestMetal2Worker; 18210 is TestMetal2Mesh. Nothing in the two-machine suite opens a NodePort.
// Public port 80 is also published when the host does not already have it, because Let's
// Encrypt's HTTP-01 challenge (TestMetal2LongSoakSetup) has to reach port 80 itself.
func PairDials() []PairDial {
	return []PairDial{
		{Role: "m1", Port: 80, Off: 80},
		{Role: "m1", Port: 443, Off: 44}, // 43 is the API
		{Role: "m1", Port: 18160, Off: 60},
		{Role: "m2", Port: 18200, Off: 25},
		{Role: "m2", Port: 18201, Off: 26},
		{Role: "m2", Port: 18210, Off: 27},
	}
}

// checkPairDials reports a table that would publish two things on one host port, or that
// dropped port 80 (the HTTP-01 exception is a second, optional forward of that same guest port).
func checkPairDials() error {
	used := map[int]string{22: "ssh sys/m1", 23: "ssh w1/m2", 24: "ssh w2", APIOff: "api"}
	seen := map[int]bool{}
	for _, d := range PairDials() {
		if d.Off < 0 || d.Off > 99 {
			return fmt.Errorf("pair dial %d: offset %d is outside the slot block", d.Port, d.Off)
		}
		if d.Port < 1 || d.Port > 65535 {
			return fmt.Errorf("pair dial port %d: want a TCP port", d.Port)
		}
		if prev, ok := used[d.Off]; ok {
			return fmt.Errorf("pair dial %d: offset %d is already %s", d.Port, d.Off, prev)
		}
		if seen[d.Port] {
			return fmt.Errorf("pair dial port %d is listed twice", d.Port)
		}
		if _, err := pairOctet(d.Role); err != nil {
			return err
		}
		seen[d.Port] = true
		used[d.Off] = fmt.Sprintf("%s:%d", d.Role, d.Port)
	}
	if !seen[80] {
		return fmt.Errorf("pair dials: port 80 is not published")
	}
	return nil
}

// Dial is the lab host port that forwards to guest on this slot. The guest still listens
// on guest.
func (p Ports) Dial(guest int) (int, error) {
	if err := checkPairDials(); err != nil {
		return 0, err
	}
	var off int
	ok := false
	for _, d := range PairDials() {
		if d.Port == guest {
			off = d.Off
			ok = true
		}
	}
	if !ok {
		return 0, fmt.Errorf("pair dial port %d is not published", guest)
	}
	// SysSSH is the slot base plus 22, the system node's SSH offset.
	base := p.SysSSH - 22
	slot := (base - PortBase) / 100
	if slot < 1 || slot > MaxLabs || base != PortBase+slot*100 {
		return 0, fmt.Errorf("%w", ErrBadSlot)
	}
	return base + off, nil
}

// HostPorts is guest port → lab host port, one entry per PairDials.
func (p Ports) HostPorts() (map[int]int, error) {
	out := map[int]int{}
	for _, d := range PairDials() {
		h, err := p.Dial(d.Port)
		if err != nil {
			return nil, err
		}
		out[d.Port] = h
	}
	return out, nil
}

// APIOff is the forwarded API port's offset in the slot's block (the system node's 6443).
const APIOff = 43

// Ports publishes one slot on the lab host.
type Ports struct {
	SysSSH int
	W1SSH  int
	W2SSH  int
	API    int
}

// PortsFor is the host ports for a slot: 21000 + slot*100 + {22 sys, 23 w1, 24 w2, 43 api}.
func PortsFor(slot int) (Ports, error) {
	if slot < 1 || slot > MaxLabs {
		return Ports{}, fmt.Errorf("%w %d", ErrBadSlot, slot)
	}
	base := PortBase + slot*100
	return Ports{SysSSH: base + 22, W1SSH: base + 23, W2SSH: base + 24, API: base + APIOff}, nil
}

// SSH returns the forwarded SSH port of a role. A pair lab's m1 uses the system node's offset
// and m2 the first worker's; there is no third SSH port.
func (p Ports) SSH(role string) int {
	switch role {
	case "sys", "m1":
		return p.SysSSH
	case "w1", "m2":
		return p.W1SSH
	case "w2":
		return p.W2SSH
	}
	return 0
}

// AllocateSlot picks the lowest free slot in 1..MaxLabs. used is the slot of each lab that
// already exists, this name's included when it is being recreated (the caller drops it first).
// A seventh lab is refused even when a duplicate slot number would leave a hole.
func AllocateSlot(used []int) (int, error) {
	if len(used) >= MaxLabs {
		return 0, fmt.Errorf("%w: %d labs already (the cap is %d); refusing another", ErrCap, len(used), MaxLabs)
	}
	taken := map[int]bool{}
	for _, s := range used {
		taken[s] = true
	}
	for s := 1; s <= MaxLabs; s++ {
		if !taken[s] {
			return s, nil
		}
	}
	return 0, fmt.Errorf("%w: slots 1..%d are all taken", ErrCap, MaxLabs)
}

// RefuseUp decides whether lab-up may proceed. kevasod on the host is refused even for a
// recreate: Kevaso manages its own firewall tables, and the lab's table is inet kvl.
func RefuseUp(name string, exists, recreate, kevasodActive bool, labs int) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if kevasodActive {
		return fmt.Errorf("%w: Kevaso manages its own firewall tables, so a lab's %s table on the same host would be rewritten; stop kevasod on the lab host before lab-up", ErrKevasod, Table)
	}
	if exists && !recreate {
		return fmt.Errorf("%w: lab %q is already on the host; lab-down first, or lab-up --recreate", ErrExists, name)
	}
	if !exists && labs >= MaxLabs {
		return fmt.Errorf("%w: %d labs already (the cap is %d); refusing a %dth", ErrCap, labs, MaxLabs, labs+1)
	}
	return nil
}

// NetworkName is the libvirt network (kvl-NAME).
func NetworkName(name string) string { return "kvl-" + name }

// VMName is one domain (kvl-NAME-sys, kvl-NAME-w1, kvl-NAME-w2).
func VMName(name, role string) string { return "kvl-" + name + "-" + role }

// Bridge is the short bridge name for a slot. Linux interface names stop at 15 characters,
// and a 12-character lab name would not fit in kvl-NAME, so the bridge is kvlbrN.
func Bridge(slot int) string { return "kvlbr" + strconv.Itoa(slot) }

// PreChain and PostChain are this lab's chains inside Table.
func PreChain(name string) string  { return "kvl-" + name + "-pre" }
func PostChain(name string) string { return "kvl-" + name + "-post" }

// IP is an address in the lab's /24. The gateway is octet 1; the nodes are 10, 11 and 12.
func IP(slot, octet int) string { return fmt.Sprintf("10.77.%d.%d", slot, octet) }

// CIDR is the lab network.
func CIDR(slot int) string { return fmt.Sprintf("10.77.%d.0/24", slot) }

// MAC is the NIC address reserved in DHCP. Slot and octet are both in the last two bytes,
// so two labs never share one.
func MAC(slot, octet int) string { return fmt.Sprintf("52:54:00:77:%02x:%02x", slot, octet) }

// Hostname is the DNS name of a node (sys.NAME.lab.test).
func Hostname(name, role string) string { return role + "." + name + "." + DNSDomain }

// Disk and Seed are the overlay and the cloud-init CD, both under ImageDir and both prefixed
// kvl-NAME-.
func Disk(name, role string) string {
	return ImageDir + "/" + VMName(name, role) + ".qcow2"
}

func Seed(name, role string) string {
	return ImageDir + "/" + VMName(name, role) + "-seed.img"
}

// SpareDisk is m2's empty second disk, prefixed kvl-NAME- like every other lab file.
func SpareDisk(name string) string {
	return ImageDir + "/" + VMName(name, "m2") + "-spare.qcow2"
}

// StateDir is /root/kvl/NAME.
func StateDir(name string) string { return StateRoot + "/" + name }

// KevasodActive is systemctl is-active's answer when lab-up must refuse.
func KevasodActive(state string) bool {
	switch strings.TrimSpace(state) {
	case "active", "activating", "reloading":
		return true
	}
	return false
}
