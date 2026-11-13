package cloudhypervisor

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

func vmVolumes() []kri.Volume {
	return []kri.Volume{
		{Name: "home", MountPath: "/home/me", HostPath: "/var/lib/kevaso/volumes/uid-web/home", SizeBytes: 5 << 30},
		{Name: "cache", MountPath: "/var/cache/app", SizeBytes: 2 << 30},
	}
}

func TestLayoutAndVMMArgs(t *testing.T) {
	n := NamesFor(id("web"))
	l := LayoutFor(n, vmVolumes(), "")
	if len(l.Disks) != 1 || len(l.Shares) != 1 || l.RootFile != "" {
		t.Fatalf("layout: %+v", l)
	}
	d, s := l.Disks[0], l.Shares[0]
	if d.Name != "cache" || !strings.HasPrefix(d.LV, n.LV+"-") || len(d.Serial) > 20 || d.Serial == "" {
		t.Fatalf("disk: %+v", d)
	}
	if s.Name != "home" || len(s.Tag) > 36 || !strings.HasPrefix(s.Socket, n.Dir+"/vfs/") || !strings.HasPrefix(s.Unit, unitPrefix+n.Short+"-fs-") {
		t.Fatalf("share: %+v", s)
	}
	if again := LayoutFor(n, []kri.Volume{vmVolumes()[1], vmVolumes()[0]}, ""); !slices.Equal(again.Disks, l.Disks) || !slices.Equal(again.Shares, l.Shares) {
		t.Fatal("the layout depends on the volumes' order")
	}
	if other := LayoutFor(NamesFor(id("db")), vmVolumes(), ""); other.Shares[0].Tag == s.Tag || other.Disks[0].LV == d.LV {
		t.Fatal("two silos' volumes share names")
	}
	args := strings.Join(VMMArgs(n, l, 4096), " ")
	for _, want := range []string{
		"--memory size=4096M,shared=on", // virtiofs needs the guest's memory shared (E029)
		"--disk path=/dev/kevaso/" + n.LV + ",image_type=raw path=" + n.Dir + "/seed.img,readonly=on,image_type=raw path=/dev/kevaso/" + d.LV + ",image_type=raw,serial=" + d.Serial,
		"--fs tag=" + s.Tag + ",socket=" + s.Socket,
	} {
		if !strings.Contains(args, want) {
			t.Errorf("VMM args lack %q:\n%s", want, args)
		}
	}
	if plain := strings.Join(VMMArgs(n, LayoutFor(n, nil, ""), 1024), " "); strings.Contains(plain, "shared=on") || strings.Contains(plain, "--fs") {
		t.Errorf("no shares, yet: %s", plain)
	}
	if root := LayoutFor(n, nil, "/var/lib/kevaso/volumes/uid-web/disk.root"); root.RootDisk(n) != "/var/lib/kevaso/volumes/uid-web/disk.root/root.raw" {
		t.Errorf("root file: %s", root.RootDisk(n))
	}
}

func TestVMMUnitWithVolumes(t *testing.T) {
	n := NamesFor(id("web"))
	l := LayoutFor(n, vmVolumes(), "")
	u := UnitFor(n, 2, 4096, BinDir+"/CLOUDHV_EFI.fd", MAC(id("web")), l)
	for _, want := range []string{
		"DeviceAllow=/dev/kevaso/" + n.LV + " rw\n", "DeviceAllow=" + l.Disks[0].Device() + " rw\n",
		"ExecStartPre=+/bin/chown " + VMMUser + " " + l.Disks[0].Device() + "\n",
		"--fs tag=" + l.Shares[0].Tag, "InaccessiblePaths=/var/lib/kevaso /root", "CapabilityBoundingSet=\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	// The VMM never sees the shared folder itself: only virtiofsd's socket, in its own directory.
	if strings.Contains(u, l.Shares[0].HostPath) {
		t.Errorf("the VMM's unit reaches the shared folder:\n%s", u)
	}
	if Unit(n, 2, 4096, "fw", "m") != UnitFor(n, 2, 4096, "fw", "m", Layout{}) {
		t.Error("Unit isn't UnitFor with no volumes")
	}
	rf := UnitFor(n, 1, 1024, "fw", "m", LayoutFor(n, nil, "/var/lib/kevaso/volumes/uid-web/disk.root"))
	for _, want := range []string{
		"--disk path=/var/lib/kevaso/volumes/uid-web/disk.root/root.raw,image_type=raw",
		"TemporaryFileSystem=/var/lib/kevaso:ro\n", "BindPaths=/var/lib/kevaso/volumes/uid-web/disk.root\n",
		"ExecStartPre=+/bin/chown " + VMMUser + " /var/lib/kevaso/volumes/uid-web/disk.root/root.raw\n",
	} {
		if !strings.Contains(rf, want) {
			t.Errorf("root-file unit lacks %q:\n%s", want, rf)
		}
	}
	if strings.Contains(rf, "DeviceAllow=/dev/kevaso/"+n.LV) || strings.Contains(rf, "InaccessiblePaths=/var/lib/kevaso ") {
		t.Errorf("root-file unit still has the LV, or hides the disk's folder:\n%s", rf)
	}
}

func TestVirtiofsdUnit(t *testing.T) {
	n := NamesFor(id("web"))
	s := LayoutFor(n, vmVolumes(), "").Shares[0]
	want := "--socket-path=" + s.Socket + " --socket-group=" + VMMUser + " --shared-dir=" + s.HostPath +
		" --cache=auto --sandbox=chroot --rlimit-nofile=0 --modcaps=-fsetid:-mknod:-setfcap"
	if got := strings.Join(VirtiofsdArgs(s), " "); got != want {
		t.Fatalf("virtiofsd args:\n got %s\nwant %s", got, want)
	}
	u := VirtiofsdUnit(n, s)
	caps := "CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETPCAP CAP_SETUID CAP_SYS_CHROOT"
	for _, want := range []string{
		"User=root\n", "Group=" + VMMUser + "\n",
		"ExecStart=" + VirtiofsdBin + " --socket-path=" + s.Socket,
		"CapabilityBoundingSet=" + caps + "\n", "AmbientCapabilities=" + caps + "\n",
		"NoNewPrivileges=yes", "PrivateNetwork=yes", "PrivateDevices=yes", "RestrictAddressFamilies=AF_UNIX\n",
		"TemporaryFileSystem=/var/lib/kevaso:ro " + SilosDir + ":ro /run:ro\n",
		"InaccessiblePaths=/root -/etc/kevaso -/etc/ssh -" + ImagesDir + "\n",
		"BindPaths=" + s.HostPath + " " + n.Dir + "/vfs\n", "RestrictSUIDSGID=yes", "Restart=no", "LimitNOFILE=",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("virtiofsd unit lacks %q:\n%s", want, u)
		}
	}
	for _, never := range []string{"CAP_SYS_ADMIN", "CAP_MKNOD", "CAP_SETFCAP", "CAP_FSETID", "DynamicUser", "ProcSubset"} {
		if strings.Contains(strings.ReplaceAll(u, "--modcaps=-fsetid:-mknod:-setfcap", ""), never) {
			t.Errorf("virtiofsd unit has %q:\n%s", never, u)
		}
	}
}

// What virtiofsd 1.10 did on a real host (Lima, Ubuntu 24.04), each of which stopped every VM
// with a virtiofs volume from booting: as any user but root it refuses --sandbox=chroot; it asks
// for its default capabilities for serving and exits ("can't apply the child capabilities")
// unless each is in the bounding set or dropped by --modcaps, and it needs CAP_SETPCAP to drop
// them; it makes its socket 0700 (the VMM got "Permission denied") unless given --socket-group;
// it also fails to apply them unless they're ambient at start;
// and it reads /proc/sys/fs/nr_open at start even with --rlimit-nofile=0, which ProcSubset=pid hides.
func TestVirtiofsdStartsOnARealHost(t *testing.T) {
	n := NamesFor(id("web"))
	s := LayoutFor(n, vmVolumes(), "").Shares[0]
	u := VirtiofsdUnit(n, s)
	args := strings.Join(VirtiofsdArgs(s), " ")
	if strings.Contains(args, "--sandbox=chroot") && !strings.Contains(u, "User=root\n") {
		t.Error("--sandbox=chroot without root")
	}
	for _, c := range VirtiofsdDefaults {
		if !slices.Contains(VirtiofsdCaps, c) && !slices.Contains(VirtiofsdDrops, c) {
			t.Errorf("virtiofsd asks for %s: neither bounded in nor dropped", c)
		}
		if slices.Contains(VirtiofsdDrops, c) && !strings.Contains(args, "-"+strings.ToLower(strings.TrimPrefix(c, "CAP_"))) {
			t.Errorf("%s not dropped in %s", c, args)
		}
	}
	if !slices.Contains(VirtiofsdCaps, "CAP_SETPCAP") {
		t.Error("no CAP_SETPCAP: virtiofsd can't drop its capabilities")
	}
	if !strings.Contains(u, "AmbientCapabilities="+strings.Join(VirtiofsdCaps, " ")+"\n") {
		t.Error("virtiofsd can't apply its capabilities unless it starts with them ambient")
	}
	if !strings.Contains(args, "--socket-group="+VMMUser) {
		t.Error("the socket isn't the VMM's group's: virtiofsd makes it 0700")
	}
	if strings.Contains(u, "ProcSubset=pid") {
		t.Error("ProcSubset=pid hides /proc/sys/fs/nr_open, which virtiofsd reads at start")
	}
}

// Start: virtiofsd first (and its socket there) before the VMM. Stop: the VMM, then virtiofsd, so a
// folder is only free to unmount (and a move's "unmounted" only true) once nothing holds it.
func TestStartStopPlans(t *testing.T) {
	n := NamesFor(id("web"))
	l := LayoutFor(n, vmVolumes(), "")
	s := l.Shares[0]
	start := StartPlan(n, l)
	want := []Step{
		{Cmd: []string{"systemctl", "restart", s.Unit}, Socket: s.Socket},
		{Cmd: []string{"ip", "link", "set", n.Tap, "up"}},
		{Cmd: []string{"systemctl", "start", n.Unit}},
	}
	if len(start) != len(want) {
		t.Fatalf("start plan: %v", start)
	}
	for i := range want {
		if !slices.Equal(start[i].Cmd, want[i].Cmd) || start[i].Socket != want[i].Socket {
			t.Fatalf("start step %d: %v, want %v", i, start[i], want[i])
		}
	}
	stop := StopPlan(n, l)
	vmm, vfs := -1, -1
	for i, c := range stop {
		if slices.Equal(c, []string{"systemctl", "stop", n.Unit}) {
			vmm = i
		}
		if slices.Equal(c, []string{"systemctl", "stop", s.Unit}) {
			vfs = i
		}
	}
	if vmm < 0 || vfs < 0 || vfs < vmm {
		t.Fatalf("stop plan: %v (want the VMM stopped before virtiofsd)", stop)
	}
	if len(StopPlan(n, LayoutFor(n, nil, ""))) != 2 {
		t.Fatal("no shares: just the VMM")
	}
}

func TestGuestMountScript(t *testing.T) {
	n := NamesFor(id("web"))
	vols := append(vmVolumes(), kri.Volume{Name: "odd", MountPath: "/srv/my data", HostPath: "/x"},
		kri.Volume{Name: "inner", MountPath: "/home/me/inner", HostPath: "/y"})
	l := LayoutFor(n, vols, "")
	block := FstabBlock(l)
	for _, want := range []string{
		"/dev/disk/by-id/virtio-" + l.Disks[0].Serial + " /var/cache/app ext4 noatime,nofail,",
		l.Shares[0].Tag + " /home/me virtiofs nofail 0 0", `/srv/my\040data virtiofs nofail`,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("fstab lacks %q:\n%s", want, block)
		}
	}
	sc := GuestMountScript(l)
	for _, want := range []string{"mkfs.ext4 -q -m 0", "blkid -p", "systemctl daemon-reload", "mountpoint -q '/srv/my data' || mount '/srv/my data'"} {
		if !strings.Contains(sc, want) {
			t.Errorf("script lacks %q:\n%s", want, sc)
		}
	}
	// Parents first.
	if strings.Index(sc, "mount '/home/me'") > strings.Index(sc, "mount '/home/me/inner'") {
		t.Errorf("a share inside another mounted first:\n%s", sc)
	}
}

// SetVolumes: a running VM with other volumes needs a restart (nothing changes yet); stopped, the
// new layout is applied (a new local disk made, a dropped share's unit gone).
func TestSetVolumes(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	running := false
	h.answer = func(cmd string) (string, error) {
		switch {
		case strings.HasPrefix(cmd, "systemctl is-active"):
			if running {
				return "active", nil
			}
			return "inactive", errors.New("exit 3")
		case strings.HasPrefix(cmd, "lvs --noheadings kevaso/"):
			return "", errors.New("exit 5") // no such LV yet
		}
		return "", nil
	}
	sp := spec("web")
	sp.Volumes = vmVolumes()[:1]
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	old := LayoutFor(n, sp.Volumes, "")
	if _, ok := h.files["/etc/systemd/system/"+old.Shares[0].Unit]; !ok {
		t.Fatal("create wrote no virtiofsd unit")
	}
	if restart, err := r.SetVolumes(ctx, sp.ID, sp.Volumes); err != nil || restart {
		t.Fatalf("unchanged: %v %v", restart, err)
	}
	running = true
	before := len(h.commands())
	if restart, err := r.SetVolumes(ctx, sp.ID, vmVolumes()[1:]); err != nil || !restart {
		t.Fatalf("running with others: %v %v (want restart)", restart, err)
	}
	for _, c := range h.commands()[before:] {
		if strings.HasPrefix(c, "lvcreate") {
			t.Fatalf("changed a running VM: %s", c)
		}
	}
	running = false
	if restart, err := r.SetVolumes(ctx, sp.ID, vmVolumes()[1:]); err != nil || restart {
		t.Fatalf("stopped: %v %v", restart, err)
	}
	nl := LayoutFor(n, vmVolumes()[1:], "")
	if indexOf(h.commands(), "lvcreate -q -T kevaso/silos -V 2048m -n "+nl.Disks[0].LV) < 0 {
		t.Fatalf("no LV for the new local volume: %v", h.commands())
	}
	if _, ok := h.files["/etc/systemd/system/"+old.Shares[0].Unit]; ok {
		t.Fatal("the dropped share's virtiofsd unit is still there")
	}
	if u := string(h.files["/etc/systemd/system/"+n.Unit]); !strings.Contains(u, "serial="+nl.Disks[0].Serial) || strings.Contains(u, "--fs") {
		t.Fatalf("VMM unit after the change:\n%s", u)
	}
	if st, _ := r.state(sp.ID); volumesKey(st.Volumes) != volumesKey(vmVolumes()[1:]) {
		t.Fatalf("state: %+v", st.Volumes)
	}
}

// Start waits for each virtiofsd's socket before the VMM; Stop and Delete stop the VMM first.
func TestStartStopWithShares(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("web")
	sp.Volumes = vmVolumes()
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	n := NamesFor(sp.ID)
	s := LayoutFor(n, sp.Volumes, "").Shares[0]
	h.answer = func(cmd string) (string, error) {
		if cmd == "systemctl restart "+s.Unit {
			h.files[s.Socket] = nil // virtiofsd made its socket (called with h.mu held)
		}
		if strings.HasPrefix(cmd, "systemctl is-active") {
			return "inactive", errors.New("exit 3")
		}
		return "", nil
	}
	if err := r.Start(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	cmds := h.commands()
	if a, b := indexOf(cmds, "systemctl restart "+s.Unit), indexOf(cmds, "systemctl start "+n.Unit); a < 0 || b < a {
		t.Fatalf("virtiofsd after the VMM: %v", cmds)
	}
	if err := r.Stop(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	cmds = h.commands()
	if a, b := lastIndex(cmds, "systemctl stop "+n.Unit), lastIndex(cmds, "systemctl stop "+s.Unit); a < 0 || b < a {
		t.Fatalf("stop: virtiofsd before the VMM: %v", cmds)
	}
	if err := r.Delete(ctx, sp.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.files["/etc/systemd/system/"+s.Unit]; ok {
		t.Fatal("delete left the virtiofsd unit")
	}
}

func lastIndex(cmds []string, prefix string) int {
	for i := len(cmds) - 1; i >= 0; i-- {
		if strings.HasPrefix(cmds[i], prefix) {
			return i
		}
	}
	return -1
}

// A root disk on a mount class's folder: made from the image once (written aside, then moved in
// place); a disk already there (moved from another host) is booted as it is; a reset makes it
// afresh; deleting the silo on a host leaves the image (it's the volume's).
func TestRootDiskFile(t *testing.T) {
	ctx := context.Background()
	dir := "/var/lib/kevaso/volumes/uid-web/disk.root"
	file := dir + "/" + RootImage
	for _, exists := range []bool{false, true} {
		h := newFakeHost()
		r := newRuntime(t, h)
		h.answer = func(cmd string) (string, error) {
			switch {
			case cmd == "test -e "+file:
				if exists {
					return "", nil
				}
				return "", errors.New("exit 1")
			case strings.HasPrefix(cmd, "systemctl is-active"):
				return "inactive", errors.New("exit 3")
			}
			return "", nil
		}
		sp := spec("web")
		sp.DiskHostPath = dir
		if err := r.Create(ctx, sp); err != nil {
			t.Fatal(err)
		}
		cmds := h.commands()
		convert := indexOf(cmds, "qemu-img convert -O raw ")
		if exists != (convert < 0) {
			t.Fatalf("exists=%v: %v", exists, cmds)
		}
		if indexOf(cmds, "lvcreate") >= 0 {
			t.Fatalf("an LV for a root disk on a folder: %v", cmds)
		}
		if !exists {
			for _, want := range []string{"qemu-img resize -f raw " + file + ".new 21474836480", "mv -f " + file + ".new " + file} {
				if indexOf(cmds, want) < convert {
					t.Fatalf("lacks %q after the convert: %v", want, cmds)
				}
			}
		}
		md := string(h.files[NamesFor(sp.ID).Dir+"/meta-data"])
		if !strings.HasPrefix(md, "instance-id: uid-web-") {
			t.Fatalf("meta-data: %s", md)
		}
		if exists {
			before := len(h.commands())
			if err := r.Reset(ctx, sp); err != nil {
				t.Fatal(err)
			}
			if indexOf(h.commands()[before:], "qemu-img convert -O raw ") < 0 {
				t.Fatal("reset kept the old disk")
			}
			if string(h.files[NamesFor(sp.ID).Dir+"/meta-data"]) == md {
				t.Fatal("reset kept the instance-id: cloud-init wouldn't apply the new keys")
			}
		}
		if err := r.Delete(ctx, sp.ID); err != nil {
			t.Fatal(err)
		}
		for _, c := range h.commands() {
			if strings.Contains(c, file) && (strings.HasPrefix(c, "rm ") && !strings.Contains(c, ".new")) {
				t.Fatalf("deleted the volume's disk: %s", c)
			}
		}
	}
}
