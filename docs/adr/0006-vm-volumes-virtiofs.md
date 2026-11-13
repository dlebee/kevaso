# ADR 0006: Volumes on microVMs: local disks, virtiofs shares, and a root disk that moves

**Status:** accepted · **Date:** 2026-11-13

## Context

Container silos had volumes (M14): `local` ones, a device class's (attached, formatted once and
mounted by kevasod), and a mount class's (JuiceFS: mounted on the host by the plugin's node side).
`cloud-hypervisor` silos were refused any volume. Research E029 tried three ways to get a JuiceFS
volume into a Cloud Hypervisor guest and chose **virtiofs from a host mount** as the default (no
credential in the guest, shareable, a move is a remount), with **a disk image on the mount** as the
single-writer option, and **never a JuiceFS client in the guest** (metadata access is bucket access).
A VM's own disk is a thin LV on its host, so the VM was pinned to it.

## Decision

### How each volume reaches the guest

1. **A `local` volume is a thin LV of its own** (`kv-SILO-KEY`), attached to the VMM as an extra
   virtio disk with a serial (`kvKEY`), which the guest finds at `/dev/disk/by-id/virtio-kvKEY`. The
   guest formats it once (ext4, only if `blkid` finds nothing at all on it, the same rule kevasod
   uses for provider block volumes) and mounts it.
2. **Any volume that is a folder on the host is shared over virtiofs**: a mount class's (mounted by
   the node side), and also a device class's (mounted by kevasod). One rule for both, and the guest
   never sees a cloud block device it would have to trust. Per shared folder: one virtiofsd, its own
   unit, a `--fs tag=kvKEY,socket=…` device on the VMM, and `memory shared=on` (virtiofs needs the
   guest's memory shared with virtiofsd, E029).
3. **virtiofsd flags follow E029**: `--cache=auto --sandbox=chroot`, plus `--rlimit-nofile=0` (the
   unit sets `LimitNOFILE`, so virtiofsd needs no `CAP_SYS_RESOURCE` to raise it). DAX stays off
   (E029 saw no cache capability; to measure on real hardware).
4. **The guest mounts them**, by tag or by serial, through the runtime's Exec once the VM runs
   (before the guest helper and init steps), and writes them into a block of `/etc/fstab` the host
   owns (`nofail`, so a missing one never holds a boot), so later boots mount them on their own.
   Not cloud-init: the seed is built once (it carries the guest's host key, which the host deletes
   after) and its per-instance modules don't rerun.
5. **No hot-add.** A changed volume list restarts the VM (`kri.VolumeSetter`: a running silo with
   other volumes is stopped, the layout applied, started again). A volume dropped from the spec
   keeps its LV until the silo is deleted: re-adding it gets the same data back.

### virtiofsd: root, bounded, then chrooted with the least it needs

*Revised after the first real-machine run (Lima, Ubuntu 24.04, virtiofsd 1.10): the first design,
virtiofsd as its own user `kevaso-vfs`, never started. virtiofsd refuses `--sandbox=chroot` for any
user but root.*

virtiofsd runs as **root** in group `kevaso-vmm`, its unit bounding it (and, because virtiofsd
fails to apply its own capabilities otherwise, granting them ambient) to:

| Capability | Why |
|---|---|
| `CAP_CHOWN`, `CAP_FOWNER`, `CAP_DAC_OVERRIDE` | the guest's root owns and changes files of every user in its volume; virtiofsd does that for it on the host |
| `CAP_SETUID`, `CAP_SETGID` | it takes the guest caller's identity per request, so files get the guest's owners |
| `CAP_SYS_CHROOT` | `--sandbox=chroot`: before serving anything it chroots into the shared folder |
| `CAP_SETPCAP` | to drop its own capabilities and bounding set for serving |

It's told to leave out of its serving set what it would ask for by default and isn't granted:
`--modcaps=-fsetid:-mknod:-setfcap`. Once serving, chrooted into its share, it holds **only
`chown, dac_override, fowner, setgid, setuid`**, with empty bounding and ambient sets: it can't
chroot out again or get anything back (checked on the host, `TestVMVolumes`).

Left out on purpose: `CAP_MKNOD` (no device nodes from a guest on the host's disks),
`CAP_SETFCAP` and `CAP_FSETID` with `RestrictSUIDSGID=yes` (no file capabilities, no set-uid or
set-gid files: a volume is data, never a way into the host), `CAP_SYS_ADMIN` (no namespaces, no
mounts). The unit also has no network (`PrivateNetwork=yes`, only `AF_UNIX`), no devices, a
read-only system, of `/var/lib/kevaso` (the control plane's data, every silo's volumes) and
`/var/lib/kevaso-silos` only the shared folder and its socket's folder (`TemporaryFileSystem=…:ro`
plus `BindPaths=`), an empty `/run` (kevasod's admin socket, the plugins' sockets), and no
`/root`, `/etc/kevaso`, `/etc/ssh` or images. No `ProcSubset=pid`: virtiofsd reads
`/proc/sys/fs/nr_open` at start even with `--rlimit-nofile=0`.

Why root is no worse than a user of its own: `CAP_SETUID`, which a file server acting for the
guest's users needs, lets any user become root, so `kevaso-vfs` would have been root in all but
name, and without the chroot. What contains it is the bounding set, the unit's namespace and the
chroot. Why not the VMM's user: then a guest that took over its VMM would be its own file server.
Its socket is a **socket unit's** (`kevaso-silo-SHORT-fs-KEY.socket`), `0660 root:kevaso-vmm`, in
the silo's own directory (`SILO/vfs/KEY.sock`), which only that silo's VMM can see, so only that
VMM connects; virtiofsd gets it as `--fd=3` and never sees the folder. virtiofsd serves one
connection and exits when it ends, and a reboot inside the guest is the VMM reconnecting to the
same socket: systemd holds the socket throughout and starts a virtiofsd for each connection. (Both
simpler ways failed on a real host: with `Restart=no` the reconnect timed out; with virtiofsd
restarted and making its own socket, which it binds `0700` and only then chowns, the VMM
reconnected in between and died of `EACCES`.)

Alternative left for later: unprivileged virtiofsd in a user namespace (`--sandbox=namespace` with
uid maps); it needs subuid ranges per silo and changes the owners files have on the host.

### Order: start, stop, move

- **Start:** each share's socket unit afresh (any virtiofsd left from the last boot stopped first),
  wait for its socket, then the TAP, then the VMM, whose connection starts virtiofsd.
- **Stop:** ask the guest to power off; then stop the VMM; then each share's socket unit (so nothing starts virtiofsd again) and virtiofsd. Only then is
  a shared folder free (virtiofsd holds it open). `kri.Runtime.Stop` and `Delete` both end there,
  and the agent unmounts volumes only after `Stop`/`Delete` returned, so the volume's `mounted:
  false`, which a move's handoff waits for (`internal/moves`, the volumes controller), is true when
  it's written. Both are pure plans (`StartPlan`, `StopPlan`), unit-tested for order.
- **Reset** keeps the volumes (LVs and shares), re-makes the root disk.

### A root disk that moves: `disk.class` on a mount class

A `cloud-hypervisor` silo with `disk.class` set to a **mount** class gets its root disk as an
**image file on a volume of that class** (`v1.DiskVolume`, volume name `disk.root`, which no
person-named volume can have; sized `disk.size`). The volumes controller creates it and points it at
the silo's host like any mount-class volume; the node side mounts it; the VMM boots
`…/volumes/UID/disk.root/root.raw`, with that one folder bound into its unit. The image is made
once (written as `root.raw.new`, grown, then renamed), reused when it's already there (the silo came
from another host), re-made by a reset, and never deleted by the runtime (it's the volume's: deleting
the silo deletes the volume through its plugin). `moves.Of` already counted `disk.class`, so such a
silo with only global volumes is **movable Anywhere**, and `onHostLoss: Move` is admitted.

**Single writer, enforced** by what already holds for mount-class volumes: the control plane
points the volume at one host at a time (`attachedTo`), and a move waits until the old host has
stopped the VM, its virtiofsd daemons, and unmounted the volume (`mounted: false`) before the new
host mounts it. Cloud Hypervisor also locks its disk images, and JuiceFS makes POSIX locks hold
across clients, which would catch a second VMM on another host; that part is on the real-machine
checklist, not relied on.

A new seed on the new host is a new cloud-init instance (`instance-id` includes the new host
key's hash), so the moved disk takes the new host's exec key (and only it: `authorized_keys` is
rewritten), host key, and address.

A device class for the root disk is refused for now (it would need the agent to hand the VMM the
block device instead of a folder); admission says so.

## Consequences

- `kri` gains `VolumeSetter`, `GuestVolumes` and `Spec.DiskHostPath`; `sdk/kri/fake.VM` records
  what a VM was given and what its guest mounted.
- The host needs Ubuntu's `virtiofsd` package (`Install` adds it).
- The real-machine checks this ADR depends on are in `docs/notes/virtiofs-real-machine-checklist.md`.
- Still open: volume sizes on `local` VM disks don't grow (an LV is made once); hot-add; DAX; a
  device-class root disk; the node side's FUSE mounts vanishing under a running virtiofsd when the
  plugin's daemons die (virtiofsd then serves a dead mount until the silo restarts).
