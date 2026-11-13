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

### virtiofsd: its own user, the least it needs

virtiofsd runs as **`kevaso-vfs`** (not root, not the VMM's user), in group `kevaso-vmm`, with
exactly these capabilities, bounding and ambient:

| Capability | Why |
|---|---|
| `CAP_CHOWN`, `CAP_FOWNER`, `CAP_DAC_OVERRIDE` | the guest's root owns and changes files of every user in its volume; virtiofsd does that for it on the host |
| `CAP_SETUID`, `CAP_SETGID` | it takes the guest caller's identity per request, so files get the guest's owners |
| `CAP_SYS_CHROOT` | `--sandbox=chroot`: once started it sees nothing but the shared folder |

Left out on purpose: `CAP_MKNOD` (no device nodes from a guest on the host's disks),
`CAP_SETFCAP` and `CAP_FSETID` with `RestrictSUIDSGID=yes` (no file capabilities, no set-uid or
set-gid files: a volume is data, never a way into the host), `CAP_SYS_ADMIN` (no namespaces, no
mounts). The unit also has no network (`PrivateNetwork=yes`, only `AF_UNIX`), no devices, a
read-only system, and of `/var/lib/kevaso` (the control plane's data, every silo's volumes) and
`/var/lib/kevaso-silos` only the shared folder and its socket's folder (`TemporaryFileSystem=…:ro`
plus `BindPaths=`).

Why not root: virtiofsd parses everything a guest sends; a bug there should land in a user that
owns nothing. Why not the VMM's user: then a guest that took over its VMM would be its own file
server, with these capabilities. Why the VMM's group: its socket is `0770 kevaso-vfs:kevaso-vmm`
in the silo's own directory (`SILO/vfs/KEY.sock`), which only that silo's VMM can see (the VMM
already sees only its own silo directory), so only that VMM connects. Alternative left for later:
unprivileged virtiofsd in a user namespace (`--sandbox=namespace` with uid maps); it needs subuid
ranges per silo and changes the owners files have on the host.

### Order: start, stop, move

- **Start:** each virtiofsd afresh (`systemctl restart`: one that served the last boot has exited
  with its VMM), wait for its socket, then the TAP, then the VMM.
- **Stop:** ask the guest to power off; then stop the VMM; then the virtiofsd units. Only then is
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
- The host needs Ubuntu's `virtiofsd` package and a `kevaso-vfs` user (`Install` adds both).
- The real-machine checks this ADR depends on are in `docs/notes/virtiofs-real-machine-checklist.md`.
- Still open: volume sizes on `local` VM disks don't grow (an LV is made once); hot-add; DAX; a
  device-class root disk; the node side's FUSE mounts vanishing under a running virtiofsd when the
  plugin's daemons die (virtiofsd then serves a dead mount until the silo restarts).
