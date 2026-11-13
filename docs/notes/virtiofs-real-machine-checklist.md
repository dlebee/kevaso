# Real-machine checklist: virtiofs into microVMs, and JuiceFS behaviours we assumed

Everything in ADR 0006 and the JuiceFS provider was built and tested with fakes. These are the
checks a Lima VM (nested KVM, as in E029) or a bare-metal host must pass before M14's storage half
counts as done on real machines. Run them as root on a host where `kvoadm` installed a worker with
the `cloud-hypervisor` runtime, the JuiceFS provider's both sides (with `--manifest
kevaso-plugin.json --yes`), a metadata database and a bucket. Record each result (pass or what
happened) in a research experiment, never here.

**Status (2026-11-13, Lima on an M-series Mac, Ubuntu 24.04, virtiofsd 1.10, Cloud Hypervisor
v54.1):** §2 and §3 ran end to end as `test/e2e` `TestVMVolumes` and `TestVMMoves`, with the test
plugin `test/plugins/hostdir` (a folder as a mount class, bind-mounted by its node side; shared
between two hosts over NFS 4.2 for §2d and §3) in place of JuiceFS. Each line below is marked
**✓** (passed as written), **corrected** (what real hosts did instead, and the fix), or
**not run here** (JuiceFS itself, proven on Linode by another branch). What the runs did is in
the tests and their logs; record it in a research experiment.

Names below: class `juicefs`, namespace `notes`. `UID` is the silo's UID (`kvo get silo vm -o
json`), `SHORT` its 10-hex-digit name on the host (the `kevaso-silo-SHORT` unit).

## 1. JuiceFS: the two assumed behaviours, and quotas

*§1 not run here (JuiceFS on Linode).*

### 1a. `juicefs status` on a fresh database says "not formatted"

The controller side formats only when `juicefs status` fails with output containing `not formatted`
(`juicefs/runner.go`, `Exec.Status`). On an empty database:

```bash
juicefs status "postgres://juicefs@DBHOST:5432/juicefs-fresh"; echo "exit $?"
```

Pass: a non-zero exit and the words `not formatted` in the output. If the wording differs, change
`Exec.Status` (and its test) to match what 1.4 prints, and check a database that's merely down
(`systemctl stop postgresql`) is **not** reported as "not formatted" (it would then be formatted
again: `--no-update` stops that from changing anything, but it must still be an error).

### 1b. `juicefs mount --subdir` of a folder the controller made

The controller side keeps the class's root mounted and makes `volumes/UID/NAME` in it; the node
side mounts only that folder. After `kvo apply` of a silo with a `juicefs` volume:

```bash
ls -la /var/lib/kevaso-provider-juicefs/mnt/juicefs/volumes/
```

```bash
grep fuse.juicefs /proc/self/mountinfo
```

```bash
echo hello > /var/lib/kevaso/volumes/UID/home/probe && cat /var/lib/kevaso-provider-juicefs/mnt/juicefs/volumes/UID/home/probe
```

Pass: the node side's mount is at `/var/lib/kevaso/volumes/UID/home`, its root is the volume's
folder (nothing above it is visible from there), the probe file shows up in the controller's view,
and the mount is in the **host's** mount table (seen from a plain root shell, not only inside the
plugin's unit). Also check it was mounted with `allow_other` (FUSE refuses every other user
without it: virtiofsd runs as root, like the node side, but a container silo's own users don't):

```bash
grep fuse.juicefs /proc/self/mountinfo | grep -c allow_other
```

If `allow_other` is missing, add `-o allow_other` to `MountArgs` for the node side.

### 1c. Quotas

```bash
juicefs quota get "postgres://juicefs@DBHOST:5432/juicefs" --path /volumes/UID/home
```

Pass: the capacity is the volume's `size` rounded up to GiB. Grow `size` in the silo's spec and run
it again: the new capacity, the silo still running. Then fill past it:

```bash
kvo exec vm -- dd if=/dev/zero of=/home/fill bs=1M count=100000
```

Pass: `dd` fails with "Disk quota exceeded" near the quota, and `kvo describe silo vm` shows no
`sizeNotEnforced`.

### 1d. The node side survives its own restart

```bash
systemctl restart kevaso-plugin-juicefs-node.service && grep -c fuse.juicefs /proc/self/mountinfo
```

**Corrected:** the node side's unit is `kevaso-plugin-NAME-node.service`. Both sides used to be
`kevaso-plugin-NAME.service`, so on a control plane that is also a worker the node side's install
replaced the controller side (fixed in `kvoadm plugin`, `PluginUnitName`).

Pass: the same number of mounts before and after (the unit has `KillMode=process`), and the silo's
files are still readable.

### 1e. The controller side under its unit

Pass: `systemctl status kevaso-plugin-juicefs.service` on the control plane is active, its class
roots are mounted inside its namespace only (`nsenter -t PID -m grep fuse.juicefs /proc/self/mountinfo`
shows them, a plain root shell doesn't), and `/var/lib/kevaso-provider-juicefs/juicefs.log` exists
(the default `/var/log/juicefs.log` is read-only to it).

## 2. virtiofs end to end

Apply a microVM with a JuiceFS volume and a local one:

```yaml
apiVersion: kevaso/v1
kind: Silo
metadata: { name: vm, namespace: notes }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 2, memory: 2Gi }
  volumes:
    - { name: home, class: juicefs, size: 5Gi, mountPath: /home/data }
    - { name: scratch, size: 2Gi, mountPath: /scratch }
```

### 2a. The host side

```bash
systemctl status 'kevaso-silo-SHORT-fs-*'
```

```bash
ps -o user,group,cmd -C virtiofsd
```

```bash
grep Cap /proc/$(pgrep -x virtiofsd)/status
```

```bash
readlink /proc/$(pgrep -x virtiofsd)/root
```

```bash
ls -l /var/lib/kevaso-silos/SHORT/vfs/
```

**Corrected** (no VM with a virtiofs volume booted as first written). virtiofsd 1.10 refuses
`--sandbox=chroot` as any user but root; asks for capabilities it isn't granted and exits ("can't
apply the child capabilities") unless they're dropped with `--modcaps` (which needs `CAP_SETPCAP`)
and start ambient; reads `/proc/sys/fs/nr_open` even with `--rlimit-nofile=0` (so no
`ProcSubset=pid`); binds its socket `0700` and changes it only after, which the VMM's reconnect on
a guest reboot raced. ADR 0006 now has the fixed design. Pass, **✓** as now written:

- one socket unit and one virtiofsd per shared folder, `kevaso-silo-SHORT-fs-KEY.socket` and
  `.service`, both active; virtiofsd as `root root` with `--fd=3 --shared-dir=… --cache=auto
  --sandbox=chroot --rlimit-nofile=0 --modcaps=-fsetid:-mknod:-setfcap`;
- serving, its capabilities decode (`capsh --decode=…`) to exactly
  `cap_chown,cap_dac_override,cap_fowner,cap_setgid,cap_setuid` effective and permitted, with
  empty bounding and ambient sets, and its root is the shared folder;
- its socket is `srw-rw---- root kevaso-vmm`;
- in its mount namespace (`nsenter -t PID -m`), `/var/lib/kevaso` and `/var/lib/kevaso-silos` hold
  only the share, and `/root`, `/home`, `/etc/kevaso`, `/etc/ssh`, the images and `/run` are empty
  (`/run` has only systemd's empty `systemd/incoming`); its network namespace has only `lo`.

### 2b. The guest side

```bash
kvo exec vm -- findmnt /home/data
```

```bash
kvo exec vm -- findmnt /scratch
```

(One path per `findmnt`: given two, it reads them as a source and a target and prints nothing.)

```bash
kvo exec vm -- grep -A3 "kevaso volumes: begin" /etc/fstab
```

```bash
kvo exec vm -- sh -c 'echo from-guest > /home/data/g && chown 1000:1000 /home/data/g && ls -ln /home/data/g'
```

```bash
ls -ln /var/lib/kevaso/volumes/UID/home/g
```

Pass: `/home/data` is `virtiofs` (source `kvKEY`), `/scratch` is `ext4` on `/dev/vdX` found by its
serial, the file the guest wrote is on the host with owner 1000:1000, and none of the bucket or
database credentials are anywhere in the guest (`kvo exec vm -- grep -r SECRET_KEY /etc /proc/*/environ`
finds nothing). **✓**, plus: a file the host writes is in the guest with its owner; a file the
guest's root makes is `0:0` on the host (**corrected**: it was group `kevaso-vmm`, virtiofsd's own,
until virtiofsd ran as `Group=root`); no host path (`/srv/…`, `/var/lib/kevaso`, the plugins'
sockets) is in the guest's mount table or fstab.

Careful when checking for a credential: don't put the value on a `kvo exec` command line. sudo
logs the command line into the guest's journal and auth.log and sets `SUDO_COMMAND`, so the check
would plant what it looks for. Give it on stdin.

What the guest must not be able to do through the share:

```bash
kvo exec vm -- sh -c 'cp /bin/sh /home/data/sh && chmod u+s /home/data/sh; ls -l /home/data/sh'
```

```bash
kvo exec vm -- mknod /home/data/dev b 8 0
```

Pass: the set-uid bit doesn't stick (or `chmod` fails) and `mknod` fails. **✓** (both
"Operation not permitted"; nothing on the host).

### 2c. Reboots, restarts and a volume change

```bash
kvo exec vm -- reboot
```

Pass: once Ready again, both volumes are mounted again (from fstab, before the agent's next pass).
**Corrected, then ✓:** the VM died on the reboot. Cloud Hypervisor reboots in place and reconnects
to the share's socket, and virtiofsd had exited with the first connection (`Restart=no`: "Timed
out waiting for vhost-user connection"; then, restarted but making its own socket: "Permission
denied"). A socket unit now holds the socket and starts a virtiofsd per connection. Check with the
guest's `/proc/sys/kernel/random/boot_id` that it really rebooted.
Then add a volume to the spec and apply: the silo restarts (`Ready=False VolumesChanged`), comes
back with the new mount, and `/scratch` still holds what it held. **✓**, and its file system is
the same (`blkid` UUID), also after `kvo reset silo vm` (a fresh root disk, both volumes and their
data kept). Deleting the silo leaves no LV, unit, virtiofsd, mount or silo folder on the host,
and the plugin deletes the volume's folder.

### 2d. Stop order and the move handoff

```bash
journalctl -u 'kevaso-silo-SHORT*' -u kevaso-plugin-juicefs-node.service --since -5m -o short-precise | grep -E 'Stopped|Deactivated|unmounted'
```

Run that after `kvo move silo vm --to hv-2` (with the local `scratch` volume removed first: it pins
the silo). Pass: the VMM stopped before its virtiofsd, both before the node side's unmount (the
plugin's journal: `unmounted /var/lib/kevaso/volumes/UID/home`), and that before hv-2's node side
mounted it; on hv-2 the guest sees the same files. **Corrected:** virtiofsd usually ends first, by
itself, when the guest powers off and drops its connection; what matters, and holds, is that the
VMM, the share's socket unit (after the VMM, so nothing starts virtiofsd again) and virtiofsd have
all ended before the unmount. Seen on delete (`TestVMVolumes`); for moves see §3.

## 3. A root disk on JuiceFS (`disk.class: juicefs`)

```yaml
spec:
  runtime: cloud-hypervisor
  disk: { class: juicefs, size: 20Gi }
  availability: { onHostLoss: Move }
```

Pass, in order:

1. `ls -l /var/lib/kevaso/volumes/UID/disk.root/` shows `root.raw` (sparse, 20 GiB apparent) owned by
   `kevaso-vmm`, and the VMM's unit can open it through `BindPaths=` under `TemporaryFileSystem=
   /var/lib/kevaso:ro` (the VM boots; if systemd can't bind a path under a tmpfs it just mounted,
   record the error). **Corrected, then ✓:** the bind works and the VM boots, but the image was
   `-rw-r--r-- kevaso-vmm root` (qemu-img under kevasod's umask): the whole disk readable by any
   user of every host sharing the class. It's made `-rw------- kevaso-vmm kevaso-vmm` before it's
   put in place now.
2. Write a file in the guest, `kvo move silo vm --to hv-2`: the VM boots on hv-2 from the same image
   (the file is there), `kvo exec` works (the new host's exec key was applied: a new instance-id),
   and the old host's exec key is no longer in `/home/kevaso/.ssh/authorized_keys`. **Corrected,
   then ✓** (two moves, w1 → w2 → w1, both VMM units watched every second: never both active; the
   new one started 0–5 s after the old one stopped; the root disk's file and a virtiofs volume's
   file both there): the old key *was* still there when the silo was Running, until cloud-init's
   final stage replaced the file; a `bootcmd` replaces it first now, at every boot.
3. Single writer: on hv-1, while the VM runs on hv-2, mount the volume by hand and start a second
   VMM on the image:

   ```bash
   /opt/kevaso/cloud-hypervisor/cloud-hypervisor --kernel /dev/null --disk path=/mnt/probe/root.raw
   ```

   Pass: Cloud Hypervisor refuses the image (it's locked), i.e. JuiceFS carried the lock across
   hosts. If it opens it, Kevaso's only guard is the handoff (ADR 0006): record that. **✓ over NFS
   4.2** (`--disk path=…,image_type=raw,readonly=on`, read-only so a failed check can't harm the
   running VM): "Failed to get Read lock for disk image … The file is already locked". That shows
   Cloud Hypervisor's lock reaching across hosts on NFS; it says nothing about JuiceFS, whose own
   locks are still to check here.
4. `onHostLoss: Move` (not in the first list): stop kevasod on the VM's host and keep it down.
   **Corrected, then ✓:** a cluster's only silo was never moved (the scheduler skipped its later
   changes after placing it once; fixed in the silo controller). Now: kevaso-fence stopped the VM
   ~57 s after kevasod stopped, the VM was up on the other host at ~71 s, the files were there,
   the lost host (agent down) had no virtiofsd left but kept its two mounts until its kevasod came
   back, when it unmounted them and started nothing.
5. Delete the silo: hv-2 stops it and unmounts, and the volume's folder is gone from the class's
   root on the control plane. **✓**
