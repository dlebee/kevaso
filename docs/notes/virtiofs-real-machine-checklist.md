# Real-machine checklist: virtiofs into microVMs, and JuiceFS behaviours we assumed

Everything in ADR 0006 and the JuiceFS provider was built and tested with fakes. These are the
checks a Lima VM (nested KVM, as in E029) or a bare-metal host must pass before M14's storage half
counts as done on real machines. Run them as root on a host where `kvoadm` installed a worker with
the `cloud-hypervisor` runtime, the JuiceFS provider's both sides (with `--manifest
kevaso-plugin.json --yes`), a metadata database and a bucket. Record each result (pass or what
happened) in a research experiment, never here.

Names below: class `juicefs`, namespace `notes`. `UID` is the silo's UID (`kvo get silo vm -o
json`), `SHORT` its 10-hex-digit name on the host (the `kevaso-silo-SHORT` unit).

## 1. JuiceFS: the two assumed behaviours, and quotas

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
plugin's unit). Also check it was mounted with `allow_other` (virtiofsd runs as `kevaso-vfs`, not
root, and FUSE refuses other users without it):

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
systemctl restart kevaso-plugin-juicefs.service && grep -c fuse.juicefs /proc/self/mountinfo
```

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
grep Cap /proc/$(pgrep -f "shared-dir=/var/lib/kevaso/volumes/UID/home")/status
```

```bash
ls -l /var/lib/kevaso-silos/SHORT/vfs/
```

Pass: one virtiofsd per shared folder, running as `kevaso-vfs` in group `kevaso-vmm` with
`--cache=auto --sandbox=chroot`; its effective capabilities decode (`capsh --decode=…`) to exactly
`cap_chown,cap_dac_override,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot`; its socket is `srwxrwx---
kevaso-vfs kevaso-vmm`. If virtiofsd refuses to start as a non-root user with `--sandbox=chroot`,
record the error: the fallback is `User=root` with the same bounding set (ADR 0006).

### 2b. The guest side

```bash
kvo exec vm -- findmnt /home/data /scratch
```

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
finds nothing).

What the guest must not be able to do through the share:

```bash
kvo exec vm -- sh -c 'cp /bin/sh /home/data/sh && chmod u+s /home/data/sh; ls -l /home/data/sh'
```

```bash
kvo exec vm -- mknod /home/data/dev b 8 0
```

Pass: the set-uid bit doesn't stick (or `chmod` fails) and `mknod` fails.

### 2c. Reboots, restarts and a volume change

```bash
kvo exec vm -- reboot
```

Pass: once Ready again, both volumes are mounted again (from fstab, before the agent's next pass).
Then add a volume to the spec and apply: the silo restarts (`Ready=False VolumesChanged`), comes
back with the new mount, and `/scratch` still holds what it held.

### 2d. Stop order and the move handoff

```bash
journalctl -u kevaso-silo-SHORT.service -u 'kevaso-silo-SHORT-fs-*' --since -5m -o short-precise | grep -E 'Stopped|Deactivated'
```

Run that after `kvo move silo vm --to hv-2` (with the local `scratch` volume removed first: it pins
the silo). Pass: the VMM stopped before its virtiofsd, both before the node side's unmount (the
plugin's journal: `unmounted /var/lib/kevaso/volumes/UID/home`), and that before hv-2's node side
mounted it; on hv-2 the guest sees the same files.

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
   record the error).
2. Write a file in the guest, `kvo move silo vm --to hv-2`: the VM boots on hv-2 from the same image
   (the file is there), `kvo exec` works (the new host's exec key was applied: a new instance-id),
   and the old host's exec key is no longer in `/home/kevaso/.ssh/authorized_keys`.
3. Single writer: on hv-1, while the VM runs on hv-2, mount the volume by hand and start a second
   VMM on the image:

   ```bash
   /opt/kevaso/cloud-hypervisor/cloud-hypervisor --kernel /dev/null --disk path=/mnt/probe/root.raw
   ```

   Pass: Cloud Hypervisor refuses the image (it's locked), i.e. JuiceFS carried the lock across
   hosts. If it opens it, Kevaso's only guard is the handoff (ADR 0006): record that.
4. Delete the silo: hv-2 stops it and unmounts, and the volume's folder is gone from the class's
   root on the control plane.
