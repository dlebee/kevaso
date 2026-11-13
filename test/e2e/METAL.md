# The metal suite: one dedicated machine

End-to-end tests on one bare-metal machine that already exists: KVM, a real external IP, fresh
Ubuntu 24.04. It is the only environment with both microVMs and an address the internet reaches,
so it proves what Lima (no real external IP) and Linode (no KVM) can't.

- Driver: `testbed/remote`. It creates nothing. It reaches the machine over SSH with one key, and
  only after the host key matches a fingerprint you pinned. "Deleting" the machine means resetting
  it to clean.
- Tests: `test/e2e/metal_*_test.go`, build tag `metal`. Without the environment below, every test
  skips and names the missing variables.
- One cluster per `go test` run: the first test resets the machine, then runs `kvoadm init`
  (control plane and worker in one, `cloud-hypervisor` and `docker`). Each test removes its own
  namespace when it ends. The run's last step is the reset again, and it fails if its checklist
  finds anything left.

## The machine we have (handed over 2026-11-13)

- **Login `ubuntu` with passwordless sudo**, not root: set `KEVASO_METAL_HOST=ubuntu@ADDRESS`.
  The driver and kvoadm both work through sudo; nothing on the machine's sshd needs changing.
- **Ubuntu 26.04.1, kernel 7.0, x86_64.** Kevaso is tested on 24.04. `kvoadm init` only warns
  ("tested on Ubuntu 24.04; others may work") and carries on. Things that may differ on 26.04
  and would show up first in setup or the first microVM test: the runtimes' package names
  (`qemu-utils`, `cloud-image-utils`, `lvm2`, `thin-provisioning-tools`, `nftables`,
  `iproute2`, `iputils-arping`, `virtiofsd`, `docker.io`), Docker's dependencies (the reset
  purges the watched ones and runs autoremove; the baseline comparison names anything left),
  and the kernel module `nf_conntrack_bridge`. The silos' own image stays Ubuntu 24.04
  (`ubuntu-24.04` is the guest, whatever the host runs), and TestMetalImages' inline disk is
  the 24.04 release image.
- **16 threads, 31 GB RAM, root on software RAID (`/dev/md3`), 440 GB free, no spare disk.**
  The volume group lives on the 60 GB loop file `/var/lib/kevaso-storage.img` (`--loop-storage`),
  which is the only kind the reset will remove. Volume tests run on it; nothing is skipped.
- **One interface with the external IPv4 on it, plus IPv6, no internal IP.** Leave
  `KEVASO_METAL_INTERNAL_IP` unset: TestMetalModel then checks that an `[internal]` port is
  refused with the reason. IPv6 isn't used by Kevaso or tested; ports opened on the external IP
  are IPv4 only, so a scan over IPv6 finds only sshd.
- **Only sshd listens, no Docker, ufw inactive:** a fresh baseline will be recorded. With ufw
  inactive nothing on the machine filters the suite's ports or DNS on 53.
- **ED25519 host key fingerprint, as read on the provider's console:**
  `SHA256:Ouz3muE8Y0/yiesaaP5dqkwtWWWZYpwlLURO9vMCbL8`. Put it in `KEVASO_METAL_HOSTKEY`. If the
  machine is reinstalled, read it again: don't update it from what the machine offers.

## Once, when the machine is handed over

The machine must be:

- freshly installed Ubuntu (24.04 is what Kevaso is tested on; see "The machine we have" for 26.04), with Docker not installed;
- KVM capable (`/dev/kvm` present);
- its external IP on one of its interfaces. Behind 1:1 NAT, `[external]` ports can't work, and
  the suite refuses to start;
- free space on `/`: at least 100 GB (a 60 GB loop file for the silos' volume group, plus
  images);
- open from this Mac through any provider firewall, on the ports listed further down, plus 22.

**1. Put the public key on the machine.** Use the provider's console or its "SSH key at
install" option, never a password over SSH. The key's public half is here:

```bash
cat ~/.ssh/kevaso-testbed_ed25519.pub
```

On the machine's console, as root, add that line to `/root/.ssh/authorized_keys`.

**2. Read the host key's fingerprint on the console.** Use the provider's web console, KVM or
serial console, not SSH. Don't take it from `ssh-keyscan` or from the first `ssh` prompt: that is
exactly the trust on first use the pin exists to avoid. On the console, as root:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Copy the `SHA256:…` field. It must be the ED25519 key, because the driver and kvoadm ask for
ED25519. If the machine is reinstalled, read it again.

**3. Set the environment** in the shell that runs the tests. The values are examples:

```bash
export KEVASO_METAL_HOST=root@203.0.113.10
```

```bash
export KEVASO_METAL_KEY=~/.ssh/kevaso-testbed_ed25519
```

```bash
export KEVASO_METAL_HOSTKEY=SHA256:paste-the-fingerprint-from-the-console
```

```bash
export KEVASO_METAL_EXTERNAL_IP=203.0.113.10
```

Optional variables:

| Variable | What it is for |
|---|---|
| `KEVASO_METAL_INTERNAL_IP` | The machine's address on a private network, if it has one. TestMetalModel then opens an `[internal]` port there; without it, it checks that one is refused |
| `KEVASO_METAL_HOSTNAME` | A public DNS name whose A record is the external IP. TestMetalIngress then gets a certificate from Let's Encrypt's **staging** directory over HTTP-01 |
| `KEVASO_METAL_ACME_EMAIL` | The ACME account's email address for that certificate (left out when unset) |
| `KEVASO_METAL_MY_IP` | This Mac's public IPv4, overriding what the machine sees as the SSH client's address (read without sudo). Only needed if this Mac reaches the machine's ports from another address than its SSH session (a VPN for SSH only) |

`KEVASO_METAL_HOST` is `[USER@]ADDRESS[:PORT]`, with user root and port 22 by default. A
non-root user needs passwordless sudo: the driver runs every command through `sudo -n sh -c`,
and kvoadm does the same for any user other than root. sudo logs each command line, so the
tests never put a whole secret on one (they build it from two halves on the machine).

**4. First contact: record the baseline and check the machine is clean.** Run this from the core
worktree:

```bash
go test -tags metal -run '^TestMetalReset$' -v -count=1 ./test/e2e/
```

This connects (the pin is checked before the key is offered) and records the fresh machine's
state in `/var/lib/kvt-baseline/state`: its packages, its nftables tables and IP forwarding. A
baseline is recorded only if the checklist passes, so a machine that already has Kevaso or Docker
on it is refused. Then it runs the reset and the checklist. If the test says the host key isn't
trusted, stop and read the fingerprint on the console again. Don't change the pin to whatever
the machine offers.

## Running

The suite takes long: run it in the background and watch the log. A whole run takes roughly
1.5 to 2.5 hours: setup is about 10 minutes, the microVM tests 10 to 20 minutes each, and the
lease test about 3 minutes.

One test (setup, the test, the final reset):

```bash
go test -tags metal -run '^TestMetalModel$' -v -count=1 -timeout 90m ./test/e2e/ 2>&1 | tee /tmp/metal-model.log
```

The tests are `TestMetalModel`, `TestMetalNames`, `TestMetalImages`, `TestMetalSecrets`,
`TestMetalIngress`, `TestMetalProbes`, `TestMetalLeases`, `TestMetalPanes`, `TestMetalFence` and
`TestMetalVolumes`. Each one can run alone.

All of them, one cluster for the whole run:

```bash
go test -tags metal -run '^TestMetal' -v -count=1 -timeout 5h ./test/e2e/ 2>&1 | tee /tmp/metal-all.log
```

Don't add `-parallel` or `t.Parallel`: the tests share the machine's ports and its one kevasod,
and TestMetalFence stops kevasod.

To keep the cluster and the namespaces after a run (for looking around with the kvo context the
run wrote under its temporary HOME, printed in the log), set `KEVASO_E2E_KEEP=1`. Reset the
machine afterwards:

```bash
go test -tags metal -run '^TestMetalReset$' -v -count=1 ./test/e2e/
```

## The reset

`remote.Driver.Reset` runs `kvoadm reset`'s plan (`internal/hostreset`, unit-tested in order)
against the suite's own baseline, then the checklist, plus the suite's own files (`/var/lib/kvt-inet`). Every step is tried even if one fails.

1. It stops and disables kevasod, the fence and every `kevaso-*` and `kvt-*` unit, then kills
   whatever is left (kevasod, cloud-hypervisor, ch-remote, virtiofsd).
2. It removes every container, volume and image, then stops Docker.
3. It deletes the links (`kvbr*`, `kvt*`, `kevaso*`, `docker0`), the addresses labelled `:kv`,
   and the nftables tables the baseline didn't have. IP forwarding goes back to the baseline's
   value.
4. It removes the `kevaso` volume group, but only when every physical volume in it is a loop
   device on `/var/lib/kevaso-storage.img`. A volume group on a real disk is refused and left
   alone. Then it detaches the loop device and deletes the file.
5. It purges the packages Kevaso's runtimes install that the baseline didn't have (Docker and its
   dependencies, qemu-utils, cloud-image-utils, virtiofsd and others), then runs autoremove.
6. It unmounts anything under Kevaso's paths and removes Kevaso's files: binaries, units,
   `/etc/kevaso`, `/var/lib/kevaso*`, `/opt/kevaso`, `/run/kevaso*`, Docker's directories. It also
   removes the tests' `/etc/hosts` lines (ending `# kvt-e2e`) and the `kevaso-*` users and groups.

The checklist fails, naming each leftover, when any of these is still there:

- a unit, a process, a file, a link, a `:kv` address or a mount;
- a `kevaso*` table, the volume group, its device-mapper devices or its loop device;
- Docker, a `kevaso-*` user, or a test line in `/etc/hosts`;
- anything listening on the suite's ports except on loopback;
- a difference from the baseline: a watched package still installed, a baseline package gone, an
  extra table, or IP forwarding changed.

The reset never touches sshd, the machine's own firewall tables, its disks, or packages that
aren't Kevaso's. A kernel that unattended-upgrades installed is left alone.

### The same, as a Kevaso command: `kvoadm reset`

The product way to return the box to clean is `kvoadm reset`. It is the same plan. It works
from the install record that `kvoadm init` wrote on the machine (`/var/lib/kevaso-install/record`)
rather than the suite's baseline. Use it after a run kept with `KEVASO_E2E_KEEP`, or whenever
the box should be handed back without a reinstall. Look first (it changes nothing):

```bash
go run ./cmd/kvoadm reset "$KEVASO_METAL_HOST" --ssh-key "$KEVASO_METAL_KEY" --host-key "$KEVASO_METAL_HOSTKEY" --dry-run
```

It lists what it will remove and what it keeps. Then run it for real. It asks you to type
`yes`:

```bash
go run ./cmd/kvoadm reset "$KEVASO_METAL_HOST" --ssh-key "$KEVASO_METAL_KEY" --host-key "$KEVASO_METAL_HOSTKEY"
```

To see whether the box is clean without changing anything (after `kvoadm reset`, for
example), run the checklist and the baseline comparison alone:

```bash
go test -tags metal -run '^TestMetalCheck$' -v -count=1 ./test/e2e/
```

After `kvoadm reset` it reports only `/var/lib/kvt-inet`, the suite's own stand-in internet,
which `TestMetalReset` removes. Everything Kevaso installed matches the fresh machine.

It refuses while silos are still on the box. Delete their namespaces first, or add `--force`,
which destroys them. On this box the volume group is on the loop file, so `--wipe-storage` is
never needed. Afterwards `TestMetalReset` passes as well: it removes the suite's own files and
checks a superset of kvoadm's checklist.

A cluster installed by a kvoadm built before the install record existed has no record. That
includes the runs on 2026-11-13, which used a test binary built earlier. `kvoadm reset` then
says `NO INSTALL RECORD`, uses its fixed lists and purges no package. Docker and the runtimes'
packages stay, so on this box `TestMetalReset` still has to purge them against the suite's
baseline.

## What each test leaves listening on the external IP

Each test opens these ports while it runs and closes them when it ends. Whatever runs on the
machine, 6443 (the API, mutual TLS) is open from the first test to the final reset.

| Test | Ports on the external IP | What answers |
|---|---|---|
| setup (whole run) | 6443/tcp | kevasod's API, client certificates only |
| TestMetalModel | 18080, 18081 (vm); 18090, 18091 (box); 18092 (box, this Mac only); 18095 (first); 18082, 18093 stay closed | a Python echo of the silo's name and port |
| TestMetalNames | 18100 (api); 53/udp+tcp while the DNS switch is on (a few minutes) | echo; Kevaso's DNS, external names only, never forwarding |
| TestMetalImages | nothing | |
| TestMetalSecrets | nothing (the stand-in API is on 127.0.0.77:443, loopback) | |
| TestMetalIngress | 80, 443 | stock nginx 1.27: the test's site (`tls: none`), a 308 to HTTPS for the Ingress without `tls:` (HTTPS is the default), 404 for unknown hosts |
| TestMetalProbes | 18110 (only while ready), 18111 | echo |
| TestMetalLeases | 18120 (for its 1-minute lease), 18121 (once approved, until closed) | echo |
| TestMetalPanes | nothing (the host dials the silos privately) | |
| TestMetalFence | nothing | |
| TestMetalVolumes | nothing | |

Silos reach the internet too: Docker Hub, cloud-images.ubuntu.com, GitHub (the Cloud Hypervisor
release), the Ubuntu archive and, with `KEVASO_METAL_HOSTNAME` set, Let's Encrypt staging.

## What the suite does not cover

- **Several machines**: moves, handoffs, the mesh between hosts, three system nodes. Lima's
  TestMoves and the Linode HA tests cover these.
- **The fence acting.** On one machine the control plane is the worker, so nobody could start
  its silos elsewhere. TestMetalFence proves the record says `fence: false` and that nothing is
  stopped. The owner's setup (a cloud VM as system node, this machine as its only worker) is
  described in `metal_linode_test.go` and belongs in the provider repository, next to its
  machine helpers.
- **Load balancers and the `IP` kind**: no provider plugin on bare metal, and ip-pool needs extra
  routed addresses the machine may not have.
- **Private registries.** Pulling with credentials needs a registry account; the suite pulls
  public images only.
- **The DNS-01 solver and Let's Encrypt production.** Certificates are HTTP-01 against staging
  only, and only with a hostname. Never production in a test.
- **The 1:1 NAT case** (external IP not on any interface): refused at setup, because it is known
  not to work.
- **OpenShell runtimes, podman, JuiceFS or other plugin storage, Kong and Caddy ingress.**
- **Reboots of the machine itself, kernel upgrades, disk-backed volume groups.**
- **IPv6.**

## Risks of running it on a machine with a real external IP

- While the suite runs, the internet can reach 6443 (mutual TLS: no certificate, no API), 80 and
  443 (nginx serving the test page), the test ports above (Python's http.server, unauthenticated
  but serving only an echo), and 53 for a few minutes (Kevaso's DNS, external names only: it can
  be used for reflection, though answers are small and the window is short). Scanners will find
  them. Nothing secret is served, but treat the machine as exposed and dedicated: no other data
  on it.
- The secrets the tests make are random values created per run. They live in the cluster's
  store under `/var/lib/kevaso` and are deleted with it. The KMS recovery key kvoadm prints is
  redacted from the log, and the cluster it opens is reset at the end of the run.
- An interrupted run (Ctrl-C, a timeout) skips the final reset: silos, ports and the loop file
  stay. Run `TestMetalReset` before anything else. The next run's setup also resets first.
- The reset is root on the machine: it purges packages and runs `rm -rf` over Kevaso's paths. It
  is pinned to this one machine by the host key. Its guards (only the `kevaso` volume group on its
  own loop file, only paths under Kevaso's roots, only packages the baseline lacked) are
  unit-tested, but it hasn't run on a real machine yet. Read its first log closely.
- Let's Encrypt staging has rate limits of its own (generous). Repeated runs with the same
  hostname are fine; never point it at production.
- The provider may flag a machine that suddenly answers on many ports, or the DNS listener, as
  abuse. Tell them it is a test machine.
