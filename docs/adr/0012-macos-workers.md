# ADR 0012: A Mac as a worker: the `tart` runtime

**Status:** accepted, built, **proven on a real cluster with one Mac** (2026-11-24: Linode control plane, mesh both ways, a macOS silo Running and `kvo exec`, two silos at a time with a third held until a slot frees, softnet isolation: internet yes, the other silo and the LAN router no); two Macs proven the same day (a MacBook and a Mac mini on different networks, kvoadm over Tailscale: mesh between them, four silos two per Mac, a fifth held until a slot frees) · **Date:** 2026-11-22 ·
**Implements:** parked.md §7 (kevaso-idealization) · **Research:** E038-E042 (kevaso-research)

## Decision

A Mac (Apple Silicon, macOS 13 or later) can be a worker. It runs `kevasod` and one runtime,
`tart`: each silo is a macOS virtual machine, for building iOS apps and running Simulators.

```yaml
spec:
  runtime: tart
  container: { image: ghcr.io/cirruslabs/macos-tahoe-base:latest }   # a macOS image in a registry
  resources: { cpu: 4, memory: 8Gi }
```

- **Two at a time.** Apple allows two macOS guests running at once on one Mac (E039). The runtime
  reports `maxSilos: 2` on its Host, and the scheduler places no third `tart` silo there. The runtime
  refuses a third start itself (`ErrCapacity`), and also reads Tart's own refusal. Linux runtimes have
  no such limit. More Macs, more macOS silos.
- **Tart is the operator's.** Tart is licensed FSL-1.1-ALv2 (no competing commercial use). Kevaso
  installs nothing: it runs the `tart` program you installed, as a separate program, and says so at
  install. No Tart or Orchard code is in Kevaso.
- **Image.** A registry reference to a macOS image, pulled once and cloned per silo (an APFS clone:
  instant, shares blocks). A pull is 25-70 GB, so pull it ahead (`tart pull IMAGE`); creating a silo
  pulls it if it must. The built-in `ubuntu-24.04` is refused for `tart`.
- **Ready** is "the first exec answers" (about 35 s), through Tart's guest agent (`tart exec`):
  exit codes and stdin pass through, so `kvo exec`, `kvo ssh` and `kvo cp` work as on any silo.
- **Who runs what.** `kevasod` runs as root under launchd (`com.kevaso.kevasod`): the mesh's utun
  needs it. `tart` runs as the Mac's own user (`--tart-user`, set by `kvoadm host add` from the user
  it logged in as), because Tart's images and VMs are a user's and Virtualization.framework runs as
  one. Every `tart` call goes through `sudo -u USER`.
- **Joining.** `kvoadm host add USER@MAC --ssh-key … ` reads the machine, finds a Mac, and installs
  the daemon: a macOS check (version, arm64, Tart, softnet, an OpenSSL that reads ed25519 because
  Apple's LibreSSL can't), the signed `kevasod` for darwin/arm64, a launchd plist. The runtime
  defaults to `tart`. Linux-only options (`--loop-storage`, `--egress-extra-ca`, other runtimes,
  `--install control-plane`) are refused on a Mac. Control planes stay on Linux.
- **Mesh.** A Mac is on the WireGuard mesh with wireguard-go (a utun device and `route`), driven by
  the same plan and `Diff` as a Linux host's kernel interface. It never relays. A macOS silo reaches
  the cluster out through the Mac's routes (Apple NAT). The cluster can reach the Mac's mesh address.
- **Isolation between silos.** On by default: every silo starts behind Tart's `softnet` packet
  filter (nothing local, the internet allowed; E042). `softnet` runs as root through a sudoers rule
  for that one binary or setuid root; the runtime says so and fails install until it can.
  `--tart-softnet=false` turns it off, and then silos reach each other and your LAN.
- **Storage.** The silo's disk is its VM, an APFS clone on that Mac. A macOS silo is pinned to its
  Mac (no storage class moves a VM bundle yet). Extra volumes are refused ("come later").

## What a macOS silo can't do yet (refused at admission, not ignored)

- Declare `ports` or a `service`: it has no cluster address (the Mac's mesh address is the Mac's, and
  no rule maps a silo to it).
- Use `grants` (egress rules, secret delivery): the egress gate is a Linux host feature.
- Have volumes.

On the Mac host: `kvoadm host add` installs two launchd daemons, kevasod (`com.kevaso.kevasod`) and
the fence (`com.kevaso.fence`, `kevasod fence-watch`, which keeps running when kevasod stops, as
`kevaso-fence.service` does on Linux). `kvoadm upgrade`, `host reconnect` and `reset` each have a
Mac path (restart through `launchctl`, repoint the plist's `--server`, remove the daemons, files and
macOS silo VMs with `--force`). A Mac has no SSH hardening and no install record: `reset` removes
Kevaso's own fixed list of paths and never touches Tart, its images or SSH.
A cluster with Macs and Linux hosts upgrades with a build for each
(`kvoadm upgrade --kevasod kevasod-linux-amd64 --kevasod kevasod-darwin-arm64`): each host gets the
one for its `uname -sm`, the roll is refused before any change when a host has none, and the new
binary runs once on its host (`kevasod version`) before it replaces the old one.

## How it gets proven

Unit tests cover the runtime against a fake Tart (limit, reset, run-as), the check, the plist, the
scheduler's limit, admission, the mesh's routing arguments. What needs a real Mac:

1. `TART_TEST_IMAGE=… go test -tags tartlive -run Live ./builtin/kri/tart` (the runtime against real
   Tart: lifecycle, exec codes, the third-silo refusal).
2. A Mac in a cluster whose control plane is on a Linode (`provider-linode` `TestMacWorkerJoinsALinodeCluster`, after `sh test/e2e/mac-setup.sh setup`): `kvoadm host add` the Mac, `kvo get
   hosts` shows it Ready with `tart` and its mesh subnet, and `ping` between the Mac's mesh address
   and a Linux worker's both ways. Tear the Linodes down afterwards.
3. A second Mac: two Macs, four macOS silos, the scheduler spreading them.
4. E040 (Xcode and the Simulator in a silo) and E042 (softnet) on a Mac with the disk for them.

Only after (1)-(3) pass does `macos/<version>` join `internal/platform`'s list (that list means
"the whole end-to-end suite passed").
