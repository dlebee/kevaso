# Worktree labs

A lab is a throwaway Kevaso cluster for one git worktree: one system node and two workers,
nested QEMU/KVM VMs on the lab host (the EPYC from E046). The workers run Cloud Hypervisor
microVMs. Several labs share the host, up to six.

```bash
make lab-up LAB=smoke
make lab-up LAB=pr PAIR=1
make lab-list
make lab-down LAB=smoke
```

`LAB=name` is a lowercase DNS label of at most 12 characters. `make lab-up LAB=name RECREATE=1`
replaces a lab of that name. `PAIR=1` is a pair lab (below), not the three-node cluster.
`lab-down` of a name that is not there does nothing, and it removes a pair lab the same way.

The host is `ubuntu@54.39.243.98`, the key `~/.ssh/kevaso-testbed_ed25519`. Override with
`LAB_HOST` (`[user@]address[:port]`), `LAB_SSH_KEY`, and `LAB_HOSTKEY` (the `SHA256:` fingerprint
of the host's ED25519 key). Without `LAB_HOSTKEY`, kvlab uses the ed25519 key already in
`~/.ssh/known_hosts` and refuses a host that is not there. Commands on the host run through
`sudo -n`. Nothing on the Mac is run with sudo.

## What lab-up does

1. Refuses if `kevasod` is active on the lab host. Kevaso manages its own firewall tables, and a
   lab's table is `inet kvl`.
2. Takes a free slot 1..6 (recorded in `/root/kvl/NAME/slot`) and a `/24`, `10.77.N.0/24`.
3. Defines libvirt network `kvl-NAME` (forward mode open, bridge `kvlbrN`, DHCP reservations
   .10 sys, .11 w1, .12 w2). Open mode adds no firewall rules: nat mode would reject new
   connections into the bridge, including the published ports. Guest traffic to the internet is
   masqueraded in `inet kvl`. DNS domain `lab.test` has `sys.NAME.lab.test`, `w1.NAME.lab.test`,
   `w2.NAME.lab.test`, and a dnsmasq rule so any name under `NAME.lab.test` answers with the
   system node.
4. Creates thin qcow2 overlays of `/var/lib/libvirt/images/e046-base-noble.img`. The system node
   is 2 vCPU, 4 GiB, 20 GiB; each worker is 4 vCPU, 8 GiB, 40 GiB. CPU is host-passthrough with
   migration off, so `/dev/kvm` inside the guest works. cloud-init creates `ubuntu` with
   passwordless sudo and the lab's own ed25519 key (generated on the host, copied to
   `testbed/lab/.labs/NAME/`, which is gitignored).
5. Forwards ports on the host's public address with nftables table `inet kvl` only:
   `21000 + slot*100 + {22 sys SSH, 23 w1, 24 w2, 43 API}`. Slot 1 is 21122, 21123, 21124, 21143.
6. Builds `kevasod`, `kvoadm` and `kvo` from this worktree (`GOPROXY=off`) and runs `kvoadm init`
   on the system node, then `kvoadm host add` for each worker (`cloud-hypervisor` and `docker`,
   20G loop storage). Workers dial the API at `10.77.N.10:6443`. kvo on the Mac uses the forwarded
   API port.

`testbed/lab/.labs/NAME/env.sh` has the variables the metal tests read, plus `LAB_NAME`:

```bash
source testbed/lab/.labs/NAME/env.sh
kvo get hosts
go test -tags metal -run X ./test/e2e/
```

`KEVASO_METAL_HOST` is `ubuntu@<lab host>:<sys ssh port>`, `KEVASO_METAL_KEY` is the lab key,
`KEVASO_METAL_HOSTKEY` is the system node's fingerprint, `KEVASO_METAL_EXTERNAL_IP` is the lab
host's public address (where the forwarded ports land) and `KEVASO_METAL_INTERNAL_IP` is the
system node's `10.77.N.10`. `KVO_CONFIG` points at the context `kvoadm init` wrote.
The metal suite's check that the external IP is configured on the machine it SSHs to does not
hold for a nested node: that address is DNATed on the lab host, not assigned inside the VM.

## Pair labs

`make lab-up LAB=name PAIR=1` (`kvlab up --pair`) is the same network, the same slot and the
same port block, with two machine VMs instead of the cluster. `m1` and `m2` are each 8 vCPU,
8 GiB and 40 GiB. `VCPU=n` (`kvlab up --pair --vcpu n`) sets that count, from 6 to 16. The
host keeps one CPU, so a machine has one fewer for silos: 4 vCPU left 3, and the two-machine
tests place five one-CPU silos on one machine, which needs 6. 16 on each machine is the
EPYC's 32 threads. Six pair labs at the default of 8 is 96 vCPUs on those 32 threads; pass
a smaller `VCPU` when several pair labs run at once.

`m2` has a second empty virtio disk, serial `kvlspare`, which the guest
names `/dev/disk/by-id/virtio-kvlspare`. LVM reports that disk by its kernel name; the reset treats the by-id path and that name as the same disk, and still refuses any other. Kevaso is not installed. On each fresh VM kvlab runs
the harness baseline (`testbed/remote` `RecordBaseline`): the checklist has to pass, then the
VM's packages, nftables tables and IP forwarding are written to `/var/lib/kvt-baseline/state`.
The two-machine tests reset against that and install Kevaso themselves with `kvoadm`.

`testbed/lab/.labs/NAME/env.sh` sets `KEVASO_METAL_*` to m1 and `KEVASO_METAL2_*` to m2:

| Variable | Value |
|---|---|
| `KEVASO_METAL_HOST` | `ubuntu@<lab host>:<m1 ssh port>` |
| `KEVASO_METAL_KEY` | the lab key (m2 uses the same key, also set as `KEVASO_METAL2_KEY`) |
| `KEVASO_METAL_HOSTKEY` | m1's fingerprint (`KEVASO_METAL2_HOSTKEY` is m2's) |
| `KEVASO_METAL_EXTERNAL_IP` | m1's `10.88.N.11` (`KEVASO_METAL2_EXTERNAL_IP` is m2's `.12`) |
| `KEVASO_METAL_INTERNAL_IP` | m1's `10.77.N.10` (`KEVASO_METAL2_INTERNAL_IP` is m2's `.11`) |
| `KEVASO_METAL2_SPARE_DISK` | `/dev/disk/by-id/virtio-kvlspare` |
| `KEVASO_METAL_API_PORT` | the slot's API port (`21000 + slot*100 + 43`), forwarded to m1's 6443 |
| `KEVASO_METAL_PORT_<port>` | the slot port for each guest port in the table below |

There is no `KVO_CONFIG`. The file unsets it.

Each machine has a second virtio NIC on a lab-only bridge, `kvlxbrN` (not a libvirt
network). The lab host is `10.88.N.1/24` on that bridge. m1 is `10.88.N.11/24` and m2 is
`10.88.N.12/24`, and those addresses are on the NIC, the way a bare-metal machine's
external address is. Traffic from that address uses policy-routing table 88: the other
machine is on-link, and everything else (this Mac) goes to `10.88.N.1`. The internal
`10.77.N.0/24` and a normal lab are unchanged. A real machine is unchanged: its external
address is still its public address, and `10.88.0.0/16` is the only private range
`testbed/remote` accepts as an external address.

SSH is forwarded as for a node lab: m1 at offset 22, m2 at offset 23, DNATed to the
internal address (sshd listens on every address, and DHCP brings the internal NIC up).
The API is the same slot port as a node lab, offset 43 (`21000 + slot*100 + 43`), DNATed
to m1's external address port 6443. The guest still listens on 6443. The packet arrives
on the external NIC with destination `10.88.N.11`, which is the address Kevaso's
hostPort rules match. `env.sh` sets `KEVASO_METAL_API_PORT` to that slot port. The Mac's
`kvoadm --api-server` is `https://<lab host>:<slot port>` (the lab host DNATs it). The
one-machine suite passes that same URL to `kvoadm init`, so the kvo config it writes
names the lab host and the slot port. m2 is given `--server https://10.88.N.11:6443`
and dials m1 on the external bridge. Unset, the URL stays `https://<external>:6443`
and the two-machine worker is not given `--server`, which is what a real machine does.
The certificate names the machine's addresses and, because the SSH address is the lab host's
public address, that address too, so the Mac's TLS name matches. There is no hairpin of
the public address on the internal bridge, and DNATed service traffic is not masqueraded:
the client address is kept, and conntrack on the lab host restores the public source on
the reply (E009). 6443 is not published on the lab host's public interface. SSH replies
are still masqueraded as they leave the internal bridge, so the guest answers the gateway.

Every other port pair mode publishes on the lab host's public address is a port in that
same block, forwarded to the guest's own port. The guest keeps the real number (an Ingress
on :80 inside the VM stays on 80). The Mac dials the slot port from `KEVASO_METAL_PORT_<port>`,
which is the real port when unset, so a real machine is unchanged. Offsets 22, 23, 24 and 43
are the ones a normal lab already uses. These stay clear of them. Nothing in the two-machine
suite opens a NodePort. The one-machine suite's ports are in the same table, on m1. Port 53
is DNS and is published for UDP and TCP.

| Guest port | Machine | Offset | Slot 1 | Env | Who dials it from the Mac |
|---|---|---|---|---|---|
| 80 | m1 | 80 | 21180 | `KEVASO_METAL_PORT_80` | TestMetal2Ingress, TestMetalIngress |
| 443 | m1 | 44 | 21144 | `KEVASO_METAL_PORT_443` | TestMetalIngress and the long soak's certificate check (43 is the API) |
| 18160 | m1 | 60 | 21160 | `KEVASO_METAL_PORT_18160` | TestMetal2LongSoakCheck |
| 18200 | m2 | 25 | 21125 | `KEVASO_METAL_PORT_18200` | TestMetal2Worker |
| 18201 | m2 | 26 | 21126 | `KEVASO_METAL_PORT_18201` | TestMetal2Worker |
| 18210 | m2 | 27 | 21127 | `KEVASO_METAL_PORT_18210` | TestMetal2Mesh |
| 53 | m1 | 53 | 21153 | `KEVASO_METAL_PORT_53` | TestMetalNames (UDP and TCP) |
| 8081 | m1 | 28 | 21128 | `KEVASO_METAL_PORT_8081` | TestMetalModel (the declared port, closed) |
| 8091 | m1 | 29 | 21129 | `KEVASO_METAL_PORT_8091` | TestMetalModel |
| 18080 | m1 | 30 | 21130 | `KEVASO_METAL_PORT_18080` | TestMetalModel |
| 18081 | m1 | 31 | 21131 | `KEVASO_METAL_PORT_18081` | TestMetalModel |
| 18082 | m1 | 32 | 21132 | `KEVASO_METAL_PORT_18082` | TestMetalModel |
| 18090 | m1 | 33 | 21133 | `KEVASO_METAL_PORT_18090` | TestMetalModel |
| 18091 | m1 | 34 | 21134 | `KEVASO_METAL_PORT_18091` | TestMetalModel |
| 18092 | m1 | 35 | 21135 | `KEVASO_METAL_PORT_18092` | TestMetalModel |
| 18093 | m1 | 36 | 21136 | `KEVASO_METAL_PORT_18093` | TestMetalModel |
| 18095 | m1 | 37 | 21137 | `KEVASO_METAL_PORT_18095` | TestMetalModel |
| 18096 | m1 | 38 | 21138 | `KEVASO_METAL_PORT_18096` | TestMetalModel |
| 18110 | m1 | 39 | 21139 | `KEVASO_METAL_PORT_18110` | TestMetalProbes |
| 18111 | m1 | 40 | 21140 | `KEVASO_METAL_PORT_18111` | TestMetalProbes |
| 18120 | m1 | 41 | 21141 | `KEVASO_METAL_PORT_18120` | TestMetalLeases |
| 18121 | m1 | 42 | 21142 | `KEVASO_METAL_PORT_18121` | TestMetalLeases |
| 18130 | m1 | 45 | 21145 | `KEVASO_METAL_PORT_18130` | TestMetalPodman |
| 18140 | m1 | 46 | 21146 | `KEVASO_METAL_PORT_18140` | TestMetalReboot |
| 18141 | m1 | 47 | 21147 | `KEVASO_METAL_PORT_18141` | TestMetalReboot |

Each of those is forwarded on the public interface to that machine's external address,
not hairpinned. `lab-up` refuses a slot port the host is already listening on, or that
another lab already forwards. The Mac dials the lab host's slot port only for the machine
that owns the guest port. WireGuard between the two machines uses the external addresses
and needs no forward: they are on the same bridge.

Public port 80 is the one exception. Let's Encrypt's HTTP-01 challenge connects to port 80
on the address the name resolves to. The lab also publishes public port 80 to m1's
external address port 80 when the host is not already using it. A second pair lab still
starts: it does not take port 80. `TestMetal2LongSoakSetup` builds the name from the
machine's external address (`10.88.N.11`), which the internet cannot reach, so HTTP-01
does not complete against a pair lab. `TestMetal2Ingress` dials the slot port and does
not need public port 80.

These checks need this Mac to reach an external address directly, not through a forwarded
port. On a pair lab that dial has no route, so it fails closed:

- `TestMetal2Worker` checks that 18200 and 18201 do not answer on m1. The slot ports are
  forwarded only to m2, so the check dials m1's `10.88` address on the real port.
- `TestMetal2Mesh` checks that 18210 does not answer on m1, the same way.
- `TestMetal2LongSoakSetup`'s HTTP-01 name is the external address. The certificate check
  dials the lab host when 443 is forwarded to that machine (m1). It still needs a route
  of its own when the ingress is on m2, and HTTP-01 itself needs a name the internet can
  reach.

```bash
source testbed/lab/.labs/pr/env.sh
go test -tags metal -run '^TestMetal2' -count=1 ./test/e2e/
```

`lab-down` deletes only `kvl-NAME` objects: the domains (sys, w1 and w2, or m1 and m2; a
name that is not there is a no-op), network `kvl-NAME`, disks and logs
matching `kvl-NAME-*`, `/root/kvl/NAME`, and that lab's nftables chains. The `inet kvl` table is
removed when no lab chain is left. The base image, libvirt's `default` network, and other labs
are not touched. The testbed reset (`testbed/remote`, `/var/lib/kvt-baseline`) also leaves
`kvl-*` domains, networks, disks, `/root/kvl` and `inet kvl` in place.

## Timings

`make lab-up LAB=smoke` on this worktree, against the EPYC (slot 1). The binaries are built
while the VMs boot, so `build` is the wait left after boot, and here that wait was already over.

| stage | time |
| --- | --- |
| connect | 1.29s |
| check | 342ms |
| slot | 358ms |
| key | 589ms |
| define | 7.442s |
| boot | 21.384s |
| seed | 7.597s |
| build | 0s |
| kevaso | 54.39s |
| runtimes | 53.198s |
| total | 2m26.591s |
