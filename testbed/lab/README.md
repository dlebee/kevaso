# Worktree labs

A lab is a throwaway Kevaso cluster for one git worktree: one system node and two workers,
nested QEMU/KVM VMs on the lab host (the EPYC from E046). The workers run Cloud Hypervisor
microVMs. Several labs share the host, up to six.

```bash
make lab-up LAB=smoke
make lab-list
make lab-down LAB=smoke
```

`LAB=name` is a lowercase DNS label of at most 12 characters. `make lab-up LAB=name RECREATE=1`
replaces a lab of that name. `lab-down` of a name that is not there does nothing.

The host is `ubuntu@54.39.243.98`, the key `~/.ssh/kevaso-testbed_ed25519`. Override with
`LAB_HOST` (`[user@]address[:port]`), `LAB_SSH_KEY`, and `LAB_HOSTKEY` (the `SHA256:` fingerprint
of the host's ED25519 key). Without `LAB_HOSTKEY`, kvlab uses the ed25519 key already in
`~/.ssh/known_hosts` and refuses a host that is not there. Commands on the host run through
`sudo -n`. Nothing on the Mac is run with sudo.

## What lab-up does

1. Refuses if `kevasod` is active on the lab host. Kevaso manages its own firewall tables, and a
   lab's table is `inet kvl`.
2. Takes a free slot 1..6 (recorded in `/root/kvl/NAME/slot`) and a `/24`, `10.77.N.0/24`.
3. Defines libvirt network `kvl-NAME` (NAT, bridge `kvlbrN`, DHCP reservations .10 sys, .11 w1,
   .12 w2). DNS domain `lab.test` has `sys.NAME.lab.test`, `w1.NAME.lab.test`, `w2.NAME.lab.test`,
   and a dnsmasq rule so any name under `NAME.lab.test` answers with the system node.
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

`lab-down` deletes only `kvl-NAME` objects: the three domains, network `kvl-NAME`, disks and logs
matching `kvl-NAME-*`, `/root/kvl/NAME`, and that lab's nftables chains. The `inet kvl` table is
removed when no lab chain is left. The base image, libvirt's `default` network, and other labs
are not touched. The testbed reset (`testbed/remote`, `/var/lib/kvt-baseline`) also leaves
`kvl-*` domains, networks, disks, `/root/kvl` and `inet kvl` in place.

## Timings

From `make lab-up LAB=smoke` on this worktree, against the EPYC. Filled in after the smoke run.
