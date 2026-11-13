# ADR 0003: Provider plugins

**Status:** accepted · **Date:** 2026-11-12

> **Note (2026-11-13):** ADR 0009 replaces a host's one address with its internal and external IPs; plugins are told both, and a port's client ranges are `sources`.

## Decision

1. **One protocol, `sdk/kplugin`: gRPC over a unix socket, like CSI.** A provider plugin is its
   own process serving `kpluginpb/kplugin.proto` on `/run/kevaso-plugins/NAME/plugin.sock`, plus the
   standard gRPC health service. `Identity.GetPluginInfo` says what it serves: `hosts` (it
   recognises its own machines), load-balancer classes, storage classes, DNS providers. The other
   services are `Hosts`, `LoadBalancers`, `Volumes` and `DNS`; a plugin registers only the ones it
   implements, and the rest answer `UNIMPLEMENTED`. Every call is idempotent and keyed by an ID the
   control plane picks (a silo's UID). Errors are CSI's status codes: `NOT_FOUND`,
   `FAILED_PRECONDITION` (someone else's), `ABORTED` (still in progress: slow work, like a Linode
   detach that once took over 5 minutes (E032), is asked again later, so no call blocks on a cloud).
   Plugin authors write Go interfaces; `Serve` and `Client` hide the protobuf. `kplugintest` is a
   fake of every interface. The generated code is committed (`make proto` regenerates it).
2. **kevasod finds plugins by their sockets** (the kubelet's plugin watcher, simplified): it polls
   the folder, asks `Info`, checks the protocol version, and drops a plugin that stops answering.
   Unknown classes are admitted; the scheduler leaves such a silo Pending with "no plugin serves it"
   until one does. A plugin that is down for a minute doesn't make writes fail.
3. **The cloud token lives in the plugin's unit only.** `kvoadm plugin install` copies the binary
   (signature checked on the host, like kevasod), stores credentials root-only under
   `/etc/kevaso/plugins/NAME/`, and runs the plugin as a hardened systemd unit (`DynamicUser`, no
   capabilities, read-only system, its credentials through `LoadCredential`). kevasod never holds
   the token. Workers never see it.
4. **Core keeps the decisions.** Controllers in `internal/controllers/provider` decide when: they
   record a host's provider details (`status.provider`), give a silo a load balancer
   (`lb.kevaso.com/CLASS` finalizer), create and attach its volumes (`kevaso.com/volumes`), and
   publish an IngressClass's host names (`dns.kevaso.com/records`). The scheduler places a silo
   using a plugin's class only on that plugin's machines, and keeps it in its volumes' region. Node
   ports (30000–32767) are allocated with the placement, like pool addresses. The worker does the
   host's part with nothing provider-specific in it: it formats a volume only when blkid finds
   nothing on it, then mounts it; it forwards node ports only from the load balancer's source
   ranges; it puts announced addresses on `lo`.
5. **A plugin's node side is optional.** The same binary can run on workers (`--side node`) for
   what must happen on the machine itself. For Linode, that's announcing shared IPs over BGP.
6. **A storage class says how it reaches a host** (`Class.reach`, M14): `device` (the default: the
   controller side attaches a block device, kevasod formats it once and mounts it) or `mount` (a
   network filesystem, like JuiceFS: nothing is attached; the plugin's node side mounts it). A node
   side serving mount classes listens on `/run/kevaso-plugins/NAME/node.sock` (Identity, saying
   which classes it mounts, and `Node`: `NodeMountVolume` and `NodeUnmountVolume` of a handle at a
   host path). Each worker's kevasod watches those sockets like the control plane watches
   `plugin.sock`, reports the classes on its Host (`status.mountClasses`), and the scheduler only
   places a silo using such a class there. `status.volumes[].attachedTo` says which host should
   mount it; when the silo moves, the old host unmounts first, as with a detach. The node side holds
   the credentials, so the silo only ever gets the mounted folder. A mount class with topology
   `global` makes a container silo movable `Anywhere`.

## Why

Consistent with Kubernetes: its API is REST/JSON (and so is ours, including for the agents, as the
kubelet uses the API server), while its plugin interfaces (CRI, CSI, KMS v2, device plugins,
plugin registration) are gRPC over unix sockets. A `.proto` is the contract a third-party plugin
author needs: typed, versioned, generated in any language, with health checks and deadlines built in.

Plugin calls follow the cloud, not the cluster's churn: the controllers remember what they last
asked each plugin and ask again only when the request changes (and every 10 minutes, to repair
changes made outside Kevaso). Heartbeats and status writes never reach the plugin.

## Tested by

`sdk/kplugin` (the gRPC wire, status codes, unserved services), `internal/plugins` (a socket appearing and going away), `internal/scheduler` (classes, regions, node
ports), `builtin/kni` (node-port rules), `internal/agent` (format only an empty volume),
`test/integration/providers_test.go` (a fake plugin in a real control plane: placement, load
balancer, volume attach, DNS records, deletion that waits for the unmount and a slow detach, no plugin calls across heartbeats),
`test/integration/mounts_test.go` (a mount class with two real agents and their node sides: only
hosts with the node side, mounted without an attach, moved after the old host unmounts, deleted),
`kplugintest.Conformance` (the protocol's promises, run on the fake and on each provider), and
the provider's own repo: the Linode API faked, and an e2e on real Linodes.
