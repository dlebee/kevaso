# ADR 0003: Provider plugins

**Status:** accepted · **Date:** 2026-11-12

## Decision

1. **One protocol, `sdk/kplugin`.** A provider plugin is its own process serving JSON over HTTP on a
   unix socket, `/run/kevaso-plugins/NAME/plugin.sock`. `Info` says what it serves: `hosts` (it
   recognises its own machines), load-balancer classes, storage classes, DNS providers. Then
   `DescribeHosts`, `Ensure/DeleteLoadBalancer`, `Ensure/Attach/Detach/DeleteVolume` and
   `Ensure/DeleteRecord`. Every call is idempotent and keyed by an ID the control plane picks (a
   silo's UID). Slow work answers `ErrInProgress` and is asked again later, so no call blocks on a
   cloud (a Linode detach once took over 5 minutes, E032). `kplugintest` is a fake of every
   interface.
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

## Why

The brainstorm's plugin table says gRPC. JSON over HTTP on a unix socket keeps the same shape
(socket-folder registration, versioned protocol, idempotent calls) without code generation. A third
party can implement it in any language with a standard library. If gRPC becomes worth it, the
socket and the calls stay; only the encoding changes.

## Tested by

`sdk/kplugin` (the wire, errors, unserved calls), `internal/scheduler` (classes, regions, node
ports), `builtin/kni` (node-port rules), `internal/agent` (format only an empty volume),
`test/integration/providers_test.go` (a fake plugin in a real control plane: placement, load
balancer, volume attach, DNS records, deletion that waits for the unmount and a slow detach), and
the provider's own repo: the Linode API faked, and an e2e on real Linodes.
