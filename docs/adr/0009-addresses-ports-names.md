# ADR 0009: Addresses, ports, services and names (the sealed model)

**Status:** accepted · **Date:** 2026-11-13 · **Implements:** design §7.0 · **Supersedes:** a host's
one `spec.address`; `expose: private|hostPort|loadBalancer`; the `hostPort` block; CIDRs in
`allowFrom`; `spec.allowFrom` on the silo; `status.address` and `publicIP`; a name for every silo;
host ports answering on every address the host has (ADR 0004 and the `ips` work state the old shapes;
this one wins where they differ).

Design §7.0 is the reference for what the user writes and sees. This ADR records how the code
carries it out and the choices the design leaves open.

## 1. Hosts: an internal IP and/or an external IP

`Host.spec.internalIP` and `spec.externalIP` replace `spec.address`. Admission refuses a host with
neither, an address that isn't IPv4, and the same address in both (a machine with one address has
one of the two). A provider's private address (`status.provider.privateAddress`) is the host's
internal IP when the operator set none (`Host.Internal()`); `kvo describe host` says so.

Which address each internal use takes:

| Use | Address | Why |
|---|---|---|
| The mesh's WireGuard endpoint, as other hosts dial it | `Reach()`: external if it has one, else internal | Hosts on other networks can only use the external one; a host with only an internal IP is reached there (a LAN, or `behindNAT`, which works as before: it dials out and is never dialed) |
| A system node's store peer URL, its API URL (`status.controlPlane.apiURL`), the OIDC issuer when there's no cluster DNS name, `kvoadm init --restore` and `host reconnect`'s default server | `Reach()` | Same reasoning: other hosts and the operator's laptop must reach them |
| The API server's and the etcd member's certificates | Both IPs (internal first), the host name, loopback, the SSH address when it's neither (`--extra-name`), the cluster DNS name | Anyone may dial either address |
| What `kvoadm` connects to over SSH | What the operator typed (`[USER@]ADDRESS`, recorded in the `kevaso.com/ssh` annotation) | It may be a name, a tunnel (`127.0.0.1:2222`) or a jump address that is neither IP |
| What a provider plugin is told (`kplugin.Host`) | Both: `internalIP` and `externalIP` as declared | The plugin knows which of its machines has which address; the fake matches on either |
| Where ip-pool's extra addresses go | The interface carrying `Reach()` | The extra addresses are routed to the machine's main address |
| A silo's address out with `egress.source: host` | `Reach()`, or nothing known behind NAT | As before |

`kvoadm init` and `host add` take `--internal-ip` and `--external-ip` (replacing `--address`).
With neither, the SSH address becomes the internal IP (when it's an IPv4 address; a name is
refused with what to say instead): kvoadm can't know an address is reachable from outside, and
"internal" claims the least. `kvoadm host list` and `kvo get hosts` show both columns; `kvo describe
host` shows internal, external and mesh IPs. `kevasod control-plane` takes `--internal-ip` and
`--external-ip`.
