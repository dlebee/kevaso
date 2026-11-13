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

## 2. Silos: declare, then open, port by port

```go
SiloSpec.Ports   []SiloPort       // {name, port, protocol}: what exists
SiloSpec.Service *SiloService     // {name, ports, loadBalancer{class, ip, dedicated}, routeWhen}
ServicePort      {port, allowFrom, hostPort, as, sources, lease, loadBalancer}
```

- `expose`, the `hostPort` block, `spec.allowFrom`, `loadBalancer.allowFrom` and `lease.allowFrom`
  are gone. Who may connect on the silo IP is the port's `allowFrom` (silos only); network ranges
  are the port's `sources`, and apply wherever it opens outside the silo IP (host addresses, the
  load balancer); a leased port's sources are the port's own (the narrowing `lease.allowFrom` did
  is now just `sources` on that port).
- **The `worker-ip` class is gone.** It was "the host's own address, the service's ports": that is
  `hostPort` now, with the address named (`[external]`, `[internal]`). `kvoadm ingress install`
  opens the proxy's ports with `--host-port external` (the default) or `--lb-class CLASS`.
- `loadBalancer: true` puts one port on the service's load-balancer address, at its `as` number;
  the class, `ip` and `dedicated` stay on `service.loadBalancer`, which is refused when no port has
  `loadBalancer: true`. A port may be both on the host and on the load balancer.
- Admission (`internal/apiserver/ports.go`, pure): declared names are labels and unique, a number
  and protocol declared once; every service port names a declared port, once; `allowFrom` entries
  are `NAME` or `NAMESPACE/NAME` (a CIDR there is refused, pointing at `sources`); `hostPort` is
  `internal`/`external`; `as` and `sources` only with `hostPort` or `loadBalancer`; the same number
  on the same network twice in one silo is refused; leases only on a port that opens outside.
- A standalone `Service`'s `targetPort` names the instances' declared port (default: the port's
  own name); an endpoint whose declared port has another protocol isn't sent that port. Probes'
  `tcp`/`http` name a declared port (no numbers).
- A SiloSet's `template.service.name` is refused: each instance's service is named after it.
- The firewall (`builtin/kni`): per service port, a DNAT on each address it opens on (the host's
  internal and/or external IP, its ip-pool address) at its `as` number, and a forward rule matching
  that original address and the port's `sources`, so traffic translated elsewhere (a Service's
  cluster IP) never rides on it. `allowFrom` (plus an Ingress's generated path, `kni.Silo.Paths`)
  opens the silo IP to the named silos only, port by port.

## 3. Placement

A port with `hostPort` needs its host to have that address: a host without an external IP is
excluded for a `[external]` port, with the reason ("no external IP, which port 443/TCP asks for
(hostPort: [external])"). And no other silo on that host may hold the same address, number (its
`as`) and protocol ("port 443/TCP on the external IP (51.38.10.20) is held by web/api-blue"). Both
reasons are the scheduler's, so `kvo describe silo` lists them per host as before. A leased port
holds its number while closed.
