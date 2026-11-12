# 6 · Networking

Kevaso owns the firewall on its hosts, and starts from **deny**. This page goes through every way
traffic is opened, one rule at a time.

---

## The defaults

| From → to | Default | Opened by |
|---|---|---|
| A silo → another silo | Denied | The receiving silo's `allowFrom` |
| The internet → a silo | Denied | The silo's `service` with `expose: hostPort` or `loadBalancer` |
| A silo → the internet | Denied | A `Grant` naming the destination ([below](#what-a-silo-may-reach-outside)) |
| A silo → its host | DNS and ping only | Never more |
| A silo → the mesh's host addresses | Denied | Never |
| A silo → names (DNS) | Allowed | Its host answers on the silo network's gateway |

Each silo also can't send packets with an address other than its own (anti-spoofing), so a rule
"from silo X" really means silo X.

---

## Private names

Every silo with a service gets a name inside the cluster:

```
NAME.NAMESPACE.kevaso      api.payments.kevaso
NAME                       api            (from a silo in the same namespace)
```

Each worker's DNS answers them for its silos, and forwards everything else.

---

## A service of its own

```yaml
spec:
  service:
    ports:
      - { name: http, port: 8080 }
      - { name: p2p,  port: 30303, protocol: UDP }
```

That alone is **private**: reachable by name, but only by silos you allow.

---

## Letting another silo in: `allowFrom`

On the silo being reached:

```yaml
spec:
  allowFrom:
    - { silo: worker, ports: [http] }     # same namespace, only the http port
    - { silo: research/crawler }          # another namespace, every port
```

It works across hosts too (over the mesh). A silo named here that isn't running opens nothing.

---

## Open to the internet

### On the host's own address: `hostPort`

```yaml
spec:
  service:
    ports:
      - { name: p2p,  port: 30303, protocol: TCP }
      - { name: disc, port: 30303, protocol: UDP }
      - { name: rpc,  port: 8545 }
    expose: hostPort
    hostPort:
      ports: [p2p, disc]              # only these; rpc stays private
      allowFrom: ["203.0.113.0/24"]   # optional: only these sources
```

Plain layer-4 forwarding: no proxy, and **the silo sees the client's real address**.

### Its own address: `loadBalancer`

| Class | Address | Needs |
|---|---|---|
| `worker-ip` | The host's own address (like `hostPort`, chosen for you) | Nothing |
| `ip-pool` | An address of its own, from an `IPPool` routed to the host | Extra addresses on that host |

```yaml
apiVersion: kevaso/v1
kind: IPPool
metadata: { name: hv2-extra }
spec: { host: hv2, addresses: ["198.51.100.17/32", "198.51.100.18/32"] }
---
# in the silo
spec:
  service:
    ports: [{ name: p2p, port: 30303 }]
    expose: loadBalancer
    loadBalancer: { class: ip-pool, pool: hv2-extra, stableIP: true }
```

Cloud load balancers (Linode NodeBalancers, floating IPs) come with the Linode plugin *(later)*.

> **Exposing publicly is its own permission:** `create` on `services/expose-public`. Namespace
> `admin`s have it, `editor`s don't.

---

## Which address its traffic leaves from

```yaml
spec:
  network:
    egress:
      source: sameAsService     # host (default) | sameAsService | pool
```

`sameAsService` is what P2P nodes need: they advertise the address they're reached on, so their
outbound traffic must come from it too.

---

## What a silo may reach outside

Nothing, until a **Grant** says so. A Grant is its own object; a silo lists the ones it uses:

```yaml
apiVersion: kevaso/v1
kind: Grant
metadata: { name: build-tools, namespace: dev }
spec:
  egress:
    - { to: api.github.com }                                  # a name: TLS on 443
    - { to: "*.npmjs.org" }                                   # a wildcard name
    - { to: "0.0.0.0/0", ports: ["30303"], protocols: [tcp, udp] }   # raw, any address, one port
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: builder, namespace: dev }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  grants: [build-tools]
```

| `to:` | How it's enforced |
|---|---|
| An address or CIDR | The host firewall, by address, port and protocol |
| A host name | The host's **egress gate**: the silo's TLS is checked against the name it asks for (SNI) and passed through, untouched, only for that name, to the address the gate looks up itself. No name or another name: refused. (The gate doesn't look inside a passed-through connection; for hosts it injects a secret for, it does, and refuses a request for another host: see [Secrets](07-secrets.md).) |

DNS always works, so a silo can resolve anything; it just can't connect where no grant says.

Next: **[Secrets →](07-secrets.md)**
