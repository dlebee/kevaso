# 5 · More machines

One control plane, any number of workers: a server in a data center, a VPS, a box at home behind
your router. They don't need to be on the same network.

---

## How workers connect

- A new worker **joins with a one-time token** and gets a certificate for exactly its own name and
  role. It can't act as another host, and it can't touch silos placed elsewhere.
- It **dials out** to the control plane and keeps that connection open; `kvo exec` and everything
  else come back through it. Nothing needs to listen on the worker.
- Hosts are on a **WireGuard mesh** run by the control plane. Each host gets its own silo subnet
  (`10.64.N.0/24`), so silos on different hosts reach each other by address and name.
- A worker **behind NAT** reaches the others through a relay (a host with a public address), end to
  end encrypted inside it: the relay only ever sees encrypted UDP.

---

## Prepare the machine

The same as for the first one ([Installing](02-install.md), steps 2 to 5): put your Kevaso key on it,
write down its fingerprint, and `kvoadm check` it.

---

## Add it

```bash
bin/kvoadm host add root@198.51.100.20 --ssh-key ~/.ssh/kevaso_ed25519 --host-key SHA256:… --kevasod bin/kevasod-linux-amd64 --install worker --name hv2 --region ca-east --runtime cloud-hypervisor
```

| Flag | Meaning |
|---|---|
| `--install worker` | This host only runs silos |
| `--region`, `--zone` | Where it is, for placement (`placement.region` on a silo) |
| `--label k=v` | Any label, for `placement.hostSelector` |
| `--runtime` | Which runtimes to install (repeatable) |
| `--behind-nat` | Nothing can reach it from outside: it'll use the relay |
| `--server URL` | The API address *as this host reaches it*, if not the one in your context |

`kvoadm` makes a one-time join token through the API (as you, a cluster admin), installs the signed
`kevasod` like `init` does, and starts it as a worker. It joins, and appears in:

```bash
bin/kvo get hosts
```

---

## Placing silos

```yaml
spec:
  placement:
    region: ca-east                 # only hosts in this region
    hostSelector: { gpu: "yes" }    # only hosts with these labels
```

The scheduler also checks the runtime is installed and Ready there, that the CPU and memory fit, and
taints and tolerations, like Kubernetes.

---

## When a host goes away

A host that stops reporting for **40 seconds** is marked lost. What happens to its silos is
**yours to choose**, per silo:

```yaml
spec:
  availability:
    onHostLoss: Wait        # Wait (default) | Recreate
```

| Policy | Meaning | Good for |
|---|---|---|
| `Wait` | Stays where it is, down, until the host is back. Its disk is never lost. | Anything with state you care about |
| `Recreate` | Started fresh from its image on another host after 30 s. Its disk on the lost host is given up. | Stateless or rebuildable silos |

To make sure two copies never run at once, a worker that loses the control plane for 30 seconds
**stops its own `Recreate` silos** before the control plane would recreate them elsewhere.

---

## Maintenance: draining

```bash
bin/kvoadm host drain hv2
```

The host takes no new silos, and it shows which of its silos would move and which must wait (`Wait`
silos keep their disk there). Bring it back with:

```bash
bin/kvoadm host uncordon hv2
```

Next: **[Networking →](06-networking.md)**
