# 8 · Runtimes

A silo is always the same thing to you (create, exec, its service, its secrets); the **runtime** is
how it's made. Pick one per silo with `spec.runtime`.

---

## At a glance

| | `cloud-hypervisor` | `openshell` | `openshell-container` | `docker` / `podman` |
|---|---|---|---|---|
| **Isolation** | MicroVM, own kernel | MicroVM (OpenShell) | Container (OpenShell) | Container |
| **Needs KVM** | Yes | Yes | No | No |
| **Network** | Real network card: TCP and UDP, in and out | None: outbound TCP through OpenShell's policy only | None: same | Its own namespace on the silo bridge: TCP and UDP |
| **Inbound services** | Yes, client IP kept | No | No | Yes, client IP kept |
| **Persists** | Its own disk | `/sandbox` | `/sandbox` | Volumes |
| **Injection** | Kevaso's egress gate | OpenShell (placeholder in an env var) | OpenShell | Kevaso's egress gate |
| **Broker (`kvo-guest`)** | Yes, over vsock | *Later* | *Later* | Yes, over a socket |
| **Root inside** | Yes | No (a sandbox user) | No | The image's user |
| **Good for** | Dev boxes, servers, P2P nodes, Docker inside | AI agents, untrusted code | The same, on hosts without KVM | Apps packaged as images |

Admission tells you when a silo asks for something its runtime can't do (a public port on
`openshell`, an address range in a grant…), instead of accepting it and never opening it.

---

## cloud-hypervisor

The default choice: a real Linux machine, booted from `ubuntu-24.04`, with its own disk.

- The hypervisor process runs as its own unprivileged user, with no capabilities, a system-call
  filter and only its own disk and network device.
- Init steps run as root inside, through SSH from the host only (a key the host holds; nothing else
  can log in).
- `kvo-guest` is installed on first boot, and the host's egress CA added to its trust store.

---

## openshell

A silo as an [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) sandbox: a microVM with **no
network card at all**. Programs inside reach only what OpenShell's policy allows, and keys are
swapped in by OpenShell's proxy.

```yaml
apiVersion: kevaso/v1
kind: Grant
metadata: { name: anthropic, namespace: agents }
spec:
  egress: [{ to: api.github.com }]
  secrets:
    - name: anthropic-key
      deliver: inject
      env: ANTHROPIC_API_KEY             # the variable holding the placeholder
      to: { host: api.anthropic.com, header: x-api-key, format: "{{value}}" }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: claude-1, namespace: agents }
spec:
  runtime: openshell
  image: ubuntu-24.04                     # OpenShell's base image
  resources: { cpu: 2, memory: 4Gi }
  grants: [anthropic]
```

Inside, `$ANTHROPIC_API_KEY` is a placeholder; a program that sends it as its key reaches the API
with the real one.

| Good to know | |
|---|---|
| Grants | Names and single addresses, TCP only, each port listed (at most 16 per rule) |
| Injection format | `Bearer {{value}}` in `Authorization`, or `{{value}}` in any header |
| Init steps | Run as the sandbox's user, not root |
| `kvo exec` stdin | At most 4 MiB (compress bigger files) |
| Gateways | One per namespace by default (`--openshell-gateway-scope host | namespace | silo` on the worker): sandboxes of one gateway share its user, so the scope is how far an escape reaches. Each gateway runs as its own user, locked down. |

## openshell-container

The same as `openshell`, on OpenShell's Docker driver: for hosts without KVM. The workload has no
network; a supervisor container makes the allowed calls.

---

## docker and podman

A container from any image, on the **same silo bridge as the VMs**, so everything on
[Networking](06-networking.md) applies unchanged: default deny, grants, `allowFrom`, `hostPort`,
the egress gate.

```yaml
apiVersion: kevaso/v1
kind: Silo
metadata: { name: web, namespace: shop }
spec:
  runtime: docker
  image: docker.io/library/python:3.12-slim
  command: [python3, -m, http.server, "8080"]
  volumes: [{ name: data, mountPath: /data }]
  service:
    ports: [{ name: http, port: 8080 }]
    expose: hostPort
  init:
    steps:
      - name: seed
        run: echo hello > /data/index.html
```

| Good to know | |
|---|---|
| `image` | Any image reference; `ubuntu-24.04` means `docker.io/library/ubuntu:24.04` |
| `command` | The main process. Without it, the image's own (for `ubuntu-24.04`, one that sleeps, so it's a machine to `exec` into) |
| Init steps | **Init containers**: each step runs in a container of its own from the silo's image, on its network and volumes, **before** the main container starts |
| Persistence | Volumes survive restarts; the container's own files stay on its host |
| Secrets | `inject` and `broker` (the socket is at `/run/kevaso/broker.sock`, `kvo-guest` is mounted in); `file` and `env` *later* |
| Volume `size` | Not enforced yet on containers |

Next: **[Operating a cluster →](09-operations.md)**
