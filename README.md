# Kevaso

Self-hosted, stateful **silos** (microVMs or containers) on the machines you bring, managed
Kubernetes-style. `kevasod` runs on every host, `kvo` is for users, `kvoadm` for operators.

**New here? Read [the guide](https://dlebee.github.io/kevaso-docs/)**: from an empty machine to a shared
cluster, one explained step at a time. (`docs/` in this repo is for people working on Kevaso itself.)

**Status:** early (M0–M12 of [MILESTONES.md](MILESTONES.md) done). What exists today:

- setup in explicit steps ([guide](https://dlebee.github.io/kevaso-docs/setup/prepare/)): you make Kevaso's SSH key and
  check the machine's fingerprint, `kvoadm init` first looks without changing anything (`--dry-run` stops there), then
  installs the control plane (signed `kevasod` verified on the host) and gives you `kvo` access, and
  `kvoadm host enable-worker` lets the same machine run silos;
- `kevasod control-plane`: the API over TLS with client certificates from the cluster's private CA,
  a root-only admin socket, one-time join tokens for hosts, SQLite storage, a Ready heartbeat;
- `kvoadm init … --worker`: the same host also runs silos. The worker installs pinned, digest-checked
  Cloud Hypervisor + firmware + an Ubuntu 24.04 image, thin-LVM disks, a bridge with NAT and
  silo↔silo isolation, and boots each silo as a locked-down VMM (own user, no capabilities, seccomp);
- a scheduler (runtime, labels, taints, CPU/memory) and the silo's **init steps**, run inside the VM;
- `kvo apply / get / describe / delete / watch` for Namespaces, Hosts and Silos, using the context
  `kvoadm init` writes (`~/.kevaso/config.yaml`), and `kvo exec silo NAME -- CMD` through the
  agent's dial-out tunnel (hosts need no inbound port);
- people: `kvoadm users invite bob --namespace payments` gives a one-time code; bob runs
  `kvo login SERVER --ca sha256:…` (browser sign-in; the control plane is its own OIDC issuer behind
  its private CA, pinned by fingerprint), and tokens go to the macOS Keychain. RBAC copied from
  Kubernetes (Roles, ClusterRoles, bindings; built-in cluster-admin / admin / editor / viewer /
  runner), `kvo ctx`, `kvo ns`, `kvo auth can-i`, ServiceAccount tokens for CI (`kvo create token`),
  and an audit log of every decision;
- many hosts: `kvoadm host add … --install worker [--region R] [--behind-nat]` sets up a worker-only
  machine that joins with a one-time token and only dials out. Hosts are on a WireGuard mesh run
  by the control plane (each its own silo subnet; boxes behind NAT reach each other through a relay,
  end-to-end encrypted inside it, so the relay sees only UDP). Placement by region/zone, host
  leases, `onHostLoss: Wait | Recreate` with agent-side fencing, `kvoadm host drain / uncordon / list`;
- services: every silo can carry its own (`spec.service`): a private name
  (`NAME.NAMESPACE.kevaso`, served on each worker), and exposure with `hostPort` or a load balancer
  (`worker-ip`, `ip-pool` from a host's extra addresses, or a plugin's class), raw TCP/UDP with the
  client's IP kept. An outside address is an `IP` object you keep (`kvo create ip`, `kvo get ips`,
  `kvo ip keep`), and there's no load-balancer object: a namespace's services of a class share one
  address and balancer on their own ports unless they name an `IP` or ask for a `dedicated` one.
  Its outbound address can be the host's, the service's (where the address is on the host; never a
  balancer's), or an IP of its own; `kvo describe silo` says whether in and out match, and why not. Silo-to-silo traffic is denied
  until the receiving silo's `allowFrom` opens it; exposing publicly needs its own permission;
- secrets: `Secret` values sealed with envelope encryption under a local KMS (a recovery key printed
  once by `kvoadm init`), never returned by reads; `Grant`s say what a silo may reach and use.
  Silos reach nothing outside the cluster without one. API keys are **injected** at the host's
  egress gate, so they never enter the silo; other secrets come over the silo's own vsock channel
  (`kvo-guest secret get`, tmpfs files, env for legacy apps); signing keys stay outside (`Sign`,
  with slashing protection). Per-secret RBAC (`list`, `use`, `read-value`, `write`, by name or
  label), write-only secrets, and rotation that reaches every silo using a secret;
- OpenShell runtimes: `runtime: openshell` (NVIDIA OpenShell's microVM, no network card) and
  `openshell-container` (its Docker driver, no KVM needed). kevasod installs the pinned release and runs
  its gateways under their own users in locked-down units, one per host, namespace or silo
  (`--openshell-gateway-scope`). Grants become OpenShell's policy and providers: the silo holds only a
  placeholder (`$API_KEY`) its programs send, and OpenShell swaps the real key in on the way out. What
  OpenShell can't do (services, address ranges, UDP, file/env/broker/sign) is refused when you apply;
- container runtimes: `runtime: docker` / `podman` on the same silo bridge as the VMs (firewall,
  default-deny egress, exposure and the egress gate apply unchanged), init steps as init containers,
  volumes that persist, the broker over a socket of their own;
- HTTPS: an ingress controller is a silo (`kvo-guest ingress`); `IngressClass` and `Ingress` route
  host names and paths to private silos, each Ingress opening exactly one path through the
  firewall. Certificates are automatic and renewed: Kevaso makes the key and keeps the lifecycle,
  and a **cert-controller** (`sdk/kcc`) turns a CSR into a chain. Built in: `acme` (Let's Encrypt or
  your own CA, cert-manager-style solvers: http01 through the ingress controllers, dns01 through a
  DNS provider program, wildcards) and `internal-ca`; anything else (certbot…) is a program on the
  control-plane host that Issuers can only name;
- backups: `kvoadm backup` writes the control plane's state sealed to the recovery key, and
  `kvoadm init --restore FILE` brings it back on a fresh machine, the master key rebuilt from the
  recovery key;
- providers: a plugin protocol (`sdk/kplugin`, gRPC over a unix socket, like CSI) for load-balancer classes,
  storage classes and DNS, installed with `kvoadm plugin install` as a hardened unit holding its
  cloud token alone. The first is [Linode](https://github.com/dlebee/kevaso-provider-linode):
  NodeBalancers, Block Storage volumes (formatted once, deleted with the silo), shared IPs announced
  over BGP that follow their silo to another Linode, and Linode DNS for Ingress host names;
- sets and images: an `Image` names what silos start from, with versions that never change (an OCI
  reference for containers, a checked disk image for VMs). A `SiloSet` is a scale set of stateful
  silos with stable names (`rpc-0`, `rpc-1`, …), spread over hosts, with booted standby instances,
  protected ones scale-in never removes (`kvo protect`), and rollouts that reset instances onto a new
  image a few at a time (or start extra ones first), volumes kept. `exclusive: true` guarantees one
  copy only. A standalone `Service` puts a virtual IP and a name in front of a set, on every worker,
  sending to the instances whose `readiness` check passes, and can take an outside address from a
  plugin's load balancer. `kvo scale`, `kvo reset`;
- under the hood: a store with global revisions and resumable watches, CEL validation, a controller
  engine; the testbed and end-to-end loop (`make e2e`).

What's planned, in order: [MILESTONES.md](MILESTONES.md).

## Develop

```bash
make race        # unit tests, every module
make e2e         # the test loop on a real machine
make workspace   # write ../go.work when provider repos sit next to this one
```

Go 1.27 (`toolchain go1.27.4`). Apache 2.0; contributions with a DCO sign-off ([CONTRIBUTING.md](CONTRIBUTING.md)).
