# ADR 0004: Images, SiloSets, standalone Services, updates

**Status:** accepted · **Date:** 2026-11-12

## Decision

1. **`Image` names bits, with immutable versions.** An Image (namespaced) lists versions, oldest
   first; each says where it is per runtime family: `container` (an OCI reference, for docker, podman
   and OpenShell) and/or `disk` (an https URL with its SHA-256, for cloud-hypervisor, which fetches it
   once and checks it). A version can't change once added (admission refuses it); a release is a new
   version. A silo's `image: NAME:VERSION` resolves through the Image of that name in its namespace
   (no version: the newest); a name with no Image is used as it is (`ubuntu-24.04`, `nginx:1.27`).
   The control plane resolves it once, into `status.image.ref`, and again only when `spec.image`
   changes, so creating an Image later never changes what a running silo is. Baking an Image from a
   `Template` is separate work, not in this milestone.
2. **Updating a silo is a reset, stop-first.** When `spec.image` resolves to something new, or
   `spec.reset` changes (`kvo reset silo`), the host's agent stops the silo completely, then the
   runtime's `Reset` (`kri.Resetter`, which every built-in runtime has) makes the disk or container
   fresh from the image, keeping the silo's name, address and volumes; `firstBoot` init steps run
   again. `status.image.running` says what it runs. A single silo's `update.strategy: StartFirst` is
   refused for now: it needs the old disk cloned, which comes with moves (M14).
3. **`exclusive: true` means one copy, ever.** It forbids `StartFirst` and automatic failover
   (`onHostLoss` must be `Wait`), and in a set it forces one instance at a time with no surge.
4. **`SiloSet` is a scale set of stateful silos** (design §0.2), not a Deployment. Instances are
   ordinary Silos named `NAME-0…`, owned by the set (an owner reference; the set's finalizer
   deletes them). Nothing is replaced to heal. The pure planner (`internal/controllers/siloset`):
   - **Scaling out** takes a booted `standby` instance first, then the lowest free name.
   - **Scaling in** removes not-Ready instances first, then follows `scaleInPolicy`
     (`NewestFirst`/`OldestFirst`), and never removes a protected one (`kevaso.com/protected`,
     `kvo protect`). `kvo scale` lists what it would delete and wants `--yes`.
   - **Rollouts.** A new template or image is a new *revision* (a hash, labelled on instances).
     With `upgradePolicy: Rolling` (or after `kvo reset siloset --rolling`, whatever the policy),
     outdated instances get the current spec; their agents reset them.
   - **Limits.** At most `maxUnavailable` (default 1) below `instances` are Ready during a
     rollout. `StartFirst` adds `maxSurge` (default 1) instances on the new revision first, and
     they go again when it's done. `Manual` (the default) reaches only new instances, plus the ones
     you reset.
   - **Spread.** `spread: host | zone | region` becomes the instances' `placement.spread`: the
     scheduler prefers the domain with the fewest of them, a preference, never a reason to wait.
5. **A standalone `Service` load-balances silos like kube-proxy.**
   - **Virtual IP.** It gets one from `10.65.0.0/16`, and the name `NAME.NAMESPACE.kevaso`, which
     wins over a silo of the same name.
   - **Endpoints.** Its endpoints are the Ready, non-standby silos its selector picks.
     `readiness` (a command run in the silo every `period`) makes Ready mean "answering".
   - **Rules on every worker.** Each worker DNATs the virtual IP from its silos to a random
     endpoint, which keeps the client's address, so the endpoint's `allowFrom` still decides.
     Default-deny holds through a Service.
   - **Same host.** A client and an endpoint on the same host are masqueraded once their
     connection is translated (the hairpin, as in kube-proxy), so the reply comes back through
     the translation; such an endpoint sees the host's gateway address.
   - **LoadBalancer.** `type: LoadBalancer` with a plugin's node-port class (e.g.
     `linode-nodebalancer`) gets node ports from 32000–32767; silos' own node ports are now
     30000–31999. Its backends are the hosts with endpoints, and each host sends the node port only
     to its own endpoints, so the client's address is kept as far as the host. Classes that route
     one address to one host (a shared IP) are refused for a Service.
   - **Permission.** Exposing publicly stays its own permission (`create` on
     `services/expose-public`): for a Service of type LoadBalancer, and for a SiloSet whose
     template exposes its instances (its controller creates them, so the check is on the set).

## Why

Stateful instances want deliberate, visible updates (a reset onto an image, never a silent
replacement). Validators and other single-writer workloads need a guarantee, not a convention, that
two copies never run. A set's StartFirst gives zero-downtime rollouts without cloning anything, by
adding an instance instead of copying one. A virtual IP with per-worker rules needs no proxy process,
keeps client addresses and works for TCP and UDP alike.

## Not yet

- Applying other spec changes (CPU, memory, command) to a running silo: today they take effect at
  its next reset.
- Cluster-wide Images.
- Baking Images from Templates.
- Single-silo StartFirst (M14).
- Handing out standby instances to runs (M13).

## Tested by

- `api/v1` (image resolution).
- `internal/controllers/siloset` (scale out/in, protected, standby, rollouts with maxUnavailable,
  surge and exclusive, Manual + reset).
- `internal/controllers/service` (endpoints, addresses, node ports).
- `builtin/kni` (virtual IP and node-port rules, allowFrom through a Service).
- `internal/agent` (an image change and a reset are stop-first, init runs again; readiness).
- `test/integration/sets_test.go`: example 07 in a control plane with a fake plugin, with a rolling
  upgrade never more than one down, admission refusals, scale-in sparing a protected instance, and
  deletion.
- `test/e2e/sets_test.go`: two hosts, a Service reached by name across the mesh, a stranger
  refused, a rolling upgrade keeping volumes, scale-in, reset.
