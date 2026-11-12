# Milestones

> The order below is the proposal we agreed to start with. It sets the build order only and can change
> at any time; the design (in the private idealization repo) is the scope.

Every milestone ends with **green unit tests** for what it adds, and from M3 on with an end-to-end run of
the test loop (create machines → `kvoadm` → test → tear down) on Lima locally and on GitHub's
`ubuntu-latest` runner in CI. Milestones set the build order only; everything in the design is in scope.

Unit-test style for every package (see `docs/adr/0001-testing.md`):
- logic as pure functions (`decide(desired, observed) → plan`), tested with tables;
- controllers against the in-memory store, fake clock and fake plugins; assert the **end state**;
- every fake plugin passes the same conformance suite as the real ones;
- `go test -race ./...` in CI, plus a goroutine-leak check.

| # | Milestone | What's inside | Unit tests that close it | Done when |
|---|---|---|---|---|
| **M0** ✅ | Foundations | Core repo with 3 Go modules (`core`, `api`, `sdk`), workspace script, lint + import boundaries, CI (race, DCO), **testbed** (Lima driver) and the empty test loop | testbed: names, tags, `limactl` commands, sweep of leftovers; boundaries enforced by lint | `make e2e` creates a Lima VM, checks KVM, deletes it; CI green |
| **M1** ✅ | API core | `kevaso/v1` types (Host, Namespace, Silo), `Store` (memory + SQLite), resourceVersion and optimistic concurrency, watch, API server pipeline (defaults → OpenAPI + CEL validation → store), controller engine (queues, dedup, backoff), controller runtime + fakes | store conformance suite (memory and SQLite pass the same tests), conflict on stale resourceVersion, watch resume from a revision, CEL rules, engine dedup / backoff / requeue | `kvo` against an in-process server creates, watches and updates objects |
| **M2** ✅ | Control plane on a host | `kvoadm init` over SSH (host-key check, root password once: E016–E018), `kevasod` control-plane component, private CA + TLS, admin socket, join tokens + CSR (E019) | SSH bootstrap against a fake SSH server, token single-use / expiry / role checks, CSR filtering, certificate role → authorization | `kvoadm init` on a Lima VM → `Host` Ready |
| **M3** ✅ | First silo | Worker component, plugin registration, `cloud-hypervisor` runtime (locked down: E010), `local` storage on thin LVM (E012), KNI bridge + nftables, scheduler (runtime, labels, taints, storage, capacity), Silo controller, **init steps**, `kvo apply / get / exec` through the dial-out channel (E020) | scheduler filters and scoring tables, Silo `decide` for every state transition, init step runner (order, failure → `InitFailed`), nftables rule generation, registration handshake | **example 01** works; first demo walkthrough |
| **M4** ✅ | Users | OIDC issuer + `kvo login` (E022), contexts, RBAC, ServiceAccounts, audit log | RBAC evaluation tables, token issue/verify, PKCE flow, audit entries | a second user only sees their namespace |
| **M5** ✅ | Many hosts | `kvoadm host add`, WireGuard mesh with diff updates (E023), relay with inner tunnel (E024), regions, `onHostLoss` Wait / Recreate, drain | peer-diff calculation, relay routing plan, host-loss decisions, drain plan | **example 02** plus a home box behind NAT |
| **M6** ✅ | Services & exposure | Private service names, `allowFrom`, `hostPort`, `worker-ip` / `ip-pool`, `IPPool`, `egress.source` (E009) | DNAT/SNAT rule generation per case, IP allocation from pools, admission refusals (e.g. `sameAsService` on a NodeBalancer) | **examples 03, 06** |
| **M7** ✅ | Secrets | Local KMS + recovery key, Secret, Grant, vsock broker with identity from the channel (E014), Sign (E015), egress gate injection (E025), per-secret RBAC, "only your own secrets", rotation | envelope encryption, grant resolution, broker authorization, gate allow/deny tables, rotation fan-out | a key works in a silo but never appears inside it |
| **M8** ✅ | OpenShell runtimes | `openshell` and `openshell-container` runtimes, `gatewayScope`, Grant → OpenShell policy + provider (E026–E028, E033, E035) | policy/provider mapping tables, capability reporting, gateway unit generation | an OpenShell silo with an injected key, both drivers |
| **M9** ✅ | Container runtimes | `docker` / `podman`, volumes for persistence, init containers | container spec generation, volume mapping, init container ordering | **example 05** on Linode workers (container silos verified on Lima; the Linode run comes with M11's load balancers) |
| **M10** | Ingress & certificates | Ingress controller silo, `IngressClass`, Certificate / ACME | routing config generation, certificate renewal decisions | **example 04** |
| **M11** | Linode provider | `kevaso-provider-linode`: DNS, NodeBalancer, shared IP (lelastic: E031), Block Storage with detach deadlines (E032) | API calls against a fake Linode API, retry / deadline logic | NodeBalancer and volume for container silos on Linode |
| **M12** | Sets & images | `Image`, `SiloSet`, standalone `Service`, update strategies, `exclusive` | scale-in / rolling-update plans, `exclusive` never two copies | **example 07** |
| **M13** | Runs | `Run`, scoped network, gateway egress, outputs | scope enforcement rules, teardown plan | **example 08** |
| **M14** | Global volumes & moves | `juicefs` class via virtiofs (E029), `onHostLoss: Move`, `kvo move` | move plans, fencing decisions | a silo restarts in another region with its files |
| **M15** | Inside the silo & panes | daemons + upkeep, pane protocol (E033), desktop panes app with the E034 rules, `kvo ui` | report limits, opaque storage, upkeep scheduling; the hostile-pane suite as a regression test | the phone + Claude + panes demo |
| **M16** | HA & operations | Embedded etcd + SQLite migration (E021), light system node, backup / restore, rolling upgrades | migration ordering, backup format round-trip, upgrade plans | lose one of three system nodes, nothing stops |
| **M17** | Extending | `KindDefinition`, `ValidationPolicy` / `MutationPolicy`, plugin operators | schema + CEL from definitions, admission policy evaluation | a plugin adds a kind with its own controller |
