# ADR 0006: More than one system node, the light node, rolling upgrades

**Status:** accepted · **Date:** 2026-11-13

> **Note (2026-11-13):** `Host.Spec.Address` is gone (ADR 0009): peers use the host's reach address, its external IP if it has one, else its internal IP.

## Context

Design §3 and §4.1: HA is 3 or 5 system nodes, or two plus a **light system node** (an etcd member
only) as the third vote; embedded etcd; any system node serves the API, one runs the controllers;
no VIP, clients and agents fail over themselves; `kvoadm upgrade` rolls control planes first, then
workers. The etcd store, the embedded member and the pure membership decisions (`etcd.NextStep`)
were already in (M16, first half). This ADR is the second half.

## Decision

1. **Joining is a token and a sealed answer.** `kvoadm host add … --install control-plane
   [--state-only]` declares the Host, mints a one-time join token with the role `system-node`, and
   starts `kevasod control-plane --join URL,… --store etcd --etcd-peer-listen ADDR:2380`. On its
   first start the node makes a key, presents the token and the key's public half at
   `POST /join/system-node`; the control plane adds it to etcd **as a learner** and answers with
   the member list and the cluster's identity — the CA, plus the master key unless the node is
   state-only — **sealed to that key**. kvoadm never sees the identity. The token is checked
   before anything else (an unauthenticated caller learns nothing, not even the store type) and
   spent only when the join succeeds. The answer is kept in `<data>/etcd/join.json` until the
   member has data, so a restart mid-join doesn't need a new token. One system node joins at a
   time (etcd allows one learner; `NextStep` waits on a learner).
2. **A cluster on SQLite is told, not switched.** host add refuses with the command to run:
   `kvoadm store migrate [USER@]ADDRESS --ssh-key PATH`, which rewrites that control plane's unit to
   `--store etcd --etcd-peer-listen ADDR:2380` and restarts it (store.db moves into etcd on that
   start). Not automatic because it restarts the only API server (every watch re-lists) and needs
   SSH to that machine, which host add doesn't have: one explicit, visible step.
3. **The leader's member controller** promotes a learner once etcd agrees it has caught up (it
   refuses earlier; the controller asks again next round) and removes members whose Host no longer
   asks for one — one `NextStep` at a time, never losing the healthy majority. It never adds
   learners: only a join does, so a merely declared Host doesn't dangle in the store.
   **Health** is the Host heartbeat (`lastHeartbeat` within the host lease) for voters; a learner
   counts as up once it has started (it can't heartbeat: a learner serves no reads). The light
   node, with no API server, heartbeats by writing its Host into the store directly
   (compare-and-swap, like any update). Membership and leadership show in
   `Host.status.controlPlane.{member,leader}`.
4. **Peers talk over `Host.Spec.Address`, not the mesh.** The mesh is configured by the control
   plane from the store; the store can't depend on it (a store without quorum couldn't repair the
   network it needs to regain quorum), and the light node runs no mesh agent. Peer traffic is mutual
   TLS with member-only certificates (CN `kevaso-etcd`, nothing else from the CA is accepted), so
   the public address is safe; the firewall should open 2380 between system nodes only. The
   annotation `kevaso.com/etcd-peer-url` overrides the URL (another port; tests).
5. **Member certificates rotate in place.** Each member checks its certificate twice a day and
   replaces it 30 days before its end (1-year certificates). etcd re-reads its certificate files at
   every handshake, and so do our clients of it, so rotation is writing the files (by rename); open
   connections keep the old, still valid, one. No member or cluster restart.
6. **Leader election through the store.** One `Lease` record (kind `Lease` in the store directly,
   like join tokens), every write a compare-and-swap on its revision: two candidates can never win
   the same revision. A candidate takes over only after seeing the revision unchanged for a whole
   `Lease` (15 s) **on its own clock**; a leader stops at `RenewDeadline` (10 s) after its last
   renewal that went through, on its own clock, with a watchdog independent of a stuck store call.
   No clock is compared across machines. Each takeover is a new term. A node shutting down
   releases the lease, so the next one starts at once. The controllers, the scheduler (in the silo
   controller), approval expiry and the member controller run in the term's context.
7. **Every system node serves the API; clients take a list or a DNS name.** `kvo` contexts and
   `kevasod worker --server` take comma-separated URLs; the client sticks to the last one that
   answered and moves on only when a request couldn't reach a server at all (a dial error: nothing
   was sent, so nothing is sent twice). A DNS name with one record per system node fails over the
   same way, by Go's dialer. `--cluster-dns NAME` puts that name in every node's certificate and
   makes it the one OIDC issuer URL, so login tokens work at any node. host add appends the new
   node's URL to the kvo context.
8. **Agents hold one tunnel per system node** (instead of routing exec between system nodes). The
   agent reads the system nodes' `status.controlPlane.apiURL` and keeps a dial-out tunnel to each,
   so an exec arriving anywhere finds the host's tunnel locally. No control-plane-to-control-plane
   hop (no second authentication, no node depending on another being up); losing a node loses only
   its own tunnels, every other node already has one; system nodes are few, so the extra
   connections cost nothing, and they are still dial-out (NAT-friendly).
9. **Version-skew rule** (`internal/upgrade`): (a) an upgrade only moves forward, by at most one
   minor within one major (a major comes with its own migration; never skip a minor); (b) system
   nodes may be at most one minor apart; (c) an agent is never newer than the oldest system node and
   at most one minor older. Hence the roll order: every system node first, then workers. The plan
   refuses a cluster already outside the rule.
10. **`kvoadm upgrade`** is a pure plan plus an executor. Plan: system nodes one at a time — light
    nodes first, the controllers' leader last (one handover, not one per step) — then workers in
    batches (`--batch`, default 2). Refused when restarting one system node would lose the healthy
    majority, and for two system nodes without a third vote. The executor checks the majority before
    each system node, installs, and waits until the host is Ready again and reports the new version;
    it stops at the first failure and says what's left. kvoadm's driver installs as install does:
    it signs the binary, the host verifies the signature with `openssl` against the key pinned at
    setup (E018) before swapping it in, then `systemctl restart kevasod`. The target version comes
    from the binary (`-X kevaso.com/core/internal/version.Version=…`) or `--version`. Hosts report
    theirs in `status.version`.

## What a worker's restart does to its silos

The agent restarts; silos keep running because no runtime keeps them inside kevasod's process:
**cloud-hypervisor** runs each VM as its own systemd unit, **docker/podman** containers belong to
their daemon, **OpenShell** sandboxes belong to its gateway unit. What is inside kevasod, and so
blips for the seconds of a restart: the silo DNS server, the egress gate (outbound HTTPS with
injected secrets), the secret broker listeners (recreated on start), open exec and pane streams,
and the agent's tunnels. Not yet true: nothing makes those survive; making the DNS server and the
egress gate their own small units is the fix when it matters.

## Left out

- **Self-update without SSH** (design §3.1: kevasod updates itself to signed versions): the
  executor's driver is SSH today; an agent-pulled driver fits the same `Driver` interface.
- **The worker inside a control plane** (HA compact) holds one tunnel, to its own node: an exec
  to its silos arriving at another node gets `HostNotConnected` until it holds per-node tunnels
  with a host certificate of its own.
- **KMS rotation on an HA cluster** is refused: each system node keeps its own copy of the
  master key file, and a key rotated on one would leave the others unable to open new secrets.
  Rotation handed to every node (or a shared KMS) is the follow-up. OIDC authorization codes are kept in memory per node (a login's
  two steps must land on one node; the sticky client does that).
- **`kvoadm doctor` warnings** (slow store member, two voters without a third) and **primary +
  standby** (`kvoadm promote`) are not built.
