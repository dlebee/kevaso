# 4 · People and access

You're the cluster admin. This page adds a colleague who works in one namespace and sees nothing
else, then a token for CI.

---

## How sign-in works

The control plane is its own sign-in provider (OpenID Connect). People get in with a **one-time
invite code**, then hold short-lived tokens that refresh themselves:

```mermaid
sequenceDiagram
  participant Admin
  participant Bob as Bob's kvo
  participant CP as Control plane
  Admin->>CP: kvoadm users invite bob --namespace payments
  CP-->>Admin: kvo login command + one-time code
  Admin->>Bob: sends both (chat, email)
  Bob->>CP: kvo login … (checks the CA fingerprint)
  Note over Bob: browser opens, Bob pastes the code
  CP-->>Bob: 15-minute access token + refresh token
  Note over Bob: tokens go to the OS keychain
```

| | Lives | Where |
|---|---|---|
| Invite code | 15 minutes, used once | Sent to the person |
| Access token | 15 minutes | Memory, sent with each request |
| Refresh token | Rotates on every use | macOS Keychain (or a 0600 file on Linux) |

---

## Invite someone

```bash
bin/kvoadm users invite bob --namespace payments
```

It binds bob as `editor` in `payments` (`--role admin` or `viewer` for others) and prints two things
to send him: the `kvo login …` line and the code.

---

## They sign in

On bob's computer:

```bash
kvo login https://203.0.113.10:6443 --ca sha256:4b1d…
```

His browser opens a "Sign in to Kevaso" page; he pastes the code. The `--ca` fingerprint is how his
`kvo` knows it's talking to *your* cluster: it refuses any other certificate, so no warning to click
through.

```bash
kvo auth whoami
```

```bash
kvo ns payments
```

`kvo ns` sets his default namespace. He can now `apply`, `get`, `exec` in `payments`, and sees no
other namespace.

---

## Roles

Permissions work like Kubernetes RBAC: **Roles** list verbs on resources, **RoleBindings** give a
role to people in a namespace. The built-in roles:

| Role | Can |
|---|---|
| `viewer` | Read silos, service accounts, grants; see that secrets exist |
| `editor` | Everything `viewer` can, plus create and change silos, `exec`, service-account tokens; create and *use* secrets (never read a value back) |
| `admin` | Everything `editor` can, plus roles and bindings in the namespace, exposing silos publicly, reading secret values |
| `cluster-admin` | Everything, everywhere (what `kvoadm init` gives you) |

Ask the cluster what you may do:

```bash
kvo auth can-i create silos/exec -n payments
```

It exits 0 for yes and 1 for no, so it fits in scripts.

---

## Contexts

Like kubeconfig contexts: one per cluster you use.

```bash
kvo ctx
```

```bash
kvo ctx home
```

The file is `~/.kevaso/config.yaml` (or `$KVO_CONFIG`). It holds addresses, CA fingerprints and
certificate paths, never tokens.

---

## Tokens for CI

A **service account** is an identity for a script or a pipeline:

```bash
printf 'apiVersion: kevaso/v1\nkind: ServiceAccount\nmetadata: { name: deployer, namespace: payments }\n' | kvo apply -f -
```

Give it a role with a RoleBinding (subject kind `ServiceAccount`), then mint a token:

```bash
kvo create token deployer -n payments --duration 1h
```

In CI, set `KVO_TOKEN` to it (and `KVO_CA_FILE` to the cluster CA). Deleting the service account
revokes every token it has.

---

## Removing someone

```bash
bin/kvoadm users disable bob
```

His tokens stop working at once: every request checks that the person is still enabled.

---

## The audit log

Every decision about a person or service account (allowed or refused), every sign-in, every secret
read and every broker call is written to `/var/lib/kevaso/audit.log` on the control plane, one JSON
object per line. See [Operating](09-operations.md#the-audit-log).

Next: **[More machines →](05-more-machines.md)**
