# ClusterSecret (v1)

Owner's decisions (2026-11-15): a secret with no namespace, for things with no namespace. No backward
compatibility. Delegation to namespaces is a later feature, defined by policies on the ClusterSecret;
v1 must leave room for it but not build it.

## The kind

```yaml
apiVersion: kevaso/v1
kind: ClusterSecret
metadata:
  name: bucket-secret-key          # no namespace
spec:
  description: "JuiceFS bucket secret key"   # optional
  plugins: [juicefs]               # required: the plugins that receive it (by plugin install name)
  hosts: []                        # optional: host names; empty = every host that runs one of those plugins
status:
  version: 3                       # bumps on every value change
  changedAt: ...
```

- Cluster-scoped (no namespace), like Host or Namespace. Stored sealed, the same way Secret values are.
- The value is write-only: `kvo create clustersecret NAME --plugin juicefs --from-file F` (or `-`),
  `kvo set clustersecret NAME --from-file F` to rotate. `kvo get clustersecret NAME` shows spec and status, never
  the value; `--reveal` works for cluster admins only, exactly like Secrets.
- Leave room, do not build: a later `spec.delegate` (namespaces that may *use* it). v1 rejects unknown fields as
  usual, so nothing to add now beyond not using the name `delegate` for anything else.

## Who can do what

- Create, update, delete, get, list, reveal: cluster-admin only (`rbac.Policy.ClusterAdmin` or the built-in
  cluster-admin role). No namespaced role, binding or grant can name a ClusterSecret. A namespaced object that
  references a ClusterSecret is refused at admission (there is none in v1; make sure grants' `secrets` and
  `container.pull.secretRef` can't resolve to one).
- A host (worker or system node certificate) may read the VALUE of a ClusterSecret only if its `spec.plugins` is
  non-empty and its `spec.hosts` is empty or names that host. Through a dedicated route, e.g.
  `GET /apis/kevaso/v1/clustersecrets/NAME/value` with the host's identity; every other identity is refused
  (403), and listing values is never possible. A host may list ClusterSecrets (names, spec, status) so it can see
  which ones are for plugins it runs.

## Delivery to plugins on a host

Today: `kvoadm plugin install --credential NAME=FILE` copies FILE to the host (root only) and the plugin's systemd
unit reads it with LoadCredential; the plugin reads it from `$CREDENTIALS_DIRECTORY` via `operator.FromEnv()` /
the sdk.

v1:
- `--credential` is removed from `kvoadm plugin install`. Nothing else changes for the plugin: the same names, the
  same credential directory, the same sdk call.
- kevasod (the agent) on each host watches ClusterSecrets. For each plugin installed on this host
  (`/etc/kevaso/plugins/NAME/` or wherever install puts them; read plugin.go), for each ClusterSecret whose
  `spec.plugins` contains that plugin name and whose `spec.hosts` is empty or names this host: fetch the value
  and write it, root only (0600, owned root), to the same path `--credential` used to write. That file IS the
  host's cache: it stays while the control plane is unreachable, and volumes keep mounting.
- On a value change (status.version), rewrite the file atomically (write temp, fsync, rename) and restart that
  plugin's unit(s) so LoadCredential picks it up. Do not restart if the bytes are the same.
- When a ClusterSecret is deleted, or no longer names this plugin/host, the agent does NOT delete the cached file
  while held or while the control plane is unreachable (a worker keeps its last state); it removes it only on a
  DELETED event or a spec change seen on an accepted history while not held, the same rule as seen deletes.
- Never log the value. Never pass it on a command line or environment of a child process other than through the
  existing systemd credential path.

## Out of v1

- Per-volume buckets from a namespace Secret; namespaces using a ClusterSecret; templated references.

## Done when

- `make race vet lint`, `go run ./hack/mutate -check` green; new tests for: cluster-admin only (each verb, plus a
  namespace admin refused); value route refused to non-hosts and to hosts not named; delivery writes the file 0600
  and restarts on change only; a held or cut-off agent keeps the file; delete removes it only when not held.
- provider-juicefs and provider-linode docs and the kevaso docs say `kvo create clustersecret` instead of
  `--credential`.
