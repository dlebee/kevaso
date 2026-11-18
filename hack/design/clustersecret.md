# ClusterSecret (v1)

Owner's decisions (2026-11-15): a secret with no namespace, for things with no namespace. Access is plain RBAC,
pinned to names: a ClusterRole with `resourceNames`, bound to the plugin's service account, so a storage class's
controller reads exactly its own secrets and nothing else. No backward compatibility. Delegation to namespaces is
a later feature (a `use` verb through bindings); v1 leaves room for it and does not build it.

## The kind

```yaml
apiVersion: kevaso/v1
kind: ClusterSecret
metadata:
  name: bucket-secret-key          # no namespace
spec:
  description: "JuiceFS bucket secret key"   # optional; nothing else in spec
status:
  version: 3                       # bumps on every value change; set by the server only
  changedAt: ...
```

- Cluster-scoped, stored sealed like Secret values. The caller's `status` is dropped on create and on update.
- Value write-only: `kvo create clustersecret NAME [--description D] --from-file F|-`,
  `kvo set clustersecret NAME --from-file F|-` (rotate), `kvo get clustersecret [NAME] [--reveal]`,
  `kvo delete clustersecret NAME`.

## Who can do what

- **Manage** (create, update, delete, and `--reveal`): cluster-admin only (`rbac.Policy.ClusterAdmin`). No role,
  whatever it says, grants these on clustersecrets.
- **get, list** of the objects (name, description, status; never a value): cluster-admin, and any identity a
  ClusterRole grants `get`/`list` on `clustersecrets` (pinned or not: names and versions only).
- **Read one value**: `GET /apis/kevaso/v1/clustersecrets/NAME/value`. Allowed for cluster-admin, or for an identity
  holding, through a **ClusterRoleBinding** to a **ClusterRole**, a rule with resource `clustersecrets/value`, verb
  `get`, and `resourceNames` containing NAME. A rule with empty `resourceNames` does NOT grant a value (always pinned).
  A namespaced Role or RoleBinding never reaches a ClusterSecret: refuse a Role that names `clustersecrets` or
  `clustersecrets/value` at admission, with a message saying to use a ClusterRole.
- **Hosts on behalf of a plugin** (the node side, see delivery):
  `GET .../clustersecrets/NAME/value?for=PLUGIN` with a host certificate (worker or system node). PLUGIN is a DNS
  label. Allowed only if the service account `plugin-PLUGIN` in namespace `kevaso-system` would itself be allowed to
  read NAME by the rule above. There is no Plugin object in this check. The host has no ClusterSecret access of its own.
- **Namespace `kevaso-system` is reserved.** A person or a service account may create, update or delete any object
  in it — service accounts, roles, role bindings, secrets, `serviceaccounts/token`, and everything else — or delete
  the namespace, only as a cluster-admin (`rbac.Policy.ClusterAdmin`, or the admin socket). Anyone else gets 403,
  whatever their roles or bindings say, except a plugin's own service account posting a token for that same
  account (its controller renews the token it runs as, and nothing else). A RoleBinding in another namespace does
  not apply: a namespaced binding reaches only its own namespace. get and list stay with RBAC. kevasod's own
  controllers, and a worker writing a status it may already write, are not these callers.
- No namespaced object may reference a ClusterSecret (grants' secrets, container pull secretRef).

## Delivery to plugins on a host

Today: `kvoadm plugin install --credential NAME=FILE` copies FILE to the host (root only); the plugin's systemd
unit loads it with LoadCredential; the plugin reads it from `$CREDENTIALS_DIRECTORY` via the sdk.

v1:
- `--credential` is removed from `kvoadm plugin install`, replaced by `--cluster-secret NAME` (repeatable): the names
  the plugin's unit will find in its credential directory. Install records them in the same place it recorded the
  credential list. When any name is given, it makes sure namespace `kevaso-system` and service account `plugin-NAME`
  exist (create if missing, leave them if present) and prints which account to bind. It does not create a role or a
  binding: the admin pins the names in a ClusterRole and binds that account. Removing the last side on the host
  deletes the service account. The plugin and the sdk do not change.
- kevasod on each host, for each plugin installed there and each recorded cluster-secret name: fetch it with
  `?for=PLUGIN`, write it root-only (0600, owner root) to the same path `--credential` used, atomically (temp in
  the same dir, fsync, rename). That file is the host's cache: volumes keep mounting while the control plane is away.
- Watch ClusterSecrets (names and status.version only) to notice rotations; on a version change rewrite and restart
  that plugin's unit(s); unchanged bytes: write nothing, restart nothing.
- 403 or a deleted ClusterSecret: remove the cached file ONLY when the agent is not held and the answer came on an
  accepted history (the seen-delete rule); held or cut off: keep it. Restart the plugin after a removal.
- Never log the value; never pass it on a command line or a child's environment.

## Out of v1

- Namespaces using a ClusterSecret; per-volume buckets from a namespace Secret; templated references.

## Done when

- `make race vet lint`, `go run ./hack/mutate -check` green; tests: manage is cluster-admin only (a ClusterRole
  granting create/delete still refused); a pinned ClusterRole bound to an SA reads exactly its names and not
  another; an unpinned rule reads none; a Role naming clustersecrets is refused; `?for=PLUGIN` is service account
  `plugin-PLUGIN` in `kevaso-system` (a DNS label, no Plugin object) and only when that account may read the name;
  delivery writes 0600 and restarts on change only; held keeps the file; seen delete removes it.
- provider-juicefs, provider-linode and kevaso docs use `kvo create clustersecret` + a ClusterRole/Binding +
  `--cluster-secret` instead of `--credential`.
