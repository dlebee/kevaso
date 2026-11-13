# ADR 0006: Plugin operators

**Status:** accepted · **Date:** 2026-11-13

## Context

Design §6's second rule: a plugin that adds a kind brings a `KindDefinition` and its own
controller, which talks only to the Kevaso API, as its own `ServiceAccount` (§4.3), and the
definitions belong to the plugin (§4.2): uninstalling it removes them, refused while objects are
left unless forced. ADR 0005 made kinds and policies definable; this ADR is how a plugin ships
and installs them with its controller. The product built on Kevaso (its `Session` and `Task`
kinds) is the user; `examples/operator-session/` is the worked example.

## Decision

1. **A package is a directory of files a person can read**, nothing packed or generated:
   `plugin.yaml` (`apiVersion: kevaso/v1`, `kind: PluginPackage`, `metadata.name`,
   `spec.version` (semver), `spec.description`, `spec.controller.binary`: the controller
   program, a file in the package built for the host, and `spec.resources`: YAML files in the
   package) and those files, holding only `KindDefinition`s, `ValidationPolicy`s and
   `MutationPolicy`s, and the `ClusterRole`s and `Role`s its controller gets. Anything else is
   refused.
2. **Package checks** (`internal/operators.Check`), before anything is written:
   - policies match only the package's own kinds (by resource, `PLURAL.GROUP`), never a built-in
     kind or `*`, so installing a plugin never changes how the cluster's own objects are admitted;
   - roles never use `*` (verbs or resources), never reach RBAC (`roles`, `rolebindings`,
     `clusterroles`, `clusterrolebindings`), `serviceaccounts/token`, `kinddefinitions`,
     `validationpolicies`, `mutationpolicies` or `plugins`, and never `read-value` or `approve`
     on secrets: a plugin's controller can't make itself more than its package says, and is never
     cluster-admin;
   - policies and roles are named `PLUGIN-…`, so whose they are is plain in `kvo get`.
3. **The operator confirms what the controller may do.** `kvoadm plugin install` prints every
   rule the controller will have (each role, and where it applies) and the two every controller
   gets to run at all, and installs only on `yes` (`--yes` for scripts).
4. **The controller's identity is a service account, `kevaso-system/plugin-NAME`,** bound to
   exactly the package's roles (a ClusterRole by a ClusterRoleBinding, a Role by a RoleBinding,
   each under the role's name), plus `plugin-NAME-self`: `get` on `plugins` and `update` on
   `plugins/status`, for its own Plugin only (its heartbeat), and `create` on
   `serviceaccounts/token` for its own account only (renewing its token).
5. **Credentials are short-lived, renewed by the controller, and never on a command line.** The
   install mints an hour's token for the service account (the cluster's OIDC issuer, M4) and puts
   it with the API's URL, the cluster CA and `plugin.json` (name, version, account) in
   `/etc/kevaso/plugins/NAME/` on the host, root only. The controller runs as a systemd unit
   (`DynamicUser`, the plugins' sandbox from ADR 0003) that gets them through `LoadCredential`
   (`$CREDENTIALS_DIRECTORY`, readable by the unit alone). `sdk/operator` renews the token at
   half its life with the token itself and keeps the new one in the unit's `StateDirectory`
   (kept across restarts). A controller down for longer than its token lasts needs
   `kvoadm plugin install` again, which hands it a new one. Deleting the service account revokes
   every token it has (tokens carry its UID).
6. **Ownership is recorded on a `Plugin` object** (built-in, cluster-scoped, named after the
   package): its version, where the controller runs (the SSH target) and as whom, and `owns`:
   everything the install made. Each of those carries an owner reference to the Plugin. Install
   decides per object: missing → create; this plugin's → update (an upgrade); another plugin's →
   refused; nobody's → refused unless `--adopt`. An upgrade deletes what the new version no longer
   has. While a Plugin is installed, its `KindDefinition`s can't be deleted on their own (409,
   "kvoadm plugin uninstall removes it").
7. **Uninstall** (`kvoadm plugin uninstall NAME [--force]`) is refused while any kind it owns has
   objects, listing how many. Otherwise, or with `--force`: it deletes the Plugin (its finalizer,
   `kevaso.com/plugin-uninstall`, holds it, and from then on its definitions may be deleted);
   with `--force` it deletes the kinds' objects, waits up to 30s for the still-running
   controller's finalizers, and then removes what's left of them; it stops and removes the
   controller's unit, binary and credentials on the host; deletes everything the Plugin owns,
   last first; and lets the Plugin go. Run again, it finishes an uninstall that stopped half-way.
8. **`kvoadm plugin list`** shows each plugin's version, the kinds it owns, whether its controller
   runs (a heartbeat in `status.controller` within the last 90s; `sdk/operator.Heartbeat` writes
   one every 30s), and its host. `kvoadm plugin install … --package` installs an operator;
   without `--package` it still installs a provider plugin (ADR 0003).
9. **One code path.** `internal/operators` does the install, uninstall and list through the API
   and a `Host` (start and stop the controller). kvoadm's host is SSH and systemd; the
   integration test's runs the example's controller program in the test on the same credentials.

## Why

Files over an archive: an operator reads exactly what will be applied and what the controller
may do before saying yes, and reviews a new version as a diff. A service account with renewable
hour-long tokens over a client certificate: the cluster already issues and revokes them (deleting
the account), RBAC already names them, and nothing long-lived sits on the host. Owner references
over a label: they say which Plugin (by UID) and are what Kubernetes users expect.

## Left for later

Signed packages (a signature over `plugin.yaml` and its files, checked like binaries), running a
controller in a container or a silo (design §6: `isolation`), more than one copy with leader
election through `Lease`, garbage collection by owner references in general (the example uses a
finalizer for its silos), and installing the controller on every control-plane host.

## Tested by

`internal/operators` (package checks, ownership decisions, the uninstall rule, the self roles),
`internal/cli/kvoadm` (the unit: credentials only through `LoadCredential`), `sdk/operator`
(renewal at half life, the state file, the expired message), `internal/schema` and
`internal/apiserver` (scale, `oldSelf`), and `test/integration/operator_test.go`: the example
installed through `operators.Installer` with the host faked, its controller as
`plugin-sessions` (can't read secrets or bind itself cluster-admin), a Session's silo and status,
scale through `/scale` and `kvo scale`, the transition rule and policy, a heartbeat in the list,
uninstall refused with a session left, done after, and its token revoked.
