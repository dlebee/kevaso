# OpenShellPolicy

A namespaced kind for the egress OpenShell can express and a Grant cannot: a rule with a path
glob, read-only or read-write access, an optional protocol (`rest`), and the binaries that may use
it. Grants stay host:port. A silo on `openshell` or `openshell-container` lists policies by name
(`spec.openshellPolicies`, its own namespace, in order). A SiloSet template carries the same field.
Any other runtime that names one is refused.

## The object

```yaml
apiVersion: kevaso/v1
kind: OpenShellPolicy
metadata: { name: example, namespace: dev }
spec:
  networkPolicies:          # 1 to 32
    - name: web             # unique, a DNS label
      endpoints:            # 1 to 16
        - host: example.com # a name, or one public IPv4 address
          port: 443         # 1 to 65535
          protocol: rest    # optional; only rest
          path: /           # optional absolute glob
          access: read-only # optional: read-only | read-write
      binaries:             # optional, 1 to 16; omitted means every binary
        - path: /usr/bin/curl
```

Unknown fields are refused. A host that is an address or CIDR inside a closed range (silo, service,
mesh, loopback, link-local: `v1.ClosedRange`) is a 422 that names the range. Any other address that
is not one public IPv4 address is refused too: hosts are names or public addresses. List caps match
the bound a grant already hits when it is rendered for OpenShell (`maxPolicyPorts`, 16 destinations
per rule); a policy holds at most 32 rules, and a silo names at most 32 policies.

## One policy file

`policy.For` turns the silo's Grants and its OpenShellPolicies into one `kri.Policy`. `PolicyYAML`
writes one file: grant endpoints stay `kv_N` (sorted by host, then port); each OpenShell rule is
`osp_<policy>_<rule>`, so the names never collide. Policies follow the silo's list, rules and
endpoints stay in the object's order. Binaries default to `/**`. No grant endpoints and no rules
is the same deny-all as today (no `network_policies` key).

A name that is not in the cache is skipped, as `GrantsFor` skips a missing grant. A person
attaching a name that does not exist gets the same 422 (`doesn't exist in namespace`). Grants do
not add a condition for a name that disappears later, and neither does this: the next push omits
it, and `PolicyApplied` reports what remains.

## Sync, reads, roles

The agent watches OpenShellPolicy the way it watches Grant, and requeues local silos that list the
one that changed, appeared, or was deleted. That is the existing `SetPolicy` path, hash included,
including the file staged before a sandbox is created.

A worker may read an OpenShellPolicy only when a silo on that host names it (`status.host` or
`status.movingFrom`), in the silo's namespace. Same rule as Grant.

`openshellpolicies` is on the same built-in roles as `grants`: editors create them in their
namespace, viewers read them. `kvo get`, `apply`, `describe`, and `delete` use the kind registry.
