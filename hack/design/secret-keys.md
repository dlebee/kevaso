# Secret keys (v1)

Owner's decision (2026-11-25): a Secret holds named keys, like a Kubernetes Secret's `data`, instead of one
value. References name the secret and, optionally, one key. Access, write-only, expiry and rotation stay per
Secret and cover all its keys. `spec.value` stays as shorthand for one key. The same for ClusterSecret. No
compatibility work beyond that shorthand: nothing is deployed.

## The objects

```yaml
apiVersion: kevaso/v1
kind: Secret
metadata: { name: db, namespace: team-a }
spec:
  data:                      # write-only: sealed, then dropped before the object is stored
    username: YXBw           # base64 in JSON and YAML, like every []byte
    password: czNjcjN0
status:
  version: 4                 # bumps on every write that changes a value, whichever key
  keys: [password, username] # names only, sorted; kvo describe shows them
  size: 9                    # all keys' bytes
```

- **Key names**: 1–253 characters, letters, digits, `-`, `_` and `.`, starting and ending with a letter or a
  digit. Two keys may not give the same variable name (upper-cased, `-` and `.` as `_`: `db-host` and `DB_HOST`
  can't both be keys), since `deliver: env` names variables from keys.
- **`spec.value` is shorthand for the key `value`**: `value: X` is `data: {value: X}`. A write may carry one
  of `value` or `data`, not both.
- **Writing keys**. `value` or `data` replaces the whole set of keys: a key left out is removed. Two write-only
  fields change some keys and keep the rest: `spec.setData` (adds or replaces the keys it names) and
  `spec.removeKeys` (removes them; removing the last key is refused). They can't be combined with `value` or
  `data`. Each such write is one new version.
- **Limits**: all keys together at most 64 KiB, as one value was.
- **Types**. `opaque` takes any keys. Signing keys (`ed25519`, `ecdsa-p256`) hold one private key, as the key
  `value` only: anything else is refused, and they still never leave Kevaso (`sign` only). Registry secrets keep
  their shape: `server`, `username`, the password as the key `value`, and no other key. `generate` makes the key
  `value` (a random token, or a new signing key).
- **Sealing**: the keys are sealed together, as one envelope (one data key, the KMS wraps it), bound to the
  secret's namespace, name and uid (and a registry secret's server). Reads never return values. Write-only
  sticks to the sealed record as before: a `setData` or `removeKeys` on a record written while write-only
  keeps it write-only, and so do the keys it adds.
- **Loosening** (K-018): making a secret readable, or allowing a delivery it didn't, needs a write that brings
  every value again (`value` or `data`): `setData` and `removeKeys` can't loosen.

ClusterSecret is the same: `spec.data`, `spec.value` (the key `value`), `spec.setData`, `spec.removeKeys`;
`status.keys` beside `status.version`.

## Reading back

- `GET …/secrets/NAME/value` (read-value, never write-only) and `GET …/clustersecrets/NAME/value` answer
  `{"data": {KEY: base64…}, "version": N}`; `?key=KEY` answers that key alone as `{"value": …}`. An unknown key
  is a 404.
- `kvo get secret NAME --reveal` prints the value when the secret's only key is `value`, and otherwise every
  key as `KEY: VALUE` lines (refused for a value that isn't text: use `--key`). `--key KEY` prints that key's
  bytes alone. The same for `kvo get clustersecret NAME --reveal [--key KEY]`.

## Commands

Values never come from argv.

```
kvo create secret NAME --from-file FILE|-                        the key value (as before)
kvo create secret NAME --from-file KEY=FILE [--from-file KEY=FILE]…   named keys (FILE may be -, once)
kvo create secret NAME --generate                                the key value, made by the server
kvo secret set NAME --from-file FILE|-                           replace every key with the one key value
kvo secret set NAME --from-file KEY=FILE…                        set these keys, keep the others
kvo secret set NAME --remove-key KEY…                            remove keys
kvo get secret NAME --reveal [--key KEY]
kvo create clustersecret NAME --from-file FILE|- | --from-file KEY=FILE…
kvo set clustersecret NAME --from-file FILE|- | --from-file KEY=FILE… | --remove-key KEY…
kvo get clustersecret NAME --reveal [--key KEY]
```

`secret set` with `KEY=FILE` sends `setData` (the others stay); with a bare FILE it sends `value` (every
other key goes). `--from-literal KEY=VALUE` works the same way, still behind `--i-know`.

## References

A Grant's `secrets:` entry names the secret and, optionally, a key:

```yaml
secrets:
  - { name: db, key: password, deliver: env, env: DB_PASSWORD }
  - { name: db, deliver: file }                # every key, a file each
  - { name: api-token, key: token, deliver: inject, to: { host: api.example.com } }
```

- **broker** (the local endpoint). `GET /v1/secrets/NAME/KEY` answers that key's bytes. `GET /v1/secrets/NAME`
  answers bytes when the answer is one key (the grant names a key, or the secret's only key is `value`), and
  otherwise `{"data": {KEY: base64…}, "version": N}` (`application/json`). A grant with `key` gives only that
  key: another key answers 404 like a secret that doesn't exist.
- **file**. With `key`: one file, at `path` (default `/run/secrets/NAME/KEY`). Without: a secret whose only
  key is `value` (made from one value) is one file at `path` (default `/run/secrets/NAME`), as before keys; any
  other is a folder there, one file per key, named by the key, added and removed as keys are. A secret that
  gains a key goes from the file to the folder (and back): the host removes what's in the way first. On a
  container the folder is mounted read-only, as before: a key added later appears in it without a restart.
  (First built as "always a folder": that turned every existing `path: /run/secrets/tls.pem` into a folder,
  so the one-value shape stayed a file.)
- **env**. With `key`: one variable, named `env`. Without: one variable per key. Default names: the secret's
  name, upper-cased with `-` and `.` as `_` (the PREFIX), then `_` and the key the same way, except that the key
  `value` is the PREFIX itself. `db` with `username`, `password` gives `DB_USERNAME`, `DB_PASSWORD`; a token made
  with `--from-file token.txt` gives `TOKEN`, as before. Without `key`, `env` replaces the PREFIX.
- **inject** adds exactly one key's value. With `key`, that key. Without, the secret must have exactly one key.
  Admission refuses a grant whose inject entry has no key when the secret has several, and any entry that names
  a key the secret doesn't have (for every delivery). A secret that later gains keys stops being injected by an
  entry without a key (the injection is left out and the gate's audit says so) until the grant names one.
- **sign** (`operations.sign.keyRef`) names a signing key's secret, as before: no key.
- **pulls** (`container.pull.secretRef`, the namespace's default) name a registry secret, as before: the
  password is its key `value`.
- **approvals** are per secret, as before; the request names the key when one was asked for.

Access stays per secret: `use` on the secret allows naming any of its keys; `read-value` reads them all.

## ClusterSecrets for plugins

`kvoadm plugin install --cluster-secret NAME` still names a whole ClusterSecret. kevasod keeps it on the host
as a **folder**, `PLUGINS/PLUGIN/NAME/`, one file per key (root only, 0600, each written atomically), and the
unit's `LoadCredential=NAME:PLUGINS/PLUGIN/NAME` loads every file in it: systemd names each credential
`NAME_KEY` (`$CREDENTIALS_DIRECTORY/juicefs_access-key`). A key removed is removed from the folder. Any changed
key restarts the plugin's units, once; unchanged bytes restart nothing. The rest is unchanged: the name-pinned
`clustersecrets/value` RBAC, `?for=PLUGIN&side=`, the cache rules, the seen-delete rule.

Providers name what they read by secret and key: provider-juicefs's `credentials` fields are
`{name, key}` references (credential `NAME_KEY`); provider-linode reads its token from the ClusterSecret
named by its `tokenSecret` setting.

## Unchanged, per secret

Rotation fan-out (a write to any key reaches every silo whose grants name the secret), expiry, write-only,
`allowedDelivery`, approvals and the audit log (the audit names the key asked for). One version per secret.

## Out of v1

- Per-key access or versions. Keys of signing keys. Projecting keys of several secrets into one folder.
- A certificate's secret split into `tls.crt` and `tls.key` (it stays one PEM bundle in `value`).

## Done when

- Tests: each delivery with keys (broker one key and all, file with and without key, env with and without key,
  inject with key); admission refuses inject without a single key and an unknown key; a rotated key reaches the
  silo; `setData` and `removeKeys`; write-only sticks across `setData`; RBAC unchanged; plugin folders.
- `make race vet lint` green; on the lab, a multi-key secret as files, env, inject and through the endpoint into a
  microVM and a container, one key rotated, and a ClusterSecret with keys used by a plugin.
- kevaso-docs: Secrets (user), cluster secrets (admin), every example that references a secret, the command
  reference.
