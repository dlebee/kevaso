# Secret keys (v1)

Owner's decision (2026-11-25): a Secret holds named keys, like a Kubernetes Secret's `data`, instead of one
value. References name the secret and one key, or every key. Access, write-only, expiry and rotation stay
per Secret and cover all its keys. The same for ClusterSecret. No compatibility work: nothing is deployed.

## Explicit keys (2026-11-25, the same day)

The first cut of this design had implicit keys: `spec.value` and `kvo create secret NAME --from-file F`
made the key `value`; a Grant entry without `key` meant "the only key" (inject) or "every key" (file, env,
broker); `/v1/secrets/NAME` answered bytes or JSON depending on the keys the secret had; a one-value
secret was a file, a keyed one a folder; signing keys and registry secrets held the key `value`.

The owner chose: **keys are always explicit**. Explicit beats implicit: what a reader sees in a Grant or a
command is what happens, whatever the secret holds today, and a secret that gains a key never changes how
an existing reference behaves. Nothing is guessed anywhere, so the special cases went too:

- `spec.value` is gone (Secret and ClusterSecret): a write carries `spec.data`, or `spec.setData` and
  `spec.removeKeys`. `spec.generate` names the key it makes (`generate: token`).
- Every Grant `secrets:` entry names `key`: one key, or `"*"` for every key. A missing key is refused at
  admission with both forms in the message. `inject` takes one named key; `"*"` is refused for it.
- file and env have no one-key special case: a key is one file or one variable, `"*"` is a folder or one
  variable per key, whatever the secret holds.
- The local endpoint is `/v1/secrets/NAME/KEY` or `/v1/secrets/NAME/*`; `/v1/secrets/NAME` is a 400 that
  shows both. The admin read `…/value` takes `?key=KEY` or `?key=*`, and `kvo get secret --reveal` takes
  `--key KEY` or `--key "*"`.
- Fixed-shape secrets have real key names: a registry secret's is `password`, a signing key's is
  `private-key`, a Certificate's secret's is `tls.pem`.
- `kvo create secret`, `kvo secret set`, `kvo create|set clustersecret` take `--from-file KEY=FILE` (or
  `KEY=-` for stdin) only; a bare `--from-file F` or `-` is refused with a message showing the form.

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
  can't both be keys), since `deliver: env` names variables from keys. `*` is never a key: it means every key.
- **Writing keys**. `data` replaces the whole set of keys: a key left out is removed. Two write-only fields
  change some keys and keep the rest: `spec.setData` (adds or replaces the keys it names) and
  `spec.removeKeys` (removes them; removing the last key is refused). They can't be combined with `data`.
  Each such write is one new version.
- **Limits**: all keys together at most 64 KiB.
- **Types**. `opaque` takes any keys. Signing keys (`ed25519`, `ecdsa-p256`) hold one key, `private-key`:
  anything else is refused, and they still never leave Kevaso (`sign` only, never readable, never delivered).
  Registry secrets keep their shape: `server`, `username`, and one key, `password`. `generate: KEY` makes
  that key when the secret has no value yet (a random token for opaque, any name; a new signing key, which
  must be `generate: private-key`).
- **Sealing**: the keys are sealed together, as one envelope (one data key, the KMS wraps it), bound to the
  secret's namespace, name and uid (and a registry secret's server). Reads never return values. Write-only
  sticks to the sealed record: a `setData` or `removeKeys` on a record written while write-only keeps it
  write-only, and so do the keys it adds.
- **Loosening** (K-018): making a secret readable, or allowing a delivery it didn't, needs a write that brings
  every value again (`data`): `setData` and `removeKeys` can't loosen.

ClusterSecret is the same: `spec.data`, `spec.setData`, `spec.removeKeys`; `status.keys` beside
`status.version`.

## Reading back

- `GET …/secrets/NAME/value?key=KEY` (read-value, never write-only) and `GET …/clustersecrets/NAME/value?key=KEY`
  answer that key alone as `{"value": …, "version": N}`; `?key=*` answers `{"data": {KEY: base64…}, "version": N}`.
  No `key` is a 400; an unknown key is a 404.
- `kvo get secret NAME --reveal --key KEY` prints that key's bytes; `--key "*"` prints every key as
  `KEY: VALUE` lines (refused for a value that isn't one line of text: print it alone with `--key`).
  `--reveal` without `--key` is refused. The same for `kvo get clustersecret NAME --reveal --key …`.

## Commands

Values never come from argv; keys are always named.

```
kvo create secret NAME --from-file KEY=FILE [--from-file KEY=FILE]…   FILE may be - (stdin), once
kvo create secret NAME --generate KEY                                 the key, made by the server
kvo create secret NAME --type ed25519 --generate private-key
kvo create secret NAME --type registry --server HOST --username U --from-file password=-
kvo secret set NAME --from-file KEY=FILE…                             set these keys, keep the others
kvo secret set NAME --remove-key KEY…                                 remove keys
kvo get secret NAME --reveal --key KEY|"*"
kvo create clustersecret NAME --from-file KEY=FILE…
kvo set clustersecret NAME --from-file KEY=FILE… | --remove-key KEY…
kvo get clustersecret NAME --reveal --key KEY|"*"
```

`secret set` sends `setData` (the other keys stay). To replace every key at once, apply a manifest with
`spec.data`. `--from-literal KEY=VALUE` works the same way, still behind `--i-know`.

## References

A Grant's `secrets:` entry names the secret and a key, or every key:

```yaml
secrets:
  - { name: db, key: password, deliver: env, env: DB_PASSWORD }
  - { name: db, key: "*", deliver: file }       # every key, a file each, in /run/secrets/db/
  - { name: api-token, key: token, deliver: inject, to: { host: api.example.com } }
```

- **broker** (the local endpoint). `GET /v1/secrets/NAME/KEY` answers that key's bytes. `GET /v1/secrets/NAME/*`
  answers `{"data": {KEY: base64…}, "version": N}` (`application/json`): every key the grant gives (all of
  them for `key: "*"`, the one key otherwise). `GET /v1/secrets/NAME` is a 400 naming both forms. A grant
  with one key gives only that key: another key answers 404 like a secret that doesn't exist.
- **file**. With a key: one file, at `path` (default `/run/secrets/NAME/KEY`). With `"*"`: a folder at `path`
  (default `/run/secrets/NAME`), one file per key, named by the key, added and removed as keys are. On a
  container the folder is mounted read-only: a key added later appears in it without a restart.
- **env**. With a key: one variable, `env` (default `NAME_KEY`). With `"*"`: one variable per key,
  `PREFIX_KEY`, where PREFIX is `env` (default the secret's name). Names are upper-cased with `-` and `.` as
  `_`: `db` with `username`, `password` and `key: "*"` gives `DB_USERNAME`, `DB_PASSWORD`.
- **inject** adds one named key's value. `key: "*"` and a missing key are refused at admission, and so is any
  entry that names a key the secret doesn't have (for every delivery). In `to.format`, `{{value}}` stands for
  the injected key's value; it is not a key name. A key removed later stops being injected (the gate's audit
  says so) until the grant names one the secret has.
- **sign** (`operations.sign.keyRef`) names a signing key's secret, as before: no key (its one key,
  `private-key`, is never delivered).
- **pulls** (`container.pull.secretRef`, the namespace's default) name a registry secret, as before: the
  password is its key `password`.
- **approvals** are per secret, as before; the request names the key asked for.

Access stays per secret: `use` on the secret allows naming any of its keys; `read-value` reads them all.

## ClusterSecrets for plugins

`kvoadm plugin install --cluster-secret NAME` still names a whole ClusterSecret. kevasod keeps it on the host
as a **folder**, `PLUGINS/PLUGIN/NAME/`, one file per key (root only, 0600, each written atomically), and the
unit's `LoadCredential=NAME:PLUGINS/PLUGIN/NAME` loads every file in it: systemd names each credential
`NAME_KEY` (`$CREDENTIALS_DIRECTORY/juicefs_access-key`). A key removed is removed from the folder. Any changed
key restarts the plugin's units, once; unchanged bytes restart nothing. The host reads the value with
`?key=*`. The rest is unchanged: the name-pinned `clustersecrets/value` RBAC, `?for=PLUGIN&side=`, the cache
rules, the seen-delete rule.

Providers name what they read by secret and key: provider-juicefs's `credentials` fields are
`{name, key}` references (credential `NAME_KEY`); provider-linode reads its token from the ClusterSecret
named by its `tokenSecret` setting, key `token`. No reader falls back to a key named `value`.

## Unchanged, per secret

Rotation fan-out (a write to any key reaches every silo whose grants name the secret), expiry, write-only,
`allowedDelivery`, approvals and the audit log (the audit names the key asked for). One version per secret.

## Out of v1

- Per-key access or versions. Projecting keys of several secrets into one folder.
- A certificate's secret split into `tls.crt` and `tls.key` (it stays one PEM bundle in `tls.pem`).

## Done when

- Tests: each delivery with a named key and with `"*"` (broker, file, env; inject with a key); admission
  refuses a missing key, `"*"` for inject, and an unknown key; the endpoint refuses `/v1/secrets/NAME`;
  `kvo` refuses a bare `--from-file`, `--reveal` without `--key`, `--generate` without a key; a rotated key
  reaches the silo; `setData` and `removeKeys`; write-only sticks across `setData`; RBAC unchanged; plugin
  folders.
- `make race vet lint` green; on the lab, a multi-key secret as files, env, inject and through the endpoint into
  a microVM and a container, with a named key and with `"*"`, one key rotated, and a ClusterSecret with keys
  used by a plugin.
- kevaso-docs: every example names its key.
