# 7 · Secrets

The goal: a silo can **use** an API key, a password or a signing key, while having as little of it
as possible inside. Often that's nothing at all.

---

## The four ways, best first

| | Tier | The silo gets | Use it for |
|---|---|---|---|
| 1 | **Injection** (`deliver: inject`) | Nothing. The key is added to its requests outside the silo. | HTTP APIs: Anthropic, GitHub, Stripe… |
| 2 | **Operations** (`operations.sign`) | Signatures. The key stays in Kevaso. | Validator keys, code signing |
| 3 | **On demand** (`deliver: broker`) | The value, when it asks, over a channel only it has | Passwords, anything that can't be injected |
| 4 | **As a file** (`deliver: file`) | A file in memory (tmpfs), rewritten on rotation | Apps that read a key file |
| — | `deliver: env` | An environment variable. Leaks into child processes, logs, an agent's context: legacy apps only. | Last resort |

---

## Store a secret

Values come from a file or from stdin, **never from the command line** (other users of the machine
and your shell history would see it):

```bash
printf '%s' "$ANTHROPIC_API_KEY" | kvo create secret anthropic-key -n dev --from-file - --allow inject --write-only
```

| Flag | Meaning |
|---|---|
| `--from-file F` / `--from-file -` | The value, from a file or stdin |
| `--generate` | Kevaso makes it (32 random bytes; or a new private key with `--type`) |
| `--type ed25519` / `ecdsa-p256` | A signing key: only ever used through `sign`, never readable |
| `--allow inject,broker` | The only ways grants may deliver it, whatever they ask |
| `--write-only` | Nobody can read it back, admins included |
| `-l sensitivity=critical` | Labels: roles can give access by label |

The API never returns a value in `get`, `list` or `watch`. Someone with `read-value` can read a
readable secret:

```bash
kvo get secret db-password -n dev --reveal
```

---

## Give it to a silo: a Grant

```yaml
apiVersion: kevaso/v1
kind: Grant
metadata: { name: claude, namespace: dev }
spec:
  secrets:
    - name: anthropic-key
      deliver: inject
      to: { host: api.anthropic.com, header: x-api-key, format: "{{value}}" }
    - name: db-password                  # deliver: broker is the default
    - name: tls-key
      deliver: file
      path: /run/secrets/tls.pem          # under /run: memory only
  operations:
    sign: { keyRef: validator-key, slashingProtection: true }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: agent, namespace: dev }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  grants: [claude]
```

```bash
kvo describe grant claude -n dev
```

`describe` says which tier each secret uses.

---

## Injection, in detail

For `cloud-hypervisor` and container silos, the host's **egress gate** sits in front of the silo's
HTTPS to `api.anthropic.com`:

1. The silo's TLS is ended with the host's own egress CA, which Kevaso put in the silo's trust
   store. Only names a grant injects for get this; anything else is refused.
2. Each request must be for that same host (no domain fronting).
3. Whatever the silo sent in that header is **removed**, and the secret is set.
4. The gate connects to the real `api.anthropic.com` itself and checks its certificate.

The program in the silo just calls the API without a key; it works. On **OpenShell** silos the
same grant gives the program an environment variable holding a *placeholder* (`$ANTHROPIC_API_KEY =
openshell:resolve:env:…`), which it sends like a key, and OpenShell swaps the real one in. See
[Runtimes](08-runtimes.md#openshell).

---

## The broker, for everything else

Each VM has a private channel to its host (vsock); each container, a socket of its own. The host
knows which silo is asking **from the channel itself**, never from what the silo says. Inside, the
helper `kvo-guest` is already installed:

```bash
kvo-guest secret get db-password
```

```bash
printf 'block 42' | kvo-guest sign validator-key --slot 42
```

```bash
kvo-guest public-key validator-key
```

- Asking for a secret the silo has no grant for answers exactly like a name that doesn't exist.
- A host gets secrets only for silos placed on it.
- `sign` with `slashingProtection` refuses a second, different payload for a slot already signed,
  and any slot before the last.
- Every call, allowed or refused, is in the audit log.

---

## Rotation

```bash
printf '%s' "$NEW_KEY" | kvo secret set anthropic-key -n dev --from-file -
```

| Delivered as | What happens |
|---|---|
| `inject` | The next request carries the new value. Nothing changes in any silo. |
| `file` | The file is rewritten in every silo that has it, within seconds. |
| `broker` | The next `kvo-guest secret get` returns it. |

One secret granted to many silos is renewed once, for all of them.

---

## Who can do what with secrets

Secrets have their own verbs, separate powers:

| Verb | Allows |
|---|---|
| `list` | See that a secret exists (name, labels, version), never its value |
| `use` | Name it in a Grant, i.e. let a silo receive it |
| `read-value` | Read the value as a person |
| `write` | Create, change, rotate, delete |

Rules can target secrets **by label**, so new secrets are covered automatically:

```yaml
kind: Role
metadata: { name: web3-dev, namespace: web3 }
rules:
  - { resources: [secrets], verbs: [list, use], selector: { sensitivity: normal } }
  - { resources: [secrets], verbs: [use], resourceNames: [validator-1-key] }
```

**No back door through silos:** writing a Grant needs `use` on every secret it names, and giving a
silo a Grant needs `use` on that Grant's secrets too. Being able to create silos doesn't give you the
namespace's secrets.

---

## The master key and the recovery key

Values are stored with **envelope encryption**: each value has its own data key, and only data keys
are wrapped by the cluster's master key (a root-only file on the control plane). A stolen copy of
the store, or of a backup, opens nothing without it.

The **recovery key** that `kvoadm init` printed is what restores secrets from a backup on a new
control plane. The control plane keeps only its public half, so it can't use it itself.

| Task | Command |
|---|---|
| New master key (re-wraps data keys; the recovery key is unchanged) | `kvoadm kms rotate root@HOST --ssh-key …` |
| The recovery key leaked: new master key and new recovery key | `kvoadm kms rotate root@HOST --ssh-key … --new-recovery-key` |

After `--new-recovery-key`, the old key opens nothing backed up from then on. Backups from before
still open with it and hold the values of then: take a fresh backup, destroy the older ones, and
rotate the secrets that matter.

Next: **[Runtimes →](08-runtimes.md)**
