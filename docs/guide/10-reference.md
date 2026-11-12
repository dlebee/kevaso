# 10 · Command reference

Every command on one page. `kvo` uses your current context (`kvo ctx`); `-n NS` picks a namespace
(default: the context's).

---

## kvo: using the platform

### Objects

| Command | Does |
|---|---|
| `kvo apply -f FILE` (or `-f -`) | Create or update every object in a YAML/JSON file |
| `kvo get KIND [NAME] [-n NS \| -A] [-o yaml\|json]` | List or show objects |
| `kvo describe KIND NAME` | Everything about one object, for people |
| `kvo delete KIND NAME` | Delete it |
| `kvo watch KIND [-n NS \| -A]` | Print the current state, then every change |

Kinds: `namespaces` (`ns`), `hosts`, `silos`, `secrets`, `grants`, `ippools`, `roles`,
`rolebindings`, `clusterroles`, `clusterrolebindings`, `serviceaccounts` (`sa`).

### Silos

| Command | Does |
|---|---|
| `kvo exec silo NAME -- CMD [ARGS…]` | Run a command inside; exits with its code; stdin passes through |

### Secrets

| Command | Does |
|---|---|
| `kvo create secret NAME --from-file F\|-` | Store a value (never from the command line) |
| `kvo create secret NAME --generate [--type ed25519\|ecdsa-p256]` | Let Kevaso make it |
| …`--allow MODES`, `--write-only`, `-l KEY=VALUE` | Restrict delivery, make write-only, label |
| `kvo secret set NAME --from-file F\|-` | A new value (rotation) |
| `kvo get secret NAME --reveal` | Print the value (needs `read-value`; never for write-only) |

### Access

| Command | Does |
|---|---|
| `kvo login SERVER --ca sha256:…` | Sign in (browser + invite code) |
| `kvo logout` | Forget this context's session |
| `kvo ctx [NAME]` | List contexts, or switch |
| `kvo ns [NAME]` | Show or set the default namespace |
| `kvo auth whoami` | Who you are to the cluster |
| `kvo auth can-i VERB RESOURCE[/NAME] [-n NS]` | Exits 0 for yes, 1 for no |
| `kvo create token SA [--duration 1h]` | A service-account token, for CI (`$KVO_TOKEN`) |

### Environment

| Variable | Means |
|---|---|
| `KVO_CONFIG` | The config file (default `~/.kevaso/config.yaml`) |
| `KVO_TOKEN`, `KVO_CA_FILE` | A service-account token and the cluster CA, for CI |
| `KVO_SERVER` | A plain-HTTP server (`kevasod dev`, local experiments) |

---

## kvoadm: running the platform

### Machines

| Command | Does |
|---|---|
| `kvoadm check [USER@]ADDR --ssh-key KEY --host-key SHA256:…` | Report what Kevaso finds; changes nothing |
| `kvoadm init [USER@]ADDR --ssh-key KEY --host-key SHA256:… --kevasod BIN [--name N] [--cluster C] [--api-server URL]` | Install the control plane; write your kvo context; print the recovery key |
| `kvoadm host enable-worker [USER@]ADDR --ssh-key KEY [--runtime R]… [--loop-storage SIZE]` | The control-plane host runs silos too |
| `kvoadm host add [USER@]ADDR --ssh-key KEY --kevasod BIN --install worker [--name N] [--region R] [--label K=V] [--runtime R] [--behind-nat]` | Add a worker |
| `kvoadm host list` | Hosts and their state |
| `kvoadm host drain NAME` / `uncordon NAME` | Maintenance |

Every command that logs in takes `--ssh-key PATH` (a key with a passphrase is taken from `ssh-agent`
or asked for) or `--password` (typed once; the machine then goes key-only), `--ssh-port N`, and
`--host-key SHA256:…` (without it, you're asked to confirm the fingerprint).

### People

| Command | Does |
|---|---|
| `kvoadm users invite NAME [--namespace NS [--role editor\|admin\|viewer]] [--group G]…` | A one-time sign-in code |
| `kvoadm users list` | Everyone who can sign in |
| `kvoadm users disable NAME` | Cut someone off now |

### Keys

| Command | Does |
|---|---|
| `kvoadm kms rotate [USER@]ADDR --ssh-key KEY` | A new master key for secrets |
| …`--new-recovery-key` | Also replace the recovery key (it leaked) |

---

## kevasod: on the hosts

You rarely run it yourself; `kvoadm` installs it as a service.

| Command | Does |
|---|---|
| `kevasod control-plane --name N --address A [--worker --runtime R…]` | The control plane (and worker) |
| `kevasod worker --name N --server URL` | A worker-only host |
| `kevasod admin recovery-key` / `kms-rotate [--new-recovery-key]` | Through the admin socket, as root |
| `kevasod dev` | The API without authentication on loopback, for trying `kvo` locally |
