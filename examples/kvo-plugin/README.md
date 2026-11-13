# Writing a kvo plugin: `kvo-whoami`

A kvo plugin is a program people install with `kvo plugin install NAME` and run as `kvo NAME`, on
macOS, Windows and Linux alike (design §10, ADR 0008). This one prints who you are in the current
context and what you can do in its namespace:

```
$ kvo whoami
user bob
context:   bob
server:    https://cp.example.com:6443
namespace: payments
token:     short-lived, 4m52s left

CAN YOU    SILOS  SECRETS
list       yes    yes
create     yes    yes
delete     yes    yes
exec into  yes
```

`kvo whoami -n other` asks about another namespace, `kvo whoami --version` prints its version.

## The contract

A plugin can be written in anything. What it has to do is in [`kvoctx.go`](kvoctx.go):

1. **Where the cluster is**, from the environment kvo sets:

   | Variable | Meaning |
   |---|---|
   | `KVO_PLUGIN_SERVER` | the control plane's URL |
   | `KVO_PLUGIN_CA_FILE` | the cluster CA (PEM): trust it and nothing else; empty only for a plain-http dev server |
   | `KVO_PLUGIN_NAMESPACE` | the context's default namespace |
   | `KVO_PLUGIN_CONTEXT` | the kvo context's name |
   | `KVO_PLUGIN_KVO` | kvo itself, to ask for tokens |
   | `KVO_PLUGIN_NAME`, `KVO_PLUGIN_VERSION`, `KVO_PLUGIN_DIR` | the plugin's own name, version and folder |

2. **A token when it needs one:** run `"$KVO_PLUGIN_KVO" plugin token`. It prints
   `{"token": "…", "expiresAt": "2026-11-13T10:05:00Z"}`. The token is short-lived: ask again
   shortly before `expiresAt`, or after a 401. Never save it, and never ask the person for a password
   or a longer-lived credential: kvo keeps the session, the plugin borrows it.
3. **Call the API** with `Authorization: Bearer TOKEN`. The plugin can do exactly what the person
   can (their RBAC).

Everything else (arguments, output, exit code) is the plugin's own; kvo passes them through.

## Building and publishing

Build one artifact per OS and CPU (`darwin`, `linux`, `windows` × `arm64`, `amd64`), named
`kvo-whoami` (`kvo-whoami.exe` on Windows), or an archive with the program inside. List each in a
plugin index with its SHA-256, sign the index, and serve both:

```bash
go run ./hack/pluginindex keygen keys/
```

```bash
go run ./hack/pluginindex add index.json --name whoami --version v0.1.0 --os linux --arch amd64 --kind binary dist/linux-amd64/kvo-whoami
```

```bash
go run ./hack/pluginindex sign keys/signing.key index.json
```

`make plugins` does all of it for this example (and the panes client on a Mac) into `bin/plugins`,
signed with a key of your checkout's own. People add a third party's index on purpose, with its key,
and its plugins carry its name:

```bash
kvo plugin index add https://plugins.acme.example/index.json --key ed25519:…
```

```bash
kvo plugin install acme/whoami
```
