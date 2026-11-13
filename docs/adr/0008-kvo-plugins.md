# ADR 0008: kvo plugins: a signed index, per-user installs, a token helper

**Status:** accepted · **Date:** 2026-11-13

## Context

Some things a person runs next to `kvo` aren't part of it: the panes client first (design §10, "`kvo`
plugins"), others later, from Kevaso or from third parties. People should install and run them the
same way on macOS, Windows and Linux, never caring what they are written in:

```
kvo plugin install panes
kvo panes
```

Kevaso already ships verified programs: `kvoadm` signs `kevasod` with an Ed25519 key and the host
checks the signature against the key it pinned before swapping the binary in (research E018,
`kvoadm install` / `kvoadm upgrade`). "Plugin" also means two other things in Kevaso: provider
plugins on hosts (`sdk/kplugin`, `kvoadm plugin install`) and plugin operators. This ADR is about
neither: a kvo plugin runs on the person's own machine, as the person.

## Decision

1. **Commands.** `kvo plugin search [TERM] | install NAME[@VERSION] | list | upgrade [NAME] |
   remove NAME | index add URL --key ed25519:… [--name N] | index list | index remove N`, and
   `kvo NAME [ARGS…]` runs an installed plugin with its arguments, standard streams and exit code
   untouched (`internal/cli/kvo/plugins.go`, `internal/kvoplugin`).
2. **A built-in always wins.** `kvo NAME` looks for a plugin only when NAME isn't one of kvo's commands
   or a name kept for one (`builtinCommands`: also `help`, `version`, `config`, `logs`, `run`, `ip`,
   `image`, …). `kvo plugin install` refuses those names, and a test reads `Run`'s source and fails
   if a command is missing from the list, so a new command can't be shadowed by a plugin installed
   earlier.
3. **Per user, one version at a time.** Plugins live under the person's own folder, no admin rights:
   `~/Library/Application Support/Kevaso/kvo/plugins` (macOS), `%LOCALAPPDATA%\Kevaso\kvo\plugins`
   (Windows), `$XDG_DATA_HOME/kevaso/kvo/plugins` or `~/.local/share/…` (Linux); `$KVO_PLUGINS_DIR`
   overrides it. Each plugin is `installed/INDEX/NAME/` with `manifest.json` (name, index and its
   URL, version, OS and CPU, kind, artifact URL and SHA-256, entry point, install time) and
   `files/`. An install is staged under `tmp/`, then swapped in by rename (the old version moves
   aside first), so a failure leaves one complete version or the other.
4. **The index** is one JSON document (`apiVersion: kevaso.com/plugin-index/v1`): its suggested name,
   a `generated` time, and plugins, each with versions (`vMAJOR.MINOR.PATCH[-pre]`) and, per OS and
   CPU (Go's names: `darwin`, `linux`, `windows`; `arm64`, `amd64`), an artifact: URL (absolute or
   relative to the index), SHA-256, size, and kind:
   - `binary`: the file is the program, saved as `kvo-NAME` (`kvo-NAME.exe` on Windows);
   - `tar.gz` or `zip`: an archive, unpacked; `entry` names the program in it (a macOS `.app`'s
     `KevasoPanes.app/Contents/MacOS/KevasoPanes`, a Windows folder's `kvo-foo.exe`).
   `install` takes the newest release (pre-releases only by `@VERSION`) that has a build for this
   OS and CPU. A platform with none gets "panes has no build for linux/arm64 yet (built for:
   darwin/arm64)" and exit 1. No fallback (Rosetta, emulation): a build is made for a platform or
   it isn't there.
5. **Signing: the same scheme as Kevaso's own binaries.** Ed25519, the private key in the PKCS#8
   PEM file `kvoadm.SigningKey` writes. The index's signature is a detached file at the index's URL
   plus `.sig`: base64 of the Ed25519 signature over `"kevaso plugin index v1\n"` followed by the
   document's exact bytes. The prefix keeps a signature over an index from ever passing for one over
   anything else the same key might sign. Artifacts aren't signed one by one: their SHA-256 is in the
   signed index, which binds them just as well with one signature to check. kvo verifies the
   signature before reading the document, checks the hash of the whole download before looking
   inside it, and only then unpacks. An index older than one kvo has seen (`generated`, remembered
   per index in `indexes.json`) is refused as a rollback.
   We chose this over minisign, cosign or TUF because it needs no new dependency or service,
   verifies offline, and is the scheme Kevaso already runs. What TUF would add (freeze protection
   with expiring metadata, key rotation, delegated roles) is left open below.
6. **Whose index.** `DefaultIndexURL` and `DefaultIndexKey` are constants in `internal/kvoplugin`.
   Until the project's index key exists, the key is empty and kvo says the index isn't published
   yet. `$KVO_PLUGIN_INDEX` and `$KVO_PLUGIN_INDEX_KEY` replace the built-in pair for a local or
   staging index (`make plugins` builds one): anyone who can set a person's environment can already
   change their `PATH`, so this opens nothing new. A third party's index is added on purpose with
   its key (`kvo plugin index add URL --key ed25519:…`), verified with that key when added, and named
   by the index's suggestion or `--name`, never `kevaso`. Its plugins are always named with it
   (`kvo plugin install acme/foo`, `kvo acme/foo`), so another index can never pass for Kevaso's. An
   index is removed only once nothing installed from it remains. Fetches are https, plain http only
   to loopback; index 8 MiB, signature 4 KiB, artifact 256 MiB at most (or its listed size).
7. **Unpacking**, as root folder of the plugin's own and nowhere else:
   - entry names relative, `/` separated, no empty, `.` or `..` part, no `\`, `:` or control
     character; a file twice, or under a file, refuses the archive;
   - regular files (mode 0644, or 0755 if any execute bit), folders, and symbolic links whose target
     is relative and stays inside, first on paper and then for real once everything is written
     (`EvalSymlinks`: a link through another link can't climb out); nothing is written through a
     link; a link that dangles is refused;
   - no hard links, devices or FIFOs; at most 20 000 entries and 1 GiB unpacked, counted as written
     (a zip bomb stops at the limit);
   - the entry point must be a regular file in the archive; it is made executable.
8. **What a plugin gets: the context, never a long-lived credential.** kvo runs the program with its
   own environment plus `KVO_PLUGIN_NAME`, `KVO_PLUGIN_VERSION`, `KVO_PLUGIN_DIR`, `KVO_PLUGIN_KVO`
   (kvo's own path), `KVO_PLUGIN_CONTEXT`, `KVO_PLUGIN_SERVER`, `KVO_PLUGIN_CA_FILE` (the cluster CA,
   the only one to trust) and `KVO_PLUGIN_NAMESPACE`, any `KVO_PLUGIN_*` already there replaced. A
   token comes from **`"$KVO_PLUGIN_KVO" plugin token`**, which prints `{"token": "…", "expiresAt":
   "…"}`: the context's access token from the cluster's issuer, refreshed (and the rotated refresh
   token saved) exactly as any kvo command does it. The refresh token never leaves kvo's token
   store. The token helper reads `KVO_PLUGIN_CONTEXT`, so `kvo ctx` switching meanwhile doesn't move
   a running plugin to another cluster. A context with a client certificate (what `kvoadm init`
   writes) is refused: kvo never hands a plugin a key. With `$KVO_TOKEN` (CI) the helper returns
   that token, which the caller already put in the environment; a plain-http dev server gets an
   empty token.
   **A helper command, not a local socket**, because:
   - it is the same on every OS: no Unix socket, no named pipe, nothing listening;
   - kvo needn't keep running beside the plugin, and the refresh logic stays in one place with its
     lock, shared with every other kvo command;
   - it gives a plugin nothing it couldn't get by running `kvo` as the same person, which is the
     rule anyway: a plugin has the caller's RBAC and nothing more.
   A socket could have scoped tokens to one plugin run and stopped handing them out when it ended.
   That is worth having once the issuer can mint narrower tokens; it can be added beside the helper
   then.
9. **Run as is.** The plugin shares kvo's terminal and gets its signals (Ctrl-C) itself; kvo returns
   its exit code. Its files are not re-hashed on every run: they sit in the person's own folder,
   which the person (or anything running as them) could change along with kvo itself.

## Consequences and what's left open

- The panes client is the plugin `panes`: an `.app` in a `tar.gz` for macOS (`apps/panes`,
  `make archive`). Its README states the contract a Windows or Linux build must meet to be added
  under the same name. `examples/kvo-plugin` (`kvo-whoami`) is the small example, built for every
  OS and CPU in `make plugins` and installed and run end to end in `test/integration`.
- `hack/pluginindex` builds an index (`add`), signs it (`sign`) and makes keys (`keygen`, kvoadm's
  format). Nothing is hosted or published by this change.
- **Open:** the project's index key and where the index is served (then set the two constants);
  key rotation (an index naming its successor key, or kvo shipping two); freeze protection (an
  `expires` field kvo enforces); a lock so two installs of the same plugin can't race; macOS
  notarisation and Windows Authenticode of the artifacts themselves, which the OSes check
  separately from kvo's verification.
