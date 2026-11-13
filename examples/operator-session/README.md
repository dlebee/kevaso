# Example plugin operator: sessions

A plugin that adds two kinds, `SessionTemplate` and `Session` (`sessions.example.dev/v1`), and
the controller for them: each Session gets `spec.replicas` silos (default 1) made from its
template, named `SESSION-0`, `SESSION-1`, …, and its status says which exist and how far along
they are. It's the worked example for plugin operators (ADR 0006) and what
`test/integration/operator_test.go` installs.

| File | What it is |
|---|---|
| `plugin.yaml` | The package: name, version, the controller program, the files below |
| `kinds.yaml` | The two `KindDefinition`s (a scale subresource, a transition rule: the template can't change) |
| `policies.yaml` | A `ValidationPolicy` on sessions (a plugin's policies apply to its own kinds only) |
| `roles.yaml` | What the controller may do, shown before install |
| `session/` | The controller, on `kevaso.com/core/api` and `kevaso.com/core/sdk` only |
| `cmd/kevaso-operator-session/` | Its program |
| `sample.yaml` | A template and a session |

Build the controller for the host, install, try it, and remove it:

```bash
GOOS=linux GOARCH=amd64 go build -o examples/operator-session/bin/kevaso-operator-session ./examples/operator-session/cmd/kevaso-operator-session
```

```bash
kvoadm plugin install root@cp1.example.com --package examples/operator-session
```

```bash
kvo apply -f examples/operator-session/sample.yaml -n dev
```

```bash
kvo get sessions -n dev
```

```bash
kvo scale session fix-login-bug --replicas 2 -n dev
```

```bash
kvoadm plugin list
```

```bash
kvoadm plugin uninstall sessions
```

Uninstall is refused while sessions exist; delete them first (`kvo delete session fix-login-bug -n dev`),
or add `--force`.
