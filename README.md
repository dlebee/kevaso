# Kevaso

Self-hosted, stateful **silos** (microVMs or containers) on the machines you bring, managed
Kubernetes-style. `kevasod` runs on every host, `kvo` is for users, `kvoadm` for operators.

**Status:** early. What exists today:

- the three Go modules: `kevaso.com/core` (server and binaries), `kevaso.com/core/api`,
  `kevaso.com/core/sdk`;
- the **testbed** and the end-to-end test loop (`make e2e`): it creates a machine (a Lima VM on macOS,
  the machine itself on Linux CI), checks it can run microVMs, and tears it down.

What's planned, in order: [MILESTONES.md](MILESTONES.md).

## Develop

```bash
make race        # unit tests, every module
make e2e         # the test loop on a real machine
make workspace   # write ../go.work when provider repos sit next to this one
```

Go 1.27 (`toolchain go1.27.4`). Apache 2.0; contributions with a DCO sign-off ([CONTRIBUTING.md](CONTRIBUTING.md)).
