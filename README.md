# Kevaso

Self-hosted, stateful **silos** (microVMs or containers) on the machines you bring, managed
Kubernetes-style. `kevasod` runs on every host, `kvo` is for users, `kvoadm` for operators.

**Status:** early (M0–M2 of [MILESTONES.md](MILESTONES.md) done). What exists today:

- `kvoadm init [USER@]ADDRESS --kevasod PATH`: sets up a fresh Linux machine over SSH (host key
  pinned or confirmed first, password used once then keys only, root password rotated, signed
  `kevasod` verified on the host) and installs the control plane as a systemd service;
- `kevasod control-plane`: the API over TLS with client certificates from the cluster's private CA,
  a root-only admin socket, one-time join tokens for hosts, SQLite storage, a Ready heartbeat;
- `kvo apply / get / delete / watch` for Namespaces, Hosts and Silos, using the context
  `kvoadm init` writes (`~/.kevaso/config.yaml`);
- under the hood: a store with global revisions and resumable watches, CEL validation, a controller
  engine; the testbed and end-to-end loop (`make e2e`).

What's planned, in order: [MILESTONES.md](MILESTONES.md).

## Develop

```bash
make race        # unit tests, every module
make e2e         # the test loop on a real machine
make workspace   # write ../go.work when provider repos sit next to this one
```

Go 1.27 (`toolchain go1.27.4`). Apache 2.0; contributions with a DCO sign-off ([CONTRIBUTING.md](CONTRIBUTING.md)).
