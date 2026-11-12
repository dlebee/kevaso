# Contributing

Kevaso is Apache 2.0 licensed. Contributions use the **Developer Certificate of Origin** (DCO), like
Kubernetes and OpenShell: there's no CLA to sign.

- Sign off every commit: `git commit -s`. It adds `Signed-off-by: Your Name <you@example.com>`, which
  certifies the [DCO](https://developercertificate.org/). CI rejects commits without it.
- Run `make vet race` before pushing; `make e2e` for anything that touches machines.
- Unit tests come with the change: pure logic as table tests, controllers against the in-memory store
  and fakes, end state asserted (see `docs/adr/0001-testing.md`).
