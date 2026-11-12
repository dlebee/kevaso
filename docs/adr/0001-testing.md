# ADR 0001: How we test

**Status:** accepted · **Date:** 2026-11-12

## Decision

1. **Pure logic first.** Every controller splits its reconcile into `decide(desired, observed) → plan`
   (a pure function) and `act(plan)`. `decide` is tested with tables and no fakes at all.
2. **Controllers against fakes.** Controllers are tested against the in-memory store, a fake clock and
   fake plugins, asserting the **end state** in the store, not the exact sequence of API calls (that's
   what makes Kubernetes' controller tests brittle).
3. **Fakes can't lie.** Every interface has a conformance suite in the `sdk` module; fakes and real
   implementations run the same suite.
4. **Integration** runs the API server, store and controllers in one process with fake plugins; it's
   cheap because the store is embedded.
5. **End to end** is always the same loop: create machines (testbed) → `kvoadm` → test → tear down. On
   Lima locally, on GitHub's `ubuntu-latest` runner in CI (it has KVM: research E036).
6. **CI** runs `go vet`, `golangci-lint`, `go test -race` for every module, and the DCO check.

## Why

Kubernetes' layering (unit with fakes, integration with a real API server, e2e on clusters) is the
model; its weak spots (assertions on call sequences, hand-built fixtures, external etcd for integration)
are what points 1–4 avoid.
