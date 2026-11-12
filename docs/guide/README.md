# The Kevaso guide

Kevaso runs **silos** — isolated, long-lived machines (microVMs or containers) — on computers you
bring: a dedicated server, a VPS, a box under your desk. You describe what you want in YAML, Kevaso
makes it so and keeps it that way, the way Kubernetes does for pods. Unlike pods, a silo is a
*machine*: it has a disk that stays, a name, and it can be the place an AI agent or a developer
works for months.

This guide takes you from an empty machine to a cluster you share with others, one step at a time,
and says *why* at each step.

---

## Read it in order

| | Page | You'll end up with |
|---|---|---|
| 1 | [Concepts](01-concepts.md) | The words Kevaso uses, and how the pieces fit |
| 2 | [Installing](02-install.md) | A control plane on your machine, set up step by step, and `kvo` working on your laptop |
| 3 | [Your first silo](03-first-silo.md) | A microVM running, with init steps, that you can `exec` into |
| 4 | [People and access](04-people-and-access.md) | A colleague signed in, seeing only their namespace |
| 5 | [More machines](05-more-machines.md) | Workers joined over an encrypted mesh, even one behind your home router |
| 6 | [Networking](06-networking.md) | Private names, silo-to-silo rules, public ports, and what a silo may reach |
| 7 | [Secrets](07-secrets.md) | An API key that works in a silo but never enters it |
| 8 | [Runtimes](08-runtimes.md) | Which kind of silo to pick: VM, OpenShell sandbox or container |
| 9 | [Operating a cluster](09-operations.md) | Day-two tasks: audit log, keys, draining, troubleshooting |
| 10 | [Command reference](10-reference.md) | Every `kvo` and `kvoadm` command on one page |

If you only have ten minutes, read **Concepts** and **Installing**.

---

## What you need

- **A Linux machine** for the control plane: Ubuntu 24.04, x86_64 or arm64, 2 CPUs and 2 GiB of
  memory is plenty. A fresh one is best: Kevaso treats the machines it manages as its own.
- **For microVM silos**, that machine (or a worker) needs **KVM** (`/dev/kvm`): bare metal, or a VPS
  with nested virtualization. Without it you can still run container silos.
- **Your own computer** (macOS or Linux) with Go 1.27 to build the tools, and OpenSSH (`ssh`,
  `ssh-keygen`), which every Mac and Linux already has.

## Status

Kevaso is early software (milestones M0–M8 done, M9 in progress; see
[MILESTONES.md](../../MILESTONES.md)). It runs real workloads in tests on real machines, but it has
no releases yet: you build the binaries yourself, as the next pages show. Things that aren't built
yet are marked *later* where they come up.
