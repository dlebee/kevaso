# ADR 0011: What a silo starts from: `container:` or `vm:`, and the kind `VMImage`

**Status:** accepted · **Date:** 2026-11-13 · **Implements:** design §0.2 ("Decided") ·
**Supersedes:** a silo's bare `spec.image`, `spec.imagePull` and `spec.command`; a SiloSet's
top-level `spec.image`; the kind `Image` (ADR 0004 states the old shapes)

## Decision

```yaml
spec:
  runtime: docker                 # docker, podman, openshell, openshell-container
  container: { image: ghcr.io/acme/api@sha256:…, pull: { secretRef: ghcr-pull }, command: [/app] }
---
spec:
  runtime: cloud-hypervisor
  vm: { image: geth-node:v2 }     # a VMImage (or ubuntu-24.04, built in)
  # or vm: { disk: { url: https://…, sha256: … } }
```

- `SiloSpec.Container` (`ContainerSource{image, pull, command}`) and `SiloSpec.VM`
  (`VMSource{image | disk}`) replace `image`, `imagePull` and `command`. Code reads them through
  `SiloSpec.From()` (one string: the container image, the VM image name, or the inline disk as
  `URL#sha256=…`), `Pull()` and `Command()`.
- **Admission** (`v1.SourceProblems`, pure): the block must fit the runtime, and the refusal names
  the right one; `vm` takes exactly one of `image` and `disk`; a disk needs an `https://` URL and
  its 64-hex `sha256`; `vm.image` can't be a registry reference; `container.image` must be a
  registry reference (or the built-in `ubuntu-24.04`) and can't be a VMImage's name. A silo with
  neither block is admitted (as before with no image) and starts from nothing it can run.
- **Resolution** (`v1.ResolveImage(spec, vmimages)`): a container image as it is; an inline disk as
  `URL#sha256=…`, the same string a VMImage version resolves to, so a host fetches and checks it on
  the same path (no new code on hosts); a VM image's version, or its newest. `status.image` keeps
  its name and meaning (what the source resolved to, and what runs); `status.image.from` is
  `From()`, so a changed inline disk is a changed source.
- **The kind `Image` is `VMImage`** (plural `vmimages`, short name `vmi`), with no alias. Its
  types are `VMImage`, `VMImageSpec`, `VMImageVersion`, `VMDisk`. The built-in roles' resource is
  `vmimages`; `kvo get vmimages`.
- **A SiloSet's top-level `image` override is removed** rather than renamed: what instances start
  from is the template's block (`template.container.image`, `template.vm.image` or
  `template.vm.disk`), one place, no override rule to explain. A rollout is a change there: the
  set's revision hashes the instance spec, so changing an inline disk rolls the set like changing
  a VMImage version does.
- `container.pull` keeps every rule `imagePull` had (use on the secret, docker and podman only,
  the image's own registry).
