# ADR 0005: Kinds defined at runtime, and admission policies

**Status:** accepted · **Date:** 2026-11-13

## Context

Design §4.2 lets a plugin or an operator add a kind with a `KindDefinition` and run its own
controller for it, and §4.1 adds in-process CEL admission policies (`ValidationPolicy`,
`MutationPolicy`) instead of webhooks. §4 deferred how defined kinds are named until kinds could be
defined. The product built on Kevaso (its `Session` and `Task` kinds, §10) is the first user.

## Decision

### Names

1. **Built-in kinds stay `kevaso/v1`**, no domain. Only Kevaso's own release adds kinds there.
2. **A defined kind's group is a domain its author owns**: a lowercase DNS name with at least one
   dot (`acme.dev`, `tasks.example.com`), at most 253 characters. `kevaso` itself and `kevaso.com`
   and its subdomains are reserved for Kevaso. Its `apiVersion` is `GROUP/VERSION` (`acme.dev/v1`).
   `version` is `v1`, `v2`, …: one served version per kind, no conversion (design §4.2).
3. **The definition's name is `PLURAL.GROUP`** (`databases.acme.dev`), as in Kubernetes, and that
   string is the kind's **resource**: its RBAC resource (`databases.acme.dev`,
   `databases.acme.dev/status`), its key in the store, what `match.kinds` in a policy names, and
   what clients and informers can always use to name it unambiguously.
4. **A defined kind never shadows a built-in one.** Its `kind`, `plural`, `singular` and short names
   can't be a built-in kind's name, plural or short name (compared without case), so `kvo get silos`
   always means Kevaso's silos. Two groups may each define a `Database`; inside one group a kind
   name is unique. Where two groups share a plural or short name, `kvo` asks for `PLURAL.GROUP`.
5. **What can't change** once defined: group, version, kind, plural and scope (they're in every
   stored object and every role). Singular, short names, the schema, the status subresource and the
   printer columns can.

### Serving

6. **Paths** are `/apis/GROUP/VERSION/[namespaces/NS/]PLURAL[/NAME[/status]]`; `GET /apis` lists
   every kind served (built-in and defined) for clients and `kvo get kinds`.
7. **Defined objects are unstructured** (`v1.Unstructured`: type, metadata, and every other field as
   JSON). Built-in kinds keep their strict decoding into Go types; nothing about them changes. The
   metadata of a defined object is decoded as strictly as a built-in's; the rest is checked against
   the definition's schema.
8. **The schema** is an OpenAPI v3 subset: `type` (object, array, string, integer, number,
   boolean), `properties`, `required`, `additionalProperties` (a map's values), `items`, `enum`,
   `minimum`/`maximum` (with `exclusiveMinimum`/`exclusiveMaximum`), `minLength`/`maxLength`,
   `pattern`, `minItems`/`maxItems`, `default`, `description`, and two Kevaso extensions:
   `x-kevaso-preserve-unknown: true` (keep fields the schema doesn't list; otherwise they're
   refused) and `x-kevaso-validations` (CEL rules with messages, on any node, `self` being that
   node). The root lists the object's top-level fields other than `apiVersion`, `kind` and
   `metadata`. Anything else in a schema is refused when the definition is written, and so is a
   CEL rule that doesn't compile.
9. **Writes, in order:** decode (metadata strictly) → system metadata (uid, timestamps, generation)
   → schema defaults → mutation policies → schema and CEL rules → validation policies → store.
   `generation` moves when anything outside `metadata` and `status` changes.
10. **The status subresource.** With `subresources.status`, people write the main resource, whose
    `status` is ignored (kept as stored), and controllers write `/status`, which changes only
    `status`; the main write is checked against the schema without `status`, a `/status` write
    only on `status`. Without it, `status` is an ordinary field and there's no `/status`.
11. **Changing a definition never makes objects unreadable.** Reads return what's stored and are
    never checked against the schema; the new schema applies from the next write of each object.
12. **Deleting a definition that still has objects is refused** (409, with how many are left).
    Delete them first. (Owner references to the plugin that installed a definition come with
    `kvoadm plugin install`.)
13. **Built-in roles don't reach defined kinds**, except cluster-admin's `*`: an operator grants
    them explicitly (a plugin's controller gets a role on its own resources).

### Admission policies

14. **Both are cluster-scoped** and match by `match.kinds` (a built-in kind's name or plural, a
    defined kind's resource, or `*`), `match.namespaces` (empty: all; a cluster-scoped object
    matches only a policy with no namespaces) and `match.operations` (`CREATE`, `UPDATE`; default
    both). They never apply to `ValidationPolicy`, `MutationPolicy` or the RBAC kinds, so a bad
    policy can always be fixed and never locks anyone out; they don't apply to `/status` writes
    (controllers reporting) or deletes.
15. **CEL variables:** `object` (the object being written), `oldObject` (`null` on create) and
    `request` (`user`, `groups`, `verb`, `operation`, `namespace`, `name`, `kind`, `resource`).
16. **A `MutationPolicy`** lists `mutations`, each `field` (a dotted path: `spec.size`,
    `metadata.labels.KEY`, `metadata.annotations.KEY`; never `apiVersion`, `kind`, the rest of
    `metadata` or `status`), `value` (CEL; `null` removes the field) and an optional `when` (CEL).
    Policies run in **name order**, each mutation in list order, each one seeing the object as the
    ones before left it. A built-in object must still decode strictly into its Go type afterwards.
17. **A `ValidationPolicy`** lists `validations`, each an `expression` that must be true and its
    `message`. Every matching policy runs, in name order, and the write is refused with every
    failure, each prefixed by its policy's name.
18. **Fail closed.** A policy whose CEL doesn't compile is refused when written; one that can't be
    evaluated (a runtime error, a non-boolean result, a field it can't set) refuses every write it
    matches, saying which policy and why.

## Left for later

Plugin-installed definitions (`kvoadm plugin install`, owner references, forced uninstall), the
scale subresource, transition rules (`oldSelf`) in schemas, server-side apply's field managers for
defined kinds, more than one served version and conversion, and policy parameters.
