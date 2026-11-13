# ADR 0008: Ingress drivers — stock proxies, driven from outside

**Status:** accepted · **Date:** 2026-11-13 · **Supersedes:** the `kvo-guest ingress` controller
(Kevaso's own proxy, from the self-built `kevaso-ingress` image, pulling its routes over the broker)

## Decision

1. **Kevaso ships no ingress controller.** An ingress controller is a silo running a proxy image
   exactly as its vendor ships it (`nginx:1.27`, `caddy:2.8`, `kong:3.7`…). Nothing of Kevaso's is
   added to it: no binary, token, socket or CA, and it never calls Kevaso. It is an ordinary silo
   behind a `loadBalancer` service (`kvoadm ingress install` makes one with its class).
2. **One small, pure interface: `sdk/kic`.** A driver has `Info()` (its name, which is also its
   annotation prefix; its vendor image and ports; the options and annotations it knows, each with a
   check) and `Render(State) (Plan, error)`.
   - `State` is proxy-neutral, for one class: routes (host, path prefix, backend address and port,
     TLS or not, the Ingress's own annotations for this driver), certificates (hosts, chain, key),
     pending ACME HTTP-01 challenges, the class's options. Sorted, so it is deterministic.
   - `Plan` is what to put where and how to make it take effect: `Config` (the main file),
     `Files` (certificates, named by their content) in a `Dir` Kevaso owns, `Check` (the proxy's own
     config test, `{config}` being the staged file), `Reload` (a command run in the silo, or a
     `Call` to the proxy's admin API).
   - Same `State`, same bytes (`Plan.Hash`), so "unchanged" means nothing is touched.
   - Optional `Blamer`: from the check's output, which Ingress caused a refusal (the drivers mark
     each Ingress's section with `# ingress NS/NAME … # -`; Kong names entities in its errors).
3. **Built in:** `nginx` (one `nginx.conf`, `nginx -t`, `nginx -s reload`), `caddy` (a Caddyfile
   with automatic HTTPS off, `caddy validate`, `caddy reload` against its admin API on the silo's own
   localhost), `kong` (DB-less: the whole declarative config in one `POST /config` to the admin
   API, which checks and swaps atomically; no files, no separate check).
4. **The control plane computes, the host's agent applies.** `internal/ingress.Desire` (pure; was
   the broker's `ingressConfig`) builds a class's `State`; the agent of each controller silo's host
   gets it from `GET /agent/ingress?namespace=&name=` (only that silo's host is answered; answers
   with keys are audited), renders it with the driver and applies it (`internal/ingress.Apply`):
   unchanged → nothing; missing supporting files written; config written as `PATH.next`; the proxy's
   check run on it **inside the silo with the proxy's own binary**; refused → `PATH.next` and the
   files just added removed, the running proxy never saw any of it; accepted → moved over `PATH`,
   reloaded, files no plan names any more (a deleted certificate's key) removed.
5. **Files go in through exec, not a volume.** The agent already runs init steps, daemons and
   readiness through the runtime's exec, which every runtime has (VM and container alike), while a
   host-written volume exists only for containers and would have to be declared on the silo (a
   stock silo shouldn't need Kevaso-shaped storage). Contents go in on stdin (`sh -c 'cat > "$1.tmp"
   && chmod && mv'`, the path an argument, never script text), so keys never sit in a command line
   or a log. Every vendor image has `sh`, `cat`, `mv`, `rm`, `ls`.
6. **Content-named certificate files.** Writing a new certificate before the check can't change a
   file the running config uses, so a refused config needs no undo beyond deleting what was added.
   A renewal therefore writes one new file and changes the config's lines naming it (one reload),
   and the old key is removed after the reload.
7. **Refusals are conditions, never half-applied.** An annotation the driver doesn't know or a value
   it won't take, an unknown driver or option, a config the proxy's check refuses: nothing is applied,
   the last good config stays, and `IngressClass.status` says why (`controllers[]` per silo:
   `applied`, `rejected`, `blamed`; condition `Applied`). The Ingress concerned gets `Ready=False`
   (`Refused`: its annotations; `Rejected`: the proxy blamed it). A worker host may write only its own
   silos' entries in a class's status. Values are checked before they reach a config: host names,
   paths, addresses and ACME tokens to their character sets (`kic.CheckState`), knobs by their
   checks; nothing is quoted or escaped, so nothing can be pasted in.
8. **API.** `IngressClass.spec.controller` is `{driver, options, namespace, silo | siloSet}`; every
   silo of a SiloSet applies the same config (HA). `Ingress` stays proxy-neutral; driver knobs are
   annotations `DRIVER/knob` (other drivers' are ignored). One class per controller silo.

## Why

The old controller was Kevaso's own proxy, i.e. code of ours on the most exposed path, an image we
build, and a silo that called back into the control plane for routes and keys. A stock proxy is
better-tested than anything we'd write, people know how to operate it, and keeping it unaware of
Kevaso makes it replaceable: a new proxy is a driver of a few hundred lines, with no change to the
API. Keeping the interface to "render, check, reload" (or "one admin call") is what lets nginx,
Caddy and Kong fit the same shape; anything proxy-specific stays in annotations the driver checks.

## Left out (for now)

- Plugin drivers over `sdk/kplugin` (the interface is ready for it; only built-ins are registered).
- `routeWhen` (probes): `Inputs.Routed` is where its decision goes; the default is "running with an
  address".
- Guards (`auth`, `limits`), TCP/UDP routes, HTTP/3, a proxy's own certificate management (Caddy's
  automatic HTTPS). Two Ingresses claiming the same host and path: the first by name keeps it, the
  other's route is left out without a condition.
- The admin-API path (`kong`) reaches the silo's private address from the host; the default silo
  `kvoadm ingress install` makes is for nginx and Caddy (Kong's image listens on 8000/8443 as a
  non-root user and needs `KONG_DATABASE=off` and an admin listener: bring your own silo).

## Tested by

`builtin/kic/{nginx,caddy,kong}` (golden files, `kictest.Conformance`: determinism, keys only in
secret files, unknown and bad knobs refused, injection refused; blame; the proxy's own check on the
rendered output when its binary is on the machine, skipped otherwise), `internal/ingress` (the
desired state, the apply plan: check before reload, keep the last good, nothing touched when
unchanged, an admin-API driver), `test/integration/ingress_test.go` (an agent with a worker's
credentials and the fake runtime: written and reloaded once, a broken annotation refused without
touching the proxy, a renewal, a deletion, no key in a log), and `test/e2e/ingress_test.go` (stock
nginx with Pebble over real HTTP-01 and DNS-01).
