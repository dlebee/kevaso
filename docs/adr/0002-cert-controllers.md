# ADR 0002: Cert-controllers

**Status:** accepted · **Date:** 2026-11-12

## Decision

1. **One small interface, `sdk/kcc`.** A cert-controller turns a CSR for some hosts into a chain:
   `Issue(ctx, Request{Issuer, Config, Hosts, CSR}) ([][]byte, error)`. It doesn't say how. An
   Issuer names one (`spec.controller` + `spec.config`); `spec.acme` and `spec.internalCA` are
   shorthands for the built-in `acme` and `internal-ca`.
2. **Kevaso keeps the lifecycle.** The certificate controller decides what must exist and when to
   renew (2/3 of the lifetime), makes the private key, sends only the CSR, and seals the result in a
   Secret. A cert-controller never sees a key, so an external tool can't leak one.
3. **The built-in `acme` is cert-manager style.** A list of solvers with selectors (`dnsNames`, then
   the longest `dnsZones`, then no selector). `http01` is answered by the ingress controllers
   (`HTTP01Solver` keeps the tokens in the store; the ingress driver renders them into the stock
   proxy's config, ADR 0008);
   `dns01` calls a DNS provider (`acme.DNSProvider`: `Present/CleanUp(fqdn, value)`). Its account
   key lives in a `SealedStore` (KMS-sealed, per issuer).
4. **Programs, not plugins in the API.** External cert-controllers and DNS providers are programs on
   the control-plane host (`builtin/kcc/exec`): files in `/etc/kevaso/cert-controllers/` and
   `/etc/kevaso/dns-providers/`, or `--cert-controller` / `--dns-provider NAME=PATH`. Issuers only
   name them. Programs and their folder must be root's (or the control plane's user) and not
   group/world-writable, or kevasod refuses to start. DNS providers follow lego's `exec` convention
   (`PROGRAM present|cleanup FQDN VALUE`); cert-controllers get the request as JSON on stdin and
   print PEM on stdout.

## Why

Kubernetes has no certificate interface: cert-manager owns both the lifecycle and every way of
getting a certificate, and extending it means its webhook issuer API. Splitting the two keeps the
part that must be right (keys, renewal, storage) in core and makes the rest swappable, down to a
shell script around certbot. Running commands named by API objects would let anyone who can create
an Issuer run code as root on the control plane; registering them on the host keeps that power with
whoever administers the host.

## Tested by

`builtin/kcc/acme` (solver selection, API shape), `builtin/kcc/exec` (both protocols, timeouts,
ownership checks), `internal/controllers/certificate` (sealed state, HTTP-01 tokens, registry),
`internal/apiserver` (Issuer rules), and `test/e2e/ingress_test.go`: Pebble issuing over real HTTP-01
and over DNS-01 through pebble-challtestsrv and a DNS provider program, including a wildcard.
