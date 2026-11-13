# ADR 0008: Nothing inside a silo: the local endpoint, host-written secrets, host-fetched panes

**Status:** accepted · **Date:** 2026-11-13 · **Design:** §8.2 ("there is no guest helper"), §8.5,
§8.7, §7.2d, §10.1

## Context

Until now a silo got its secrets, signatures, port leases and panes through a helper Kevaso put
inside it, talking JSON lines to its host over a per-silo channel (vsock for microVMs, a unix socket
mounted into containers). The decision in design §8.2 is that Kevaso installs nothing in a silo, on
any runtime: a silo's image needs nothing of Kevaso's. What the helper did is now done from the
outside:

| A silo gets | How |
|---|---|
| An injected credential | The egress gate, outside the silo (unchanged) |
| A `file` or `env` secret | Written into the silo by its host, through the runtime |
| A `broker` secret, a signature, a public key, a port lease | A plain HTTP endpoint only that silo can reach |
| Panes | Fetched by the host from where the silo's spec says it answers |

Who may get what is decided where it was: the control plane (`internal/apiserver/broker.go`,
`approvals.go`, `leases.go`). Only the transport changes.

## Decision

### 1. The local endpoint

**Address: `http://169.254.42.1` (port 80), the same in every silo on the bridge runtimes.** A
link-local address, added as a `/32` on the host's silo bridge (`kvbr0`) and answered by the host's
own `kevasod`. A silo reaches it through its default route (the bridge's gateway) or, if its image
treats `169.254.0.0/16` as on-link, by ARP on the bridge, which the host answers: either way it
arrives on the bridge. It is not `169.254.169.254`, the address clouds use for their own metadata
service, which the host itself may need. `cloud-hypervisor` microVMs and `docker` / `podman`
containers are on the same bridge with the same rules, so **one way serves both**; the containers'
unix socket is gone.

**Who is asking: where the request arrived, never what it says.** The host maps the request's
source address to the one silo of this host the runtime gave that address (registered by the agent
from the runtime's own status, never from the API or the silo). That's unforgeable because:
- the bridge drops any frame from a silo's tap or veth whose IPv4 source isn't the silo's own, and
  any ARP claiming another address. These rules are now in the bridge's **prerouting** hook, so they
  also cover frames addressed to the host itself (before, they were in forward only, which frames for
  the host never cross: a silo could have spoofed another's address towards the host);
- the host firewall drops anything for `169.254.42.1` that didn't come in on the bridge (the mesh,
  the host's uplink), and on the bridge accepts it only from the silos that have an endpoint.

Nothing in a request (no header, token, parameter or body field) names a silo.

**Off unless a grant needs it.** A silo has an endpoint only when it has a `broker` secret, a `sign`
operation, or a leased port (`v1.NeedsEndpoint`). For any other silo there is no firewall rule (its
packets to the address are dropped) and the server doesn't know its address (it would answer 404).

**Not reachable by accident.** Every request must carry `Kevaso-Local: 1`. A browser can't add a
custom header without a CORS preflight (`OPTIONS`), which the endpoint refuses, and a server-side
URL fetcher tricked into fetching the address doesn't send it. The endpoint also refuses:
- a request with an `Origin` header or any `Sec-Fetch-*` header (a browser made it);
- a `Host` that isn't `169.254.42.1` or `169.254.42.1:80` (DNS rebinding: a name resolving to the
  address carries its own name);
- any path that isn't exactly one of the routes: no redirects ever (it's not `http.ServeMux`, which
  redirects unclean paths and trailing slashes), no CORS headers ever.

**Small limits.** Headers 8 KiB, the whole request read within 10 s (headers 5 s), answers written
within 30 s, idle connections closed after 30 s, a body only for `sign` (at most 512 KiB), at most 8
requests at once per silo (`429` past that).

**Approvals (§8.7).** A call that needs a person's yes answers `428` with the pending approval;
the client polls the same URL with `approval=NAME` (which doesn't replace the pending request;
asking without it does), every couple of seconds, until it's answered (`200`, or `403` denied /
expired). `curl -f` fails on `428`, so a script never mistakes "pending" for a value.

#### Routes

Every route is under `/v1`, needs `Kevaso-Local: 1`, and answers errors as
`application/json` `{"error": "…"}`. `for` and `wait` are Go durations (the access wanted once
approved, how long the request may wait for an answer; the cluster's defaults otherwise).

| Route | Answer |
|---|---|
| `GET /v1/secrets/NAME[?for=D&wait=D&approval=A]` | `200`, the value as `application/octet-stream`; its version in `Kevaso-Version` |
| `POST /v1/sign/KEY[?slot=N&for=D&wait=D&approval=A]`, body = the payload | `200`, the signature, hex, `text/plain` |
| `GET /v1/keys/KEY` | `200`, the public key, hex, `text/plain` |
| `POST /v1/ports/NAME/open[?for=D&wait=D&approval=A]` | `200` `{"port":"debug","until":"2026-11-13T15:04:05Z","clamped":false}` |
| `POST /v1/ports/NAME/close` | `200` `{"port":"debug","closed":true}` |

| Status | Meaning |
|---|---|
| `400` | a bad parameter (a duration, a slot, a name) |
| `403` | refused: missing header, `Origin`, wrong `Host`, an approval denied or expired, a lease refused |
| `404` | no such route, or a secret or key that doesn't exist **or isn't this silo's** (the same answer, word for word but the name) |
| `405` | wrong method (`OPTIONS` included) |
| `409` | signing refused by slashing protection |
| `413` | payload over 512 KiB |
| `428` | pending: `{"pending":{"namespace":"…","name":"…","expiresAt":"…"},"error":"waiting for a person's yes: kvo approve NAME -n NS"}`, also in `Kevaso-Approval` |
| `429` | too many requests at once from this silo |
| `503` | the control plane can't be reached; try again |

The exact lines a silo uses:

```sh
curl -fsS -H 'Kevaso-Local: 1' http://169.254.42.1/v1/secrets/db-password
curl -fsS -H 'Kevaso-Local: 1' 'http://169.254.42.1/v1/secrets/github-admin?for=30m&wait=10m'
curl -fsS -H 'Kevaso-Local: 1' 'http://169.254.42.1/v1/secrets/github-admin?for=30m&approval=github-admin-x7k2p'
printf 'block 7' | curl -fsS -H 'Kevaso-Local: 1' --data-binary @- 'http://169.254.42.1/v1/sign/validator-1-key?slot=7'
curl -fsS -H 'Kevaso-Local: 1' http://169.254.42.1/v1/keys/validator-1-key
curl -fsS -H 'Kevaso-Local: 1' -X POST 'http://169.254.42.1/v1/ports/debug/open?for=1h'
curl -fsS -H 'Kevaso-Local: 1' -X POST http://169.254.42.1/v1/ports/debug/close
```

A wait for a yes, in plain `sh`:

```sh
u='http://169.254.42.1/v1/secrets/github-admin?for=30m'; a=
while :; do
  code=$(curl -sS -o /run/answer -w '%{http_code}' -H 'Kevaso-Local: 1' "$u${a:+&approval=$a}")
  [ "$code" = 428 ] || break
  a=$(sed -n 's/.*"name":"\([^"]*\)".*/\1/p' /run/answer); sleep 2
done
```

**Behind it** the host relays exactly what it relayed before (`POST /agent/broker`, ops
`get-secret` (now `broker` delivery only), `sign`, `public-key`, `port-open`, `port-close`), with
the silo's identity from the arrival point; the control plane decides, audits, and adds `code`
(`NotFound`, `Conflict`) to refusals so the host picks the status.

#### Per runtime

| Runtime | Endpoint |
|---|---|
| `cloud-hypervisor` | `169.254.42.1` over the silo's tap on the bridge |
| `docker`, `podman` | `169.254.42.1` over the silo's veth on the bridge (named like a tap: the same rules) |
| `openshell` (VM driver), `openshell-container` (docker driver) | **not served yet.** Their sandboxes have no ordinary network: everything leaves through OpenShell's proxy under the sandbox's policy. What they need (proven in E033): the endpoint as a destination the policy allows, answered on a host address the gateway's proxy reaches, and identity from a per-silo credential OpenShell injects on the way out (a provider, like an injected secret), so the program never holds it and can't move it elsewhere in the request. The agent marks such a silo `LocalEndpoint=False NotSupported` |

### 2. `file` and `env` secrets: written by the host

The agent writes them into the silo through the runtime's **exec**, on every runtime, when the silo
is running: before its init steps, again whenever what it receives changes (a secret rotated, a
grant changed: the agent's informers enqueue every local silo a change reaches, one secret to many
silos), and it removes what's no longer delivered. The values reach the silo on exec's stdin, a
pipe: never in argv, never in a file on the host.

- Paths and modes as before: files at the grant's `path` (default `/run/secrets/NAME`), which must
  be under `/run/`, mode `0400`; env vars in `/run/kevaso/secrets.env` (`0400`, shell-quoted), read
  by login shells through `/etc/profile.d/kevaso-secrets.sh` (`0644`, no secret in it); what was
  written is listed in `/run/kevaso/delivered`, so the next pass removes what went.
- **Only on tmpfs.** The script refuses to write a secret into a folder whose filesystem (from
  `/proc/mounts`) isn't `tmpfs` or `ramfs`: the agent says so in the silo's `SecretsDelivered`
  condition. microVMs: `/run` is a tmpfs in any systemd guest. **Containers: every silo container
  now gets `--tmpfs /run`**, so the write lands in memory; with a plain exec into the container's
  `/run`, it would have landed in the engine's overlay, on the host's disk, in clear text. A
  host-written bind mount would have needed the files on the host (and the container recreated
  for each new path).
- An image needs a POSIX `sh`, `cat`, `mkdir`, `chmod`, `mv`, `rm` for this: no Kevaso tool. One
  without (distroless) gets `SecretsDelivered=False` with the exec error.
- Containers' init steps run in init containers before the main container starts, so they don't
  see `file` / `env` secrets (VMs' init steps, run by exec, do).

### 3. The egress CA

A silo whose grants inject a secret must trust its host's egress CA. Containers keep the bundle the
runtime mounts read-only (the host's CAs plus the egress CA: public, so on the host's disk is fine)
with `SSL_CERT_FILE` and friends. microVMs get it by exec in the same step as files: the CA in
`/etc/kevaso/egress-ca.crt`, then `update-ca-certificates` (Debian, Ubuntu, Alpine) or
`update-ca-trust` (Fedora, RHEL) when present, and `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
`CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` in `/etc/environment`. **An image with neither tool** gets a
bundle of its own system CAs (if it has a bundle) plus the egress CA in `/etc/kevaso/ca-bundle.crt`,
pointed at by those variables only: programs that ignore them won't trust the gate, and the
`SecretsDelivered` condition says "CA trusted through environment variables only".

### 4. Panes: fetched by the host

`spec.panes` gains `http: { port, path }` (where the silo answers, on its own address) and `every`
(how often the host asks: default 5s, at least 1s, at most 5m); `allow` and `maxPanes` stay.
`enabled` goes: without `http`, panes are off and nothing is ever fetched.

The protocol is two GETs a silo implements with any web server:
- `GET PATH` answers `application/json` `{"panes": [REPORT, …]}`, each report as in design §10.1
  (`pane`, `kind`, `title`, `state`, `progress`, `message`, `fields`, `bundle`, `data`, `ttl`;
  `silo` / `siloUID` are ignored: the control plane fills them in);
- `GET PATH/bundles/sha256:HEX` answers an HTML pane's bundle (ADR 0007's format), asked once per
  digest.

The host's agent asks from the host itself, at the silo's own private address (as probes do, never
a public one), with nothing from clients or the control plane in the request: no parameters, no
identity, no cookies. It follows no redirect, reads at most `maxPanes × 81 KiB` for the list and
512 KiB for a bundle, gives the list 2 s and a bundle 5 s, decodes strictly (unknown fields refused),
checks every report with `internal/panes` (kinds allowed, `maxPanes`, sizes, TTL), checks a
bundle's size and that its sha256 is its name, fills in a TTL of three periods when a report has
none (so a silo that stops answering goes stale), and relays only what changed (or what would go
stale otherwise) through the same token bucket the control plane applies. The control plane checks
everything again, as before.

**Cut off.** Too much (over a size), too slowly (past a time limit), too often (more changes than
the rate allows), or wrong (a redirect, a status other than 200, a content type other than JSON,
more than `maxPanes` panes, a kind not allowed, a report the limits refuse, a bundle whose digest
doesn't match): the host stops asking for a minute, doubling up to 15 minutes, and starts over after
an answer that's fine. Meanwhile its panes go stale. The silo's `Panes` condition says why
(`CutOff`, or `Unreachable` while nothing answers, which isn't held against it).

### 5. Removed

`internal/guest` and the `kvo-guest` command; `kevasod` answering to that name; installing it into
VMs and its systemd service; `kri.Broker` and the per-silo JSON-lines listeners (vsock, the
containers' `/run/kevaso/broker.sock` and `KVO_GUEST_BROKER`); the silo-side ops `deliveries`
(now the host's own, with `delivery-values`), `watch`, `pane`, `pane-bundle` (now ops the host uses
after fetching). The gate's `injections` and `ask-inject` were always the host's own and stay.

## Consequences

- A silo's image needs nothing of Kevaso's: `curl` (or any HTTP client) for on-demand secrets,
  signatures and leases; any small web server for panes.
- A secret on demand is one HTTP call away for anything in the silo that has the header, which is
  the same trust as the old helper's socket (anything in the silo could call it).
- OpenShell silos get `file` / `env` secrets by exec where their sandbox allows it, but no
  endpoint until the policy-and-token path is built.
- No live "rotated" notice inside the silo any more: a program that keeps a `file` secret open
  re-reads it on its own schedule (or watches the file).

## History

This replaces the guest helper `kvo-guest` (`internal/guest`, design §8.2 before the decision), its
`sync` service writing deliveries, its `pane report` / `pane html` commands and its vsock channel.
