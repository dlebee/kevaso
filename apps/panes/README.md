# Kevaso Panes (macOS)

The desktop client of the pane protocol (design §7, §10.1). Sign in to your clusters like `kvo login`,
pick a namespace, turn panes on: each one floats in its own small always-on-top window, with the
identity (rim, silo, namespace, host) drawn by the app. A silo reports what its status looks like;
the control plane keeps the latest report per pane and relays it; this app draws it. Nothing flows
back to the silo.

- `Sources/PaneKit`: the library.
  - `Trust`: `PinnedCA` (the cluster's CA, its `sha256:` fingerprint), `PinnedSession` (a URLSession
    that trusts only that CA and never follows redirects), `fetchCA` (the `kvo login --ca` steps).
  - `SignIn`: `BrowserSignIn` (PKCE on a loopback redirect, the sign-in pages relayed over the pinned
    session), `OIDCClient` (token, refresh, revoke), `ClusterSession` (refresh token in the keychain,
    access tokens in memory, refresh, reuse → signed out, sign-out).
  - `Keychain`: `KeychainVault` (generic passwords under `com.kevaso.panes`).
  - `Contexts`: `ClusterContext`, `ContextStore` (the clusters, `contexts.json`).
  - `LoopbackHTTP`: a small HTTP/1.1 server on 127.0.0.1 (the sign-in's redirect and relay).
  - `PaneWindows`: `PanePanel`, `PaneWindowController`, `FloatingPanes`, `WindowPlaces`.
  - `Notifier`: `NeedsYouNotifier`, `SystemNotifications`.
  - `SealedPaneView`: an HTML pane in a sealed WKWebView (rules below).
  - `StatusPaneView`: a status pane, drawn natively: no web view, no JavaScript, plain text only.
  - `PaneFrame`, `RimView`: the identity the client draws (rim colour, striped when untrusted, silo,
    namespace, host, stale and needs-you marks).
  - `PaneAPI`: lists and watches panes, lists namespaces, reads a silo's host and trust, downloads a
    bundle and checks its digest.
  - `PaneBundle`: digest check and unpacking into a fresh folder per opened pane.
  - `PaneStore`: the app's state (panes, switches per cluster, silo info, one controller per open
    HTML pane).
- `Sources/KevasoPanes`: the app: one main window (clusters, namespace, panes and their switches),
  one floating window per pane turned on.
- `Tests/PaneKitTests`: the hostile-pane suite; the API, store and window tests against a fake control
  plane; sign-in against a fake issuer over TLS; TLS pinning; the keychain.

Needs macOS 14 or later (the tests' TLS server: macOS 15) and Swift 6 (Xcode or the command line
tools). No admin rights.

## Build and run

```bash
cd apps/panes
```

```bash
swift build
```

```bash
swift run KevasoPanes
```

Press **Add Cluster…** and give what your admin gave you for `kvo login`: the server and the CA
fingerprint (`sha256:…`), plus a name and a namespace. The app downloads the CA, accepts it only
with that fingerprint, checks the server holds a certificate from it, then opens your browser to
sign in (the invite code). Add as many clusters as you like and switch between them in the sidebar;
right-click one to sign in, sign out or remove it.

For CI, the environment still works and wins over the clusters:

```bash
KVO_SERVER=https://control-plane:6443 KVO_CA_FILE=ca.pem KVO_TOKEN=… KVO_NAMESPACE=team swift run KevasoPanes
```

`KVO_TOKEN` alone overrides the token of a signed-in cluster.

## Sign-in, tokens, TLS

- **Like `kvo login`** (core's `internal/login`, research E022): authorization code with PKCE (S256),
  `state` and `nonce`, redirect `http://127.0.0.1:<free port>/callback`. The browser is sent to the
  app's own loopback port, which relays `GET /oidc/authorize` and `POST /oidc/login` to the control
  plane over the pinned TLS session, so a private CA causes no certificate warning and the browser
  never talks to the cluster unverified. The relay checks the Host header (DNS rebinding), passes
  back only Content-Type, Cache-Control, CSP and X-Frame-Options (no cookies), and a redirect only
  to this sign-in's own callback. A callback with the wrong `state` is ignored.
- **Client id**: the app uses kvo's public client `kvo`. The issuer's rules for it (no secret, PKCE,
  a loopback redirect on any port) fit the app exactly, and a second client id would buy nothing the
  issuer checks today; it can be split later if the issuer ever treats clients differently.
- **The keychain**: the refresh token is a generic password in the login keychain, service
  `com.kevaso.panes`, account the cluster's id. Never `kvo`'s items (`com.kevaso.kvo`): the app and
  kvo have separate sessions, and signing out of one leaves the other. Never the defaults or a file:
  `contexts.json` (Application Support/KevasoPanes, 0600) holds the server, CA and namespace only.
  Access tokens stay in memory. An unsigned build is identified by its code hash, so after a rebuild
  macOS may ask once whether the new binary may read the item.
- **Refresh**: an access token within 30 s of expiry is refreshed; the rotated refresh token is saved
  before the new access token is used; concurrent callers share one refresh. A 401 drops the cached
  access token and tries once more.
- **Revoked or reused**: when the issuer says the refresh token was already used (a copy got out:
  it revoked the session for everyone) or the session ended, the app deletes the keychain item,
  closes the cluster's panes and shows that it is signed out. "Raced" (another copy of the app
  refreshed a moment ago) re-reads the keychain and goes on.
- **Sign-out** calls the issuer's `POST /oidc/revoke` (added for this app, RFC 7009, in core's
  `internal/issuer`) with the refresh token, then deletes the keychain item. If the cluster can't be
  reached the local sign-out still happens and the session ends when idle.
- **TLS**: every request (API, watch, bundle, token, the relayed pages) goes through a session that
  anchors to the cluster's CA only (`SecTrustSetAnchorCertificatesOnly`), checks the hostname or IP,
  fetches nothing (no AIA or OCSP), and follows no redirect. https without a pinned CA is refused
  before any request: the system roots are never used. Plain http only to loopback (the tests).
  The one unverified request is `GET /ca.crt` while adding a cluster, and its answer is checked
  against the fingerprint before anything else happens.

## Floating panes

Each pane turned on is a `PanePanel`: a small window at the floating level on every Space, never
key and never main, that doesn't activate the app (a click in a pane leaves the keyboard where it
was). The header (identity, untrusted, needs-you and stale marks, a × that turns the pane off) drags
it; the edges resize it, between 220×140 and 1400×1000. Where each window was is kept per cluster and
pane in `windows.json` and fitted to the screens there are when it reopens (a window on an unplugged
display comes back stacked at the bottom right). The main window lists clusters, the namespace and
the panes with their switches.

A pane can't affect any window: WebKit's `resizeTo`, `moveTo`, `close`, `focus` and sized
`window.open` reach UI delegate methods the sealed view doesn't implement, fullscreen is off, the
panel can't become key (hostile case t17). A pane that calls `window.close()` only silences itself.

**Needs you**: when a pane that's turned on changes into `state: needs-you`, its rim glows and, if the
person ticked "Notify me when a pane needs me" (and allowed it in macOS), a notification says
"SILO needs you · PANE · NAMESPACE". The text is the client's (the silo's name, the pane's name made
plain), never the silo's message. A repeat of the same state doesn't ring again, and one pane rings at
most once a minute. A pane's content can't raise one: the sealed view refuses the Notification API
(t07, t17). macOS notifications need the app to run as a bundle; with `swift run` it bounces the
Dock icon instead.

## Untrusted silos: the striped rim

Design §7: untrusted silos get a striped rim. Where "untrusted" comes from:

- **A label on the Silo object**, `kevaso.com/trust: untrusted`, read by the client with the same
  token (`GET …/silos/NAME`, the read that already gives the host). Never from the pane's report or
  content.
- **Unknown is striped too**: until the client has read the Silo object, or when it can't (no
  permission, an error), the rim is striped and the header says "trust unknown". Only a silo the
  client read and found unmarked gets the solid rim.
- Not from the runtime: container versus microVM is about isolation strength, not about whether the
  silo runs code or content you shouldn't trust (a microVM crawler is still untrusted).

**Proposal for the orchestrator (no Go API change made):**

1. Make `kevaso.com/trust` a reserved label: settable only by someone who may update the Silo (it is
   today), never by credentials the silo itself holds (kvo-guest's pane reports write Pane objects
   only; keep it that way), and documented next to `kevaso.com/protected`.
2. Optionally, have the control plane copy it into the Pane object's server-set fields (say
   `status.siloTrust: untrusted`) when it stores a report, so a client that may read panes but not
   silos still draws the right rim, and with one read less. The client would prefer that field when
   present and keep reading the Silo otherwise.
3. Optionally, `kvo create silo --untrusted` (or a `sandbox-untrusted` template) sets the label, and
   a silo with an empty keyring could be marked by default.

## The regression suite: rerun on every macOS / WebKit update

```bash
swift test
```

That one command runs everything; the hostile suite alone is `swift test --filter HostileSuiteTests`.
It takes about 3 minutes and needs a logged-in desktop session: small panes appear at the bottom
right of the screen and are clicked and typed into by synthetic events. Leave them alone while it runs.
The sign-in tests write to the login keychain under a service of their own
(`com.kevaso.panes.test-…`) and delete it afterwards; they never touch the app's or kvo's items. The
TLS tests make throwaway CAs with `/usr/bin/openssl` in a temp folder and load the server identity
into memory only (nothing is imported into a keychain).

**Rerun it after every macOS or Safari/WebKit update, and after any change to `SealedPolicy` or
`SealedPaneView`.** Two of the protections rely on private WebKit settings that can change or vanish
silently (`test00_privateSettingsStillExist` fails first if one does), and E034 showed a "standard"
control (`webrtc 'block'` in the CSP) doing nothing at all.

How it measures (ported from research E034): a collector inside the test process listens on
`127.0.0.1` and the Mac's LAN address, TCP and UDP, on free ports, and records every TCP connection
(even one that sends nothing), every request and every datagram: that is "the outside". Each hostile
bundle (`Tests/PaneKitTests/Hostile`) is loaded into a `SealedPaneView`, hovered and clicked where the
case needs a user gesture, and the case passes only if the collector got **nothing** and the page's own
report shows each attempt failed. Positive controls prove the measurement works: an unsealed web view
does reach the collector over HTTP and WebRTC UDP, and a plain web view does receive typed keys.
If a case would change the clipboard, the test restores the person's clipboard from an in-memory copy;
its content is never logged.

| Case | Attack | Asserted |
|---|---|---|
| t01 | every subresource kind (fetch, XHR, beacon, img, CSS, fonts, scripts, import(), iframes, media, workers, service worker), loopback and LAN | 0 hits |
| t02 | WebSocket, EventSource, WebRTC (main realm, fresh iframe realm) | 0 hits, no RTCPeerConnection anywhere |
| t03 | dns-prefetch, preconnect, `<a ping>`, hover then click | 0 hits (no link preconnect), click never reaches the page |
| t04 | form submit, location.*, pushState, meta refresh, data:/javascript: URLs, link click | 0 hits, still on its own page |
| t05 | window.open with and without a click, target=_blank, top.location | 0 hits, no window, no navigation |
| t06 | localStorage, sessionStorage, cookies, IndexedDB, Cache: another pane, the same pane in a new view | nothing seen |
| t07 | clipboard read/write (incl. iframe realm), execCommand copy, notifications, geolocation, camera/mic, screen capture, fullscreen, share, print, alert/prompt, file picker | clipboard unchanged, all refused |
| t08 | file://, `..` and `%2e%2e` traversal, sibling folder, other pane, symlink out | nothing read |
| t08b | the same through `<script src>`, which reaches the scheme handler itself | own file served, ≥5 refusals, no secret |
| t09 | `window.webkit.messageHandlers` | absent |
| t10a | busy loop | the watchdog kills it, its process ends, the neighbour pane keeps animating, the client never stalls, a new pane works |
| t10b, t10c | memory hog, giant canvases | closed, process ends, neighbour unaffected |
| t11 | data with `</script>`, quotes, backticks, U+2028, `__proto__`, `onerror` | arrives verbatim as data, never runs |
| t12 | a legitimate animated pane driven by data | renders, all updates arrive, > 20 fps (≈ 60 measured) |
| t13 | inline script, `<noscript>` and `onerror` beacons; a status pane whose fields carry HTML and markdown | 0 hits; status drawn with no web view, text verbatim |
| t14 *(new)* | click into a pane, type, ⌘V | no key or paste reaches the page (the pane takes no keyboard focus) |
| t15 *(new)* | `a download` (blob, data, own file), blob navigation, window.open(blob), with a click | no file saved, still on its page |
| t16 *(new)* | two open panes via BroadcastChannel, storage events, a named window, postMessage | neither hears the other |
| t17 *(new)* | in the app's floating window: resizeTo/By, moveTo/By, focus, blur, fullscreen, a Notification, a sized window.open, window.close, with and without a click | its window's frame, level and visibility unchanged, a neighbour pane's window unchanged, the key window unchanged, no visible window opened, 0 hits |
| t00 | the configuration: private settings exist and are applied, no drop targets, empty context menu | — |

## The sealed view

Every rule of design §10.1, in `SealedPolicy` and `SealedPaneView`:

- **Its own content security policy** on every response from the scheme handler; the bundle's own
  is never trusted (a meta CSP can only tighten). `default-src 'none'`, `connect-src 'none'`, no
  frames, workers or forms; scripts and styles only from the pane itself (inline allowed: the whole
  document is untrusted anyway).
- **A block-all content rule list**: every URL blocked except `kvpane:`.
- **A script at document start, in every frame**: removes WebRTC and `navigator.clipboard`, makes
  `execCommand` refuse copy/cut/paste, swallows copy/cut/paste and drag events, and cancels pointer and
  click defaults on links (WebKit preconnects on mousedown before navigation can be cancelled).
- **WebKit settings, private API**: `_setPeerConnectionEnabled:`, `_setMediaDevicesEnabled:`,
  `_setJavaScriptCanAccessClipboard:`, `_setDOMPasteAllowed:`, `_setDNSPrefetchingEnabled:` all off,
  and `_killWebContentProcess` for the watchdog. Private API: not on the Mac App Store, may change in
  any update, hence the suite. (The test harness also uses `_setWindowOcclusionDetectionEnabled:` and
  `_webProcessIdentifier` to measure; the app doesn't.)
- **A non-persistent data store per pane**, and **no script message handlers at all**.
- **A separate folder per opened pane** behind a scheme handler of its own that knows only that pane's
  id and folder and refuses anything else: other panes, `..` (encoded or not), symlinks out, folders,
  non-GET requests.
- **`data` only as a call argument** (`callAsyncJavaScript` with `arguments`): bundles define
  `window.kvoUpdate(data)`. Nothing is ever pasted into source.
- **A watchdog**: a ping every second in a script world of the client's own; a pane that leaves one
  unanswered for 3 s is killed and shown as "stopped: unresponsive". It is never reloaded by itself.
- **Only its first page load**: every other navigation, response, download, new window, dialog, media
  capture, file picker and fullscreen is refused. No keyboard focus, no drops, an empty context menu,
  no text selection, no link previews, no magnification.
- **Status panes**: drawn natively in SwiftUI from the report's fields with `Text(verbatim:)`, after
  removing control characters and bidirectional overrides and capping lengths.
- **The identity is the client's**: the frame (rim colour from the namespace and silo name, silo name,
  pane name, namespace, host from the silo's status) is drawn by SwiftUI outside the pane's view, from
  the Pane object's server-set fields, never from the silo's report.

## Bundles

The control plane stores a bundle as opaque bytes and serves them at
`GET /apis/kevaso/v1/namespaces/NS/panes/NAME/bundle`. The client downloads it, refuses it unless its
SHA-256 is exactly the pane's `spec.bundle` (and it is at most 512 KiB), then unpacks it into a new
folder: a POSIX tar (ustar) of regular files and folders holding `index.html` (no links, no absolute
paths, no `..`, at most 256 files and 8 MiB unpacked), or else the bytes are the single `index.html`.
A new digest reopens the pane in a new folder and a new origin; other reports only push `data`.

## What is not done

- **Signing, notarisation, distribution**: out of scope; the app runs with `swift run`. So macOS
  notifications fall back to bouncing the Dock icon, and the keychain may ask again after a rebuild.
- **Several clusters at once**: clusters are added and switched; the panes of one cluster float at a
  time (switching closes the other's windows, which come back where they were).
- **Docking to an edge and the collapsed pill** of the mockup: panes float and resize; they don't dock
  or shrink to a pill yet. The prompt line is out of scope (nothing flows back to the silo).
- **An HA server list** (`kvo`'s comma-separated servers): a cluster here has one server URL.
- **DNS-only leaks** (`<link rel=dns-prefetch>` to a name nobody resolves) are still not measured: it
  needs a DNS server on port 53, i.e. admin rights. DNS prefetching is off in WebKit and link clicks
  never reach it, but the channel is unverified, as in E034.
- **Drag and drop** is asserted by configuration only (no drop types registered, drags swallowed):
  synthesising a real drag needs the Accessibility permission.
- **Real mouse drags and edge resizes** of the floating windows are AppKit's own and weren't
  synthesised (the tests set the frame and check it's remembered); the header button's click is.
- **Lockdown Mode** (`WKWebpagePreferences.isLockdownModeEnabled`, public API) wasn't tried: it might
  replace some private settings but could cost WebGL and JIT for three.js panes; worth an experiment.
- **Cost of many panes** (Q006): not measured.
