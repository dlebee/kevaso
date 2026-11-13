# Kevaso Panes (macOS)

The desktop client of the pane protocol (design §10.1): one window that owns many panes. A silo reports
what its status looks like; the control plane keeps the latest report per pane and relays it; this app
draws it. Nothing flows back to the silo.

- `Sources/PaneKit`: the library.
  - `SealedPaneView`: an HTML pane in a sealed WKWebView (rules below).
  - `StatusPaneView`: a status pane, drawn natively: no web view, no JavaScript, plain text only.
  - `PaneFrame`: the identity the client draws itself (rim colour, silo, namespace, host, stale mark).
  - `PaneAPI`: lists and watches panes, looks up a silo's host, downloads a bundle and checks its digest.
  - `PaneBundle`: digest check and unpacking into a fresh folder per opened pane.
  - `PaneStore`: the app's state (which panes are on, one sealed view per open HTML pane).
- `Sources/KevasoPanes`: the minimal SwiftUI app.
- `Tests/PaneKitTests`: the hostile-pane suite, and the API tests against a fake control plane.

Needs macOS 14 or later and Swift 6 (Xcode or the command line tools). No admin rights.

## Build and run

```bash
cd apps/panes
```

```bash
swift build
```

```bash
KVO_SERVER=https://control-plane:6443 KVO_CA_FILE=ca.pem KVO_TOKEN=… KVO_NAMESPACE=team swift run KevasoPanes
```

Without the environment, open the app's Settings (⌘,), fill in the server URL, CA file, token and
namespace, and press Connect. Turn panes on in the list; only those are shown and opened.

## The regression suite: rerun on every macOS / WebKit update

```bash
swift test
```

That one command runs everything; the hostile suite alone is `swift test --filter HostileSuiteTests`.
It takes about 2½ minutes and needs a logged-in desktop session: small panes appear at the bottom
right of the screen and are clicked and typed into by synthetic events. Leave them alone while it runs.

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

- **Keychain**: the token comes from `KVO_TOKEN` or the app's settings, stored in its defaults in plain
  text. The user's `kvo` login (tokens in the keychain) isn't read yet. Sign-in through the browser is
  out of scope.
- **Signing, notarisation, distribution**: out of scope; the app runs with `swift run`.
- **The striped rim for untrusted silos** (design §7): the Pane object doesn't say whether a silo is
  untrusted yet, so every rim is solid.
- **DNS-only leaks** (`<link rel=dns-prefetch>` to a name nobody resolves) are still not measured: it
  needs a DNS server on port 53, i.e. admin rights. DNS prefetching is off in WebKit and link clicks
  never reach it, but the channel is unverified, as in E034.
- **Drag and drop** is asserted by configuration only (no drop types registered, drags swallowed):
  synthesising a real drag needs the Accessibility permission.
- **TLS in the tests**: the fake control plane speaks plain HTTP on loopback (the client refuses plain
  HTTP to any other host). The CA-file path (anchor to that CA only, hostname checked) isn't exercised
  against a TLS server by the suite.
- **Panes as separate floating windows** (the mockup's pinned panels): this app is one window with a
  grid. Each pane is still its own sealed view.
- **Lockdown Mode** (`WKWebpagePreferences.isLockdownModeEnabled`, public API) wasn't tried: it might
  replace some private settings but could cost WebGL and JIT for three.js panes; worth an experiment.
- **Cost of many panes** (Q006): not measured.
