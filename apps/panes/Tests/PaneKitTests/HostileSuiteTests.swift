import AppKit
import SwiftUI
import WebKit
import XCTest
@testable import PaneKit

/// The hostile-pane regression suite (research E034, ported; design §10.1). Each case loads a
/// deliberately malicious bundle into `SealedPaneView` and asserts that "the outside" (a collector on
/// loopback and the LAN address, TCP and UDP) receives nothing, plus the case's own expectation.
///
/// **Rerun on every macOS / WebKit update** (`swift test` in apps/panes): two protections rely on
/// private WebKit settings that can change silently.
@MainActor
final class HostileSuiteTests: XCTestCase {
    var h: Harness!
    var start = 0

    override func setUp() async throws {
        h = try await Harness.get()
        start = h.collector.count
    }

    /// Zero leaks: nothing reached the collector while the case ran (plus a grace period).
    func assertNoLeak(_ name: String, file: StaticString = #filePath, line: UInt = #line) async {
        await sleep(1)
        let hits = h.collector.hits(since: start)
        XCTAssertEqual(hits.count, 0, "\(name) leaked: \(hits)", file: file, line: line)
        print("HOSTILE \(name): \(hits.isEmpty ? "0 leaks" : "\(hits.count) LEAKS \(hits)")")
    }

    /// One hostile page in one pane; optional hover and clicks; then its report.
    func simple(_ bundle: String, wait: Double = 4, click: Bool = false) async throws -> (TestPane, String) {
        let p = try TestPane(h, id: "p-\(bundle)", bundle: bundle)
        p.load()
        await sleep(1.5)
        if click {
            p.hover(); await sleep(2.0)                   // hover only
            p.click(); await sleep(0.4); p.click()
        }
        await sleep(wait)
        let r = await p.report()
        print("REPORT \(bundle): \(r)")
        return (p, r)
    }

    // MARK: t00: the configuration itself (fails first when an update removes a private setting)

    func test00_privateSettingsStillExist() throws {
        let avail = SealedPolicy.privatePreferencesAvailable()
        for (k, ok) in avail { XCTAssertTrue(ok, "private WebKit setting \(k) is gone: the sealed view lost a protection") }
        XCTAssertTrue(SealedPolicy.killAvailable, "_killWebContentProcess is gone: the watchdog can't stop a hung pane")
        let v = try SealedPaneView(paneID: "p-config", root: h.dir("t12-legit"), ruleList: h.ruleList)
        XCTAssertEqual(v.appliedPrivatePreferences.values.filter { !$0 }.count, 0)
        XCTAssertFalse(v.web!.acceptsFirstResponder)
        XCTAssertTrue(v.web!.registeredDraggedTypes.isEmpty, "the pane accepts drops")
        let menu = NSMenu(); menu.addItem(withTitle: "Open Link in New Window", action: nil, keyEquivalent: "")
        v.web!.willOpenMenu(menu, with: NSEvent())
        XCTAssertEqual(menu.items.count, 0, "the pane shows a context menu")
        XCTAssertEqual(v.web!.configuration.userContentController.userScripts.count, 1)
        XCTAssertFalse(v.web!.configuration.websiteDataStore.isPersistent)
        v.close()
    }

    /// Positive control: an unsealed web view leaks to the collector over HTTP and WebRTC UDP, so the
    /// collector really sees what the suite tries.
    func test00_positiveControlCollectorSeesLeaks() async throws {
        let w = WKWebView(frame: NSRect(x: 0, y: 0, width: 300, height: 180))
        let panel = TestPanel(contentRect: NSRect(x: 0, y: 0, width: 300, height: 180), styleMask: [.borderless], backing: .buffered, defer: false)
        panel.contentView = w; panel.isReleasedWhenClosed = false; panel.orderFrontRegardless()
        let html = try String(contentsOf: h.dir("t02-sockets-webrtc/index.html"), encoding: .utf8)
            + "<img src='http://127.0.0.1:\(h.collector.tcpPort)/control/img'>"
        w.loadHTMLString(html, baseURL: URL(string: "http://127.0.0.1:\(h.collector.tcpPort)/"))
        let got = await eventually(10) { h.collector.hits(since: start).contains { $0.kind == "udp" } }
        let hits = h.collector.hits(since: start)
        panel.orderOut(nil); panel.close()
        XCTAssertTrue(hits.contains { $0.kind == "request" }, "collector saw no HTTP from an unsealed view: \(hits)")
        XCTAssertTrue(got, "collector saw no WebRTC UDP from an unsealed view: \(hits)")
        print("HOSTILE control: unsealed view produced \(hits.count) collector hits (expected > 0)")
        await sleep(3) // let the control's stragglers land before the next case counts
    }

    // MARK: E034 cases

    func test01_subresources() async throws {
        let (p, r) = try await simple("t01-subresources")
        XCTAssertTrue(r.contains("done: t01"), r)
        XCTAssertTrue(r.contains("fetch: blocked"), r)
        p.close()
        await assertNoLeak("t01-subresources")
    }

    func test02_socketsAndWebRTC() async throws {
        let (p, r) = try await simple("t02-sockets-webrtc", wait: 6)
        XCTAssertTrue(r.contains("webrtc: ok no RTCPeerConnection API"), r)
        XCTAssertTrue(r.contains("webrtc-iframe-realm: ok no RTCPeerConnection in iframe realm"), r)
        XCTAssertTrue(r.contains("websocket: blocked"), r)
        XCTAssertTrue(r.contains("eventsource: blocked"), r)
        p.close()
        await assertNoLeak("t02-sockets-webrtc")
    }

    func test03_prefetchAndPing() async throws {
        let (p, r) = try await simple("t03-prefetch-ping", click: true)
        XCTAssertFalse(r.contains("a-click"), "a link click reached the page: \(r)")
        p.close()
        await assertNoLeak("t03-prefetch-ping")
    }

    func test04_navigation() async throws {
        let (p, r) = try await simple("t04-navigation", wait: 5, click: true)
        let url = await p.url()
        XCTAssertEqual(url, "kvpane://p-t04-navigation/index.html", r)
        XCTAssertTrue(r.contains("history.pushState-cross-origin: blocked"), r)
        p.close()
        await assertNoLeak("t04-navigation")
    }

    func test05_windows() async throws {
        let (p, r) = try await simple("t05-windows", click: true)
        XCTAssertTrue(r.contains("window.open-no-gesture: ok null"), r)
        XCTAssertEqual(NSApp.windows.filter { $0.isVisible && $0 !== p.panel && $0 is TestPanel == false }.count, 0)
        let url = await p.url()
        XCTAssertEqual(url, "kvpane://p-t05-windows/index.html")
        p.close()
        await assertNoLeak("t05-windows")
    }

    func test06_storage() async throws {
        let a1 = try TestPane(h, id: "p-storage-a", bundle: "t06-storage", slot: 0)
        a1.load(); await sleep(2.5)
        let rA1 = await a1.report()
        let b = try TestPane(h, id: "p-storage-b", bundle: "t06-storage", slot: 1)
        b.load(); await sleep(2.5)
        let rB = await b.report()
        a1.close()
        let a2 = try TestPane(h, id: "p-storage-a", bundle: "t06-storage", slot: 0)
        a2.load(); await sleep(2.5)
        let rA2 = await a2.report()
        b.close(); a2.close()
        print("REPORT t06: first=\(rA1) other=\(rB) reopened=\(rA2)")
        for (who, r) in [("other pane", rB), ("same pane, new view", rA2)] {
            XCTAssertTrue(r.contains("seen-localStorage: null"), "\(who): \(r)")
            XCTAssertTrue(r.contains("seen-sessionStorage: null"), "\(who): \(r)")
            XCTAssertTrue(r.contains(#"seen-cookie: \"\""#), "\(who): \(r)")
            XCTAssertTrue(r.contains("seen-indexedDB: ok undefined") || r.contains("seen-indexedDB: blocked"), "\(who): \(r)")
        }
        await assertNoLeak("t06-storage")
    }

    func test07_deviceAPIsAndClipboard() async throws {
        // Keep the person's clipboard untouched: snapshot it in memory, restore it if it changed. Never logged.
        let pb = NSPasteboard.general
        let saved = pb.pasteboardItems?.map { item in item.types.compactMap { t in item.data(forType: t).map { (t, $0) } } } ?? []
        let before = pb.changeCount
        let (p, r) = try await simple("t07-device-apis", click: true)
        let changed = pb.changeCount != before
        if changed {
            pb.clearContents()
            for item in saved {
                let n = NSPasteboardItem()
                for (t, d) in item { n.setData(d, forType: t) }
                pb.writeObjects([n])
            }
        }
        XCTAssertFalse(changed, "the pane changed the clipboard")
        XCTAssertFalse(r.contains("clipboard.writeText: ok written"), r)
        XCTAssertFalse(r.contains("clipboard.readText: ok read"), r)
        XCTAssertFalse(r.contains("execCommand-copy: ok true"), r)
        XCTAssertFalse(r.contains("getUserMedia: ok granted"), r)
        XCTAssertFalse(r.contains("requestFullscreen: ok fullscreen"), r)
        p.close()
        await assertNoLeak("t07-device-apis")
    }

    func test08_files() async throws {
        let (p, r) = try await simple("t08-files")
        XCTAssertFalse(r.contains("got ") && r.contains("root:"), "a system file was read: \(r)")
        for k in ["fetch-file-etc-passwd", "fetch-traversal-dots", "fetch-traversal-encoded", "fetch-sibling-prefix",
                  "fetch-other-pane", "fetch-symlink-out"] {
            XCTAssertFalse(r.contains("\(k): ok"), "\(k): \(r)")
        }
        XCTAssertTrue(r.contains("iframe-file-readable: ok no access"), r)
        p.close()
        await assertNoLeak("t08-files")
    }

    func test08b_schemeTraversal() async throws {
        let (p, r) = try await simple("t08b-scheme-traversal", wait: 2)
        XCTAssertTrue(r.contains("own.js loaded: true"), r)
        XCTAssertTrue(r.contains("SECRET loaded: undefined"), r)
        let denies = p.view.schemeLog.filter { $0.hasPrefix("DENY") }
        print("REPORT t08b scheme: \(p.view.schemeLog)")
        XCTAssertGreaterThanOrEqual(denies.count, 5, "\(p.view.schemeLog)")
        XCTAssertFalse(p.view.schemeLog.contains { $0.hasPrefix("serve") && $0.contains("secret") })
        p.close()
        await assertNoLeak("t08b-scheme-traversal")
    }

    func test09_messageHandlers() async throws {
        let (p, r) = try await simple("t09-message-handlers", wait: 1)
        XCTAssertTrue(r.contains("typeof window.webkit: undefined"), r)
        p.close()
        await assertNoLeak("t09-message-handlers")
    }

    /// The watchdog: a pane in a busy loop is killed (its process ends), the client stays responsive
    /// and a pane next to it keeps animating.
    func test10a_busyLoopKilledByWatchdog() async throws {
        let legit = try TestPane(h, id: "p-legit-10a", bundle: "t12-legit", slot: 1)
        legit.load(); await sleep(1.5)
        let hog = try TestPane(h, id: "p-t10a-busy-loop", bundle: "t10a-busy-loop", slot: 0, watchdogTimeout: 2)
        hog.load()
        await sleep(1.5)
        let pid = hog.view.webProcessID
        XCTAssertGreaterThan(pid, 0)
        let lag = LagProbe()
        let killed = await eventually(10) { hog.view.state == .stopped("unresponsive") }
        XCTAssertTrue(killed, "watchdog didn't stop the hung pane: \(hog.view.state) \(hog.view.events)")
        let gone = await eventually(5) { !alive(pid) }
        XCTAssertTrue(gone, "the hung pane's process \(pid) is still running")
        for i in 0..<5 { legit.view.push(["progress": Double(i) / 5, "label": "tick \(i)"]); await sleep(0.1) }
        let lr = await legit.report()
        XCTAssertTrue(lr.contains("updates: 5"), "the pane next to it stopped: \(lr)")
        XCTAssertLessThan(lag.worst, 0.5, "client main thread stalled")
        print("HOSTILE t10a: watchdog killed it, process gone=\(gone), worst lag \(String(format: "%.3f", lag.worst)) s, neighbour \(lr)")
        lag.stop()
        hog.close(); legit.close()
        // a fresh pane works afterwards
        let fresh = try TestPane(h, id: "p-legit-10a-reopened", bundle: "t12-legit")
        fresh.load(); await sleep(1.5)
        fresh.view.push(["progress": 0.5, "label": "reopened"]); await sleep(0.4)
        let fr = await fresh.report()
        XCTAssertTrue(fr.contains("updates: 1"), fr)
        fresh.close()
        await assertNoLeak("t10a-busy-loop")
    }

    func test10b_memoryHogClosed() async throws { try await hogCloses("t10b-memory") }
    func test10c_giantCanvasClosed() async throws { try await hogCloses("t10c-giant-canvas") }

    func hogCloses(_ bundle: String) async throws {
        let legit = try TestPane(h, id: "p-legit-\(bundle)", bundle: "t12-legit", slot: 1)
        legit.load(); await sleep(1.5)
        let hog = try TestPane(h, id: "p-\(bundle)", bundle: bundle, slot: 0)
        hog.load()
        let lag = LagProbe()
        for i in 0..<20 { legit.view.push(["progress": Double(i % 10) / 10, "label": "tick \(i)"]); await sleep(0.2) }
        let pid = hog.view.webProcessID
        let hr = await hog.report(timeout: 2)
        hog.close()
        let gone = await eventually(10) { !alive(pid) }
        XCTAssertTrue(gone, "\(bundle): process \(pid) still running after close")
        let lr = await legit.report()
        XCTAssertTrue(lr.contains("updates: 20"), "\(bundle): neighbour: \(lr)")
        XCTAssertLessThan(lag.worst, 0.5)
        print("HOSTILE \(bundle): hog \(hr), closed, process gone=\(gone), worst lag \(String(format: "%.3f", lag.worst)) s")
        lag.stop(); legit.close()
        await assertNoLeak(bundle)
    }

    func test11_dataInjection() async throws {
        let p = try TestPane(h, id: "p-inject", bundle: "t11-data-injection")
        p.load(); await sleep(1.5)
        let payloads: [Any] = [
            "</script><script>window.__pwned=1</script>",
            "\"); window.__pwned=2; //",
            "'; window.__pwned=3; //",
            "${window.__pwned=4}",
            "`; window.__pwned=5; `",
            ["__proto__": ["polluted": true], "constructor": ["prototype": ["polluted2": true]], "x": "<img src=x onerror=window.__pwned=6>"],
            "\u{2028}window.__pwned=7\u{2029}",
        ]
        for pl in payloads { p.view.push(pl); await sleep(0.2) }
        await sleep(1)
        let r = await p.report()
        print("REPORT t11: \(r)")
        XCTAssertTrue(r.contains("pwned: undefined"), r)
        XCTAssertTrue(r.contains("proto-polluted: undefined undefined"), r)
        let got = await p.view.probe("return String(window.__got.length)")
        XCTAssertEqual(got, "7")
        let first = await p.view.probe("return window.__got[0]")
        XCTAssertEqual(first, payloads[0] as? String)
        p.close()
        await assertNoLeak("t11-data-injection")
    }

    func test12_legitPaneWorks() async throws {
        let p = try TestPane(h, id: "p-legit", bundle: "t12-legit")
        p.load(); await sleep(1.5)
        let f0 = await p.view.probe("return String(frames)")
        for i in 0...20 { p.view.push(["progress": Double(i) / 20, "label": "step \(i)"]); await sleep(0.1) }
        await sleep(0.5)
        let r = await p.report()
        let f1 = await p.view.probe("return String(frames)")
        let fps = (Double(f1 ?? "0")! - Double(f0 ?? "0")!) / 2.6
        print("REPORT t12: \(r) ~\(Int(fps)) fps")
        XCTAssertTrue(r.contains("updates: 21"), r)
        XCTAssertTrue(r.contains(#"\"label\":\"step 20\""#), r)
        XCTAssertGreaterThan(fps, 20, "the legit pane barely animates")
        p.close()
        await assertNoLeak("t12-legit")
    }

    /// (a) a bundle whose inline script, `<noscript>` and `onerror` all try to beacon; (b) a status pane
    /// whose fields carry HTML: drawn natively, no web view, the text shown verbatim.
    func test13_scriptBeaconsAndStatusPane() async throws {
        let (p, r) = try await simple("t13-js-off", wait: 1)
        print("REPORT t13a: \(r)")
        p.close()
        let spec = Pane.Spec(silo: "api", siloUID: "u1", pane: "overview", kind: "status",
                             title: "claude · <b>refactor</b>", state: "needs-you", progress: 0.5,
                             message: "<img src=http://127.0.0.1:\(h.collector.tcpPort)/t13/status-img onerror=alert(1)> [link](http://127.0.0.1:\(h.collector.tcpPort)/md)",
                             fields: [.init(label: "<script>x</script>", value: "**bold**")], bundle: nil, data: nil, ttl: nil)
        let lines = StatusPaneView.lines(spec)
        XCTAssertEqual(lines[0], spec.title)
        XCTAssertEqual(lines[2], spec.message)
        XCTAssertEqual(lines[3], "<script>x</script>: **bold**")
        let host = NSHostingView(rootView: StatusPaneView(spec: spec, rim: Brand.amber).frame(width: 300, height: 180))
        let panel = TestPanel(contentRect: NSRect(x: 0, y: 0, width: 300, height: 180), styleMask: [.borderless], backing: .buffered, defer: false)
        panel.contentView = host; panel.isReleasedWhenClosed = false; panel.orderFrontRegardless()
        await sleep(1)
        func hasWeb(_ v: NSView) -> Bool { v is WKWebView || v.subviews.contains(where: hasWeb) }
        XCTAssertFalse(hasWeb(host), "a status pane must not use a web view")
        panel.orderOut(nil); panel.close()
        await assertNoLeak("t13-script-beacons+status")
    }

    // MARK: cases E034 listed as not covered, measurable without admin rights

    /// Clicking into a pane and typing (incl. ⌘V) must reach nothing: the pane takes no keyboard focus.
    func test14_keyboardAndPaste() async throws {
        let p = try TestPane(h, id: "p-t14-keyboard", bundle: "t14-keyboard")
        p.load(); await sleep(1.5)
        p.panel.makeKey()
        p.click(); await sleep(0.3)
        for (c, code) in [("a", UInt16(0)), ("s", 1), ("d", 2)] { p.key(c, code: code) }
        p.key("v", code: 9, flags: .command)
        p.panel.performKeyEquivalent(with: NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command, timestamp: 0,
            windowNumber: p.panel.windowNumber, context: nil, characters: "v", charactersIgnoringModifiers: "v", isARepeat: false, keyCode: 9)!)
        await sleep(0.5)
        let r = await p.report()
        print("REPORT t14: \(r) firstResponder=\(String(describing: p.panel.firstResponder))")
        XCTAssertTrue(r.contains("keys: 0"), r)
        XCTAssertTrue(r.contains("pastes: 0"), r)
        XCTAssertTrue(r.contains("value-changed: false"), r)
        XCTAssertFalse(p.panel.firstResponder is WKWebView)
        p.close()
        await assertNoLeak("t14-keyboard")
    }

    /// Positive control for t14: an ordinary web view in the same panel does get the keys, so the
    /// measurement works.
    func test14_positiveControlKeysReachPlainView() async throws {
        let w = WKWebView(frame: NSRect(x: 0, y: 0, width: 300, height: 180))
        let panel = TestPanel(contentRect: NSRect(x: 0, y: 0, width: 300, height: 180), styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.contentView = w; panel.isReleasedWhenClosed = false; panel.orderFrontRegardless()
        w.loadHTMLString("<body style=margin:0><textarea id=t style='width:100vw;height:100vh'></textarea><script>window.k=0;document.addEventListener('keydown',()=>window.k++,true)</script>", baseURL: nil)
        await sleep(1.5)
        panel.makeKey()
        for t in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
            panel.sendEvent(NSEvent.mouseEvent(with: t, location: NSPoint(x: 150, y: 90), modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                               windowNumber: panel.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!)
        }
        await sleep(0.3)
        for t in [NSEvent.EventType.keyDown, .keyUp] {
            panel.sendEvent(NSEvent.keyEvent(with: t, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                             windowNumber: panel.windowNumber, context: nil, characters: "a", charactersIgnoringModifiers: "a", isARepeat: false, keyCode: 0)!)
        }
        await sleep(0.5)
        let k = try await w.callAsyncJavaScript("return String(window.k)", contentWorld: .page) as? String
        panel.orderOut(nil); panel.close()
        XCTAssertNotEqual(k, "0", "control: a plain web view got no keys, so t14 measures nothing")
        print("HOSTILE t14 control: plain view saw \(k ?? "?") key events (expected > 0)")
    }

    /// A pane must not be able to save a file to disk.
    func test15_downloads() async throws {
        let name = "kevaso-hostile-\(UUID().uuidString.prefix(8)).txt"
        let f = h.dir("t15-downloads/index.html")
        try String(contentsOf: f, encoding: .utf8).replacingOccurrences(of: "__DLNAME__", with: name).write(to: f, atomically: true, encoding: .utf8)
        let (p, r) = try await simple("t15-downloads", click: true)
        let url = await p.url()
        XCTAssertEqual(url, "kvpane://p-t15-downloads/index.html", r)
        let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        XCTAssertFalse(FileManager.default.fileExists(atPath: downloads.appendingPathComponent(name).path), "the pane saved a file")
        print("REPORT t15: \(r) events=\(p.view.events)")
        p.close()
        await assertNoLeak("t15-downloads")
    }

    /// Two open panes must not hear each other (BroadcastChannel, storage events, named windows, postMessage).
    func test16_crossPane() async throws {
        let a = try TestPane(h, id: "p-cross-a", bundle: "t16-crosspane", slot: 0)
        let b = try TestPane(h, id: "p-cross-b", bundle: "t16-crosspane", slot: 1)
        a.load(); b.load()
        await sleep(3)
        let ra = await a.report(), rb = await b.report()
        print("REPORT t16: a=\(ra) b=\(rb)")
        XCTAssertTrue(ra.contains("heard: []"), ra)
        XCTAssertTrue(rb.contains("heard: []"), rb)
        XCTAssertTrue(ra.contains("named-window: null"), ra)
        a.close(); b.close()
        await assertNoLeak("t16-crosspane")
    }

    // MARK: t17: a pane in its own floating window, as the app shows it

    /// A pane in the app's floating window (PanePanel, the client's frame around it) tries to resize,
    /// move, close and focus its window, go fullscreen, open a sized window and raise a notification,
    /// with and without a click. Nothing changes: its window's frame, level and visibility, a
    /// neighbouring pane's window, which window is key, and the app's windows; nothing leaks.
    func test17_floatingWindowCantBeTakenOver() async throws {
        let screen = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        let frame = NSRect(x: screen.maxX - 340, y: screen.minY + 24, width: 320, height: 220)
        let view = try SealedPaneView(paneID: "p-t17-floating", root: h.dir("t17-floating"), ruleList: h.ruleList)
        TestPane.ignoreOcclusion(view.web!)
        let ident = PaneIdentity(silo: "sandbox-untrusted", siloUID: "s17", namespace: "team", host: "w2", trust: .untrusted)
        let w = PaneWindowController(key: "t17", frame: frame, rootView: PaneFrame(identity: ident, paneName: "overview", stale: false) {
            SealedViewHost(view: view)
        })
        let neighbourFrame = frame.offsetBy(dx: -340, dy: 0)
        let neighbour = PaneWindowController(key: "t17-n", frame: neighbourFrame, rootView: Color.blue)
        // a window of the person's that has the keyboard, which the pane must not take
        let mine = TestPanel(contentRect: NSRect(x: screen.minX + 24, y: screen.minY + 24, width: 200, height: 120),
                             styleMask: [.titled], backing: .buffered, defer: false)
        mine.isReleasedWhenClosed = false
        mine.makeKeyAndOrderFront(nil)
        w.show(); neighbour.show()
        let keyBefore = NSApp.keyWindow
        let windowsBefore = Set(NSApp.windows.map(ObjectIdentifier.init))
        XCTAssertFalse(w.panel.canBecomeKey)
        XCTAssertFalse(w.panel.canBecomeMain)
        XCTAssertTrue(w.panel.styleMask.contains(.nonactivatingPanel))
        XCTAssertEqual(w.panel.level, .floating)
        view.load()
        await sleep(1.5)
        // click into the pane's content (below the client's header)
        for t in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
            if let ev = NSEvent.mouseEvent(with: t, location: NSPoint(x: frame.width / 2, y: frame.height / 2 - 20), modifierFlags: [],
                                           timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: w.panel.windowNumber,
                                           context: nil, eventNumber: 0, clickCount: 1, pressure: 1) {
                w.panel.sendEvent(ev)
            }
        }
        await sleep(4)
        let r = await view.probe("return JSON.stringify(window.__report || null)") ?? "TIMEOUT"
        print("REPORT t17: \(r) events=\(view.events)")
        XCTAssertTrue(r.contains("done: t17"), r)
        XCTAssertTrue(r.contains("click: user click"), "the click didn't reach the pane: \(r)")
        XCTAssertEqual(w.panel.frame, frame, "the pane changed its window's frame")
        XCTAssertTrue(w.panel.isVisible, "the pane closed or hid its window")
        XCTAssertEqual(w.panel.level, .floating)
        XCTAssertFalse(w.panel.styleMask.contains(.fullScreen))
        XCTAssertEqual(neighbour.panel.frame, neighbourFrame)
        XCTAssertTrue(neighbour.panel.isVisible)
        XCTAssertFalse(w.panel.isKeyWindow, "the pane took the keyboard")
        XCTAssertTrue(NSApp.keyWindow === keyBefore, "the pane took focus from the person's window: \(String(describing: NSApp.keyWindow))")
        let extra = NSApp.windows.filter { !windowsBefore.contains(ObjectIdentifier($0)) }
        print("T17 extra windows: \(extra.map { "\(type(of: $0)) visible=\($0.isVisible) frame=\($0.frame) level=\($0.level.rawValue)" })")
        XCTAssertTrue(extra.allSatisfy { !$0.isVisible }, "the pane opened a window: \(extra)")
        XCTAssertFalse(r.contains("Notification: ok granted"), r)
        XCTAssertFalse(r.contains("requestFullscreen: ok fullscreen"), r)
        XCTAssertTrue(view.state == .running, "\(view.state)")
        view.close(); w.close(); neighbour.close()
        mine.orderOut(nil); mine.close()
        await assertNoLeak("t17-floating")
    }
}

/// The client's main-thread responsiveness: a 50 ms timer, worst lateness.
@MainActor
final class LagProbe {
    private(set) var worst = 0.0
    private var last = Date()
    private var timer: Timer?
    init() {
        timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                let late = Date().timeIntervalSince(self.last) - 0.05
                if late > self.worst { self.worst = late }
                self.last = Date()
            }
        }
    }
    func stop() { timer?.invalidate() }
}
