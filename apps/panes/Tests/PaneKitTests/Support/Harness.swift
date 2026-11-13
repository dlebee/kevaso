import AppKit
import WebKit
import XCTest
@testable import PaneKit

/// A borderless panel that may become key (to test what typing reaches a pane).
final class TestPanel: NSPanel {
    override var canBecomeKey: Bool { true }
}

/// Shared state for the hostile suite: the collector ("the outside"), the hostile bundles with the
/// collector's addresses filled in, and the compiled rule list. Ported from research E034 (run.sh and
/// SealedPane's harness), with the collector in-process on ephemeral ports.
@MainActor
final class Harness {
    static var shared: Harness?
    let collector: Collector
    let bundles: URL
    let ruleList: WKContentRuleList
    let lan: String

    static func get() async throws -> Harness {
        if let shared { return shared }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        app.finishLaunching() // without it the windows count as hidden and WebKit throttles timers and frames
        let h = try await Harness()
        shared = h
        return h
    }

    private init() async throws {
        collector = try Collector()
        lan = collector.lan ?? "127.0.0.1"
        ruleList = try await SealedPolicy.ruleList()
        let src = Bundle.module.url(forResource: "Hostile", withExtension: nil)!
        let out = FileManager.default.temporaryDirectory.appendingPathComponent("kevaso-hostile-\(UUID().uuidString.prefix(8))")
        try FileManager.default.copyItem(at: src, to: out)
        let c = "http://127.0.0.1:\(collector.tcpPort)", l = "http://\(lan):\(collector.tcpPort)"
        let htmls = (FileManager.default.enumerator(at: out, includingPropertiesForKeys: nil)?.allObjects as? [URL] ?? []).filter { $0.pathExtension == "html" }
        for f in htmls {
            var s = try String(contentsOf: f, encoding: .utf8)
            s = s.replacingOccurrences(of: "__C__", with: c).replacingOccurrences(of: "__L__", with: l)
                .replacingOccurrences(of: "__LANIP__", with: lan)
                .replacingOccurrences(of: "__TCP__", with: "\(collector.tcpPort)").replacingOccurrences(of: "__UDP__", with: "\(collector.udpPort)")
            try s.write(to: f, atomically: true, encoding: .utf8)
        }
        // the symlink cases (run.sh)
        let fm = FileManager.default
        try fm.createSymbolicLink(atPath: out.appendingPathComponent("t08-files/link-to-passwd").path, withDestinationPath: "/etc/passwd")
        try fm.createSymbolicLink(atPath: out.appendingPathComponent("t08b-scheme-traversal/link-out").path, withDestinationPath: "../t08-files-secret/secret.js")
        try fm.createSymbolicLink(atPath: out.appendingPathComponent("t08b-scheme-traversal/link-dir-out").path, withDestinationPath: "../t08-files-secret")
        bundles = out
    }

    func dir(_ name: String) -> URL { bundles.appendingPathComponent(name) }
}

/// One sealed pane on screen, as the hostile suite drives it.
@MainActor
final class TestPane {
    let view: SealedPaneView
    let panel: TestPanel

    init(_ h: Harness, id: String, bundle: String, slot: Int = 0, watchdogTimeout: TimeInterval = 3) throws {
        view = try SealedPaneView(paneID: id, root: h.dir(bundle), ruleList: h.ruleList, watchdogTimeout: watchdogTimeout)
        let size = NSSize(width: 300, height: 180)
        let screen = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        let origin = NSPoint(x: screen.maxX - size.width - 24 - CGFloat(slot) * (size.width + 12), y: screen.minY + 24)
        panel = TestPanel(contentRect: NSRect(origin: origin, size: size), styleMask: [.borderless, .nonactivatingPanel],
                          backing: .buffered, defer: false)
        panel.level = .floating
        panel.isReleasedWhenClosed = false
        view.frame = NSRect(origin: .zero, size: size)
        if let w = view.web { Self.ignoreOcclusion(w) }
        panel.contentView = view
        panel.orderFrontRegardless()
    }

    func load() { view.load() }

    /// Test harness only (private API): inside xctest, which never runs NSApplication's own event
    /// loop, WebKit takes a visible panel for an occluded one and stops frames and throttles timers.
    /// The app runs a normal event loop and doesn't need this.
    static func ignoreOcclusion(_ w: WKWebView) {
        let sel = NSSelectorFromString("_setWindowOcclusionDetectionEnabled:")
        guard w.responds(to: sel), let m = w.method(for: sel) else { return }
        typealias F = @convention(c) (AnyObject, Selector, Bool) -> Void
        unsafeBitCast(m, to: F.self)(w, sel, false)
    }

    /// What the hostile page recorded about its own attempts (window.__report).
    func report(timeout: TimeInterval = 3) async -> String {
        await view.probe("return JSON.stringify(window.__report || null)", timeout: timeout) ?? "TIMEOUT"
    }

    func url() async -> String { await view.probe("return location.href") ?? "TIMEOUT" }

    func mouse(_ type: NSEvent.EventType, at p: NSPoint? = nil, clicks: Int = 1) {
        let p = p ?? NSPoint(x: panel.frame.width / 2, y: panel.frame.height / 2)
        if let ev = NSEvent.mouseEvent(with: type, location: p, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                       windowNumber: panel.windowNumber, context: nil, eventNumber: 0, clickCount: clicks,
                                       pressure: type == .mouseMoved ? 0 : 1) {
            panel.sendEvent(ev)
        }
    }

    /// Synthetic mouse moves across the pane (hover only).
    func hover() {
        panel.acceptsMouseMovedEvents = true
        for i in 0..<10 {
            mouse(.mouseMoved, at: NSPoint(x: panel.frame.width * CGFloat(i + 1) / 11, y: panel.frame.height / 2), clicks: 0)
        }
    }

    /// A click in the middle of the pane: gives the page user activation, as a real click would.
    func click() {
        mouse(.leftMouseDown)
        mouse(.leftMouseUp)
    }

    func key(_ chars: String, code: UInt16, flags: NSEvent.ModifierFlags = []) {
        for t in [NSEvent.EventType.keyDown, .keyUp] {
            if let ev = NSEvent.keyEvent(with: t, location: .zero, modifierFlags: flags, timestamp: ProcessInfo.processInfo.systemUptime,
                                         windowNumber: panel.windowNumber, context: nil, characters: chars,
                                         charactersIgnoringModifiers: chars, isARepeat: false, keyCode: code) {
                panel.sendEvent(ev)
            }
        }
    }

    func close() {
        view.close()
        panel.orderOut(nil)
        panel.close()
    }
}

func sleep(_ s: Double) async { try? await Task.sleep(nanoseconds: UInt64(s * 1_000_000_000)) }

func alive(_ pid: Int32) -> Bool { pid > 0 && kill(pid, 0) == 0 }

/// Waits until `cond` holds or `timeout` passes.
@MainActor
func eventually(_ timeout: Double, step: Double = 0.1, _ cond: () -> Bool) async -> Bool {
    var t = 0.0
    while !cond() && t < timeout { await sleep(step); t += step }
    return cond()
}
