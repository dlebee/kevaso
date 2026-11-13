import AppKit
import SwiftUI
import XCTest
@testable import PaneKit

/// Floating pane windows: one per pane turned on, placed where the person left it (per pane and
/// cluster, kept on disk), closed when the pane is turned off; and the needs-you notifier.
@MainActor
final class WindowTests: XCTestCase {
    override func setUp() async throws { _ = try await Harness.get() } // a running NSApplication, as in the app

    func tempFile() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("kevaso-windows-\(UUID().uuidString.prefix(8)).json")
    }

    func testPlacesPersistAndFitTheScreens() throws {
        let f = tempFile()
        defer { try? FileManager.default.removeItem(at: f) }
        let p = WindowPlaces(file: f)
        p.set("c1|team/api.overview", NSRect(x: 100, y: 120, width: 330, height: 240))
        p.saveNow()
        let again = WindowPlaces(file: f)
        XCTAssertEqual(again.place("c1|team/api.overview"), NSRect(x: 100, y: 120, width: 330, height: 240))
        XCTAssertNil(again.place("c2|team/api.overview"), "places are per cluster")

        let screen = NSRect(x: 0, y: 0, width: 1440, height: 900)
        // on screen: kept
        XCTAssertEqual(WindowPlaces.fit(NSRect(x: 100, y: 100, width: 320, height: 220), screens: [screen]),
                       NSRect(x: 100, y: 100, width: 320, height: 220))
        // half off the edge: pulled back in
        XCTAssertEqual(WindowPlaces.fit(NSRect(x: 1300, y: -50, width: 320, height: 220), screens: [screen]),
                       NSRect(x: 1120, y: 0, width: 320, height: 220))
        // on a display that's gone: nil (the app cascades it instead)
        XCTAssertNil(WindowPlaces.fit(NSRect(x: 3000, y: 100, width: 320, height: 220), screens: [screen]))
        // too small or too big: within the limits
        XCTAssertEqual(WindowPlaces.fit(NSRect(x: 10, y: 10, width: 20, height: 20), screens: [screen])?.size, WindowPlaces.minSize)
        // a second display
        let right = NSRect(x: 1440, y: 0, width: 1920, height: 1080)
        XCTAssertEqual(WindowPlaces.fit(NSRect(x: 2000, y: 500, width: 320, height: 220), screens: [screen, right])?.origin,
                       NSPoint(x: 2000, y: 500))
        // cascade: bottom right, stacking up
        let c0 = WindowPlaces.cascade(0, screen: screen), c1 = WindowPlaces.cascade(1, screen: screen)
        XCTAssertEqual(c0.maxX, screen.maxX - 14)
        XCTAssertGreaterThan(c1.minY, c0.maxY)
    }

    func fakeCluster() throws -> FakeAPI {
        let fake = try FakeAPI()
        let base = "/apis/kevaso/v1/namespaces/team/panes"
        func pane(_ name: String, state: String) -> String {
            #"{"metadata":{"name":"\#(name)","namespace":"team"},"spec":{"silo":"\#(name.split(separator: ".")[0])","siloUID":"u-\#(name)","pane":"\#(name.split(separator: ".")[1])","kind":"status","title":"t","state":"\#(state)","message":"Your Mac needs your password","ttl":"30s"},"status":{"updatedAt":"2026-11-13T10:00:00Z"}}"#
        }
        fake.routes.with {
            $0[base] = .init(body: Data(#"{"items":[\#(pane("api.overview", state: "running")),\#(pane("scrape.overview", state: "running"))],"metadata":{"resourceVersion":"5"}}"#.utf8))
            $0[base + "?watch"] = .init(lines: [Data(#"{"type":"MODIFIED","object":\#(pane("scrape.overview", state: "needs-you"))}"#.utf8),
                                                Data(#"{"type":"MODIFIED","object":\#(pane("scrape.overview", state: "needs-you"))}"#.utf8),
                                                Data(#"{"type":"MODIFIED","object":\#(pane("api.overview", state: "needs-you"))}"#.utf8)])
            $0["/apis/kevaso/v1/namespaces/team/silos/scrape"] = .init(body: Data(#"{"metadata":{"labels":{"kevaso.com/trust":"untrusted"}},"status":{"host":"w2"}}"#.utf8))
            $0["/apis/kevaso/v1/namespaces/team/silos/api"] = .init(body: Data(#"{"metadata":{},"status":{"host":"w1"}}"#.utf8))
        }
        return fake
    }

    func testFloatingWindowsFollowTheSwitchesAndRememberTheirPlace() async throws {
        let fake = try fakeCluster()
        let defaults = UserDefaults(suiteName: "kevaso-panes-test-\(UUID().uuidString)")!
        let f = tempFile()
        defer { try? FileManager.default.removeItem(at: f) }
        let store = PaneStore(defaults: defaults)
        let floating = FloatingPanes(store: store, places: WindowPlaces(file: f))
        store.connect(ServerConfig(server: fake.url, namespace: "team"), scope: "c1")
        let listed = await eventually(5) { store.panes.count == 2 }
        XCTAssertTrue(listed, store.status)
        XCTAssertTrue(floating.windows.isEmpty, "nothing floats until it is turned on")

        store.setEnabled("team/api.overview", true)
        store.setEnabled("team/scrape.overview", true)
        let opened = await eventually(3) { floating.windows.count == 2 }
        XCTAssertTrue(opened)
        for w in floating.windows.values {
            XCTAssertTrue(w.panel.isVisible)
            XCTAssertEqual(w.panel.level, .floating, "always on top")
            XCTAssertFalse(w.panel.canBecomeKey)
            XCTAssertTrue(w.panel.styleMask.contains(.resizable))
            XCTAssertTrue(w.panel.styleMask.contains(.nonactivatingPanel))
            XCTAssertTrue(w.panel.collectionBehavior.contains(.canJoinAllSpaces))
        }
        // the trust read from the Silo object, not from the pane
        let trusted = await eventually(3) { store.silos["u-scrape.overview"]?.trust == .untrusted && store.silos["u-api.overview"]?.trust == .trusted }
        XCTAssertTrue(trusted)
        XCTAssertTrue(store.identity(store.panes["team/scrape.overview"]!).striped)
        XCTAssertFalse(store.identity(store.panes["team/api.overview"]!).striped)

        // the person moves and resizes one: remembered, and used when it opens again
        let w = floating.windows["team/api.overview"]!
        let moved = NSRect(x: 200, y: 200, width: 360, height: 260)
        w.panel.setFrame(moved, display: false)
        store.setEnabled("team/api.overview", false)
        let closed = await eventually(3) { floating.windows["team/api.overview"] == nil }
        XCTAssertTrue(closed)
        XCTAssertFalse(w.panel.isVisible)
        floating.places.saveNow()
        XCTAssertEqual(WindowPlaces(file: f).place("c1|team/api.overview"), moved)
        store.setEnabled("team/api.overview", true)
        let back = await eventually(3) { floating.windows["team/api.overview"] != nil }
        XCTAssertTrue(back)
        XCTAssertEqual(floating.windows["team/api.overview"]?.panel.frame, moved)

        floating.closeAll()
        XCTAssertTrue(floating.windows.isEmpty)
        store.disconnect()
    }

    /// The header's turn-off button sits where a titled window has its (transparent) titlebar: a click
    /// there must still reach it, and a drag elsewhere in the header must move the window.
    func testHeaderButtonIsClickable() async throws {
        var clicked = 0
        let ident = PaneIdentity(silo: "api", siloUID: "u", namespace: "team", host: "w1", trust: .trusted)
        let frame = NSRect(x: 300, y: 300, width: 320, height: 220)
        let w = PaneWindowController(key: "t", frame: frame, rootView: PaneFrame(identity: ident, paneName: "overview", stale: false,
            trailing: AnyView(Button { clicked += 1 } label: { Image(systemName: "xmark").font(.system(size: 9, weight: .bold)) }
                .buttonStyle(.plain))) { Color.black })
        w.show()
        await sleep(0.3)
        let host = w.panel.contentView!
        host.layoutSubtreeIfNeeded()
        // find the button's spot: the right end of the header row
        let p = NSPoint(x: frame.width - 14, y: frame.height - 15)
        for t in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
            let ev = NSEvent.mouseEvent(with: t, location: p, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                        windowNumber: w.panel.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!
            w.panel.sendEvent(ev)
        }
        let ok = await eventually(2) { clicked == 1 }
        XCTAssertTrue(ok, "the header button didn't get the click")
        w.close()
    }

    /// Only a change into needs-you of a pane that's turned on rings, once; the text is the client's
    /// (silo, pane, namespace), never the silo's message; nothing when the person hasn't allowed it.
    func testNeedsYouNotifies() async throws {
        let fake = try fakeCluster()
        let store = PaneStore(defaults: UserDefaults(suiteName: "kevaso-panes-test-\(UUID().uuidString)")!)
        var notes: [NeedsYouNotifier.Note] = []
        let notifier = NeedsYouNotifier(enabled: true) { notes.append($0) }
        store.onNeedsYou = { p, id in notifier.needsYou(p, id) }
        store.connect(ServerConfig(server: fake.url, namespace: "team"), scope: "c1")
        store.setEnabled("team/scrape.overview", true) // api.overview is off: its needs-you doesn't ring
        let rang = await eventually(5) { !notes.isEmpty }
        XCTAssertTrue(rang)
        await sleep(0.6) // the rest of the watch: a repeat, and a pane that's off
        XCTAssertEqual(notes, [.init(id: "team/scrape.overview", title: "scrape needs you", body: "overview · team")])
        XCTAssertFalse(notes.contains { $0.body.contains("password") || $0.title.contains("password") })
        store.disconnect()

        var off: [NeedsYouNotifier.Note] = []
        let quiet = NeedsYouNotifier(enabled: false) { off.append($0) }
        let p = try Pane.decode(Data(#"{"metadata":{"name":"a.b","namespace":"n"},"spec":{"silo":"a","siloUID":"u","pane":"b","kind":"status","state":"needs-you"}}"#.utf8))
        quiet.needsYou(p, PaneIdentity(silo: "a", siloUID: "u", namespace: "n", host: nil))
        XCTAssertTrue(off.isEmpty)
    }
}
