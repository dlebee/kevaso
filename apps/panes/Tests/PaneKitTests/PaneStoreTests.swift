import AppKit
import SwiftUI
import XCTest
@testable import PaneKit

/// The app's store against the fake control plane: it lists, opens only the panes turned on, and
/// refuses an HTML pane whose bundle doesn't match its digest.
@MainActor
final class PaneStoreTests: XCTestCase {
    func testStoreOpensEnabledPanesAndRefusesWrongDigest() async throws {
        let fake = try FakeAPI()
        let ns = "team", base = "/apis/kevaso/v1/namespaces/team/panes"
        let good = Data("<!doctype html><script>window.kvoUpdate=d=>{window.__last=d}</script>".utf8)
        let gd = PaneBundle.digest(good)
        func pane(_ name: String, _ bundle: String) -> String {
            #"{"metadata":{"name":"\#(name)","namespace":"\#(ns)"},"spec":{"silo":"api","siloUID":"s1","pane":"\#(name.split(separator: ".")[1])","kind":"html","bundle":"\#(bundle)","data":{"n":1},"ttl":"30s"},"status":{"updatedAt":"2026-11-13T10:00:00Z"}}"#
        }
        let otherDigest = PaneBundle.digest(Data("something else".utf8))
        fake.routes.with {
            $0[base] = .init(body: Data(#"{"items":[\#(pane("api.good", gd)),\#(pane("api.swapped", otherDigest)),\#(pane("api.off", gd))],"metadata":{"resourceVersion":"5"}}"#.utf8))
            $0[base + "?watch"] = .init(lines: [])
            $0[base + "/api.good/bundle"] = .init(body: good)
            $0[base + "/api.swapped/bundle"] = .init(body: good) // not what its digest says
            $0["/apis/kevaso/v1/namespaces/team/silos/api"] = .init(body: Data(#"{"status":{"host":"mac-mini-2"}}"#.utf8))
        }
        UserDefaults.standard.removeObject(forKey: "enabledPanes")
        let store = PaneStore()
        store.enabled = ["team/api.good", "team/api.swapped"]
        store.connect(ServerConfig(server: fake.url, namespace: ns))
        let listed = await eventually(5) { store.panes.count == 3 }
        XCTAssertTrue(listed, store.status)
        let opened = await eventually(5) { store.controllers["team/api.good"]?.view != nil && store.controllers["team/api.swapped"]?.problem != nil }
        XCTAssertTrue(opened)
        XCTAssertNil(store.controllers["team/api.off"], "a pane that isn't turned on must not be opened")
        XCTAssertTrue(store.controllers["team/api.swapped"]?.problem?.contains("digestMismatch") ?? false, store.controllers["team/api.swapped"]?.problem ?? "")
        XCTAssertNil(store.controllers["team/api.swapped"]?.view)
        XCTAssertFalse(fake.requests.value.contains { $0.path.hasSuffix("/api.off/bundle") })
        let host = await eventually(5) { store.hosts["s1"] == "mac-mini-2" }
        XCTAssertTrue(host)
        XCTAssertTrue(store.shown.allSatisfy { store.enabled.contains($0.id) })
        let p = store.panes["team/api.good"]!
        XCTAssertTrue(p.isStale(now: p.status!.updatedAt!.addingTimeInterval(60)))
        store.enabled.remove("team/api.good")
        XCTAssertNil(store.controllers["team/api.good"])
        store.disconnect()
        UserDefaults.standard.removeObject(forKey: "enabledPanes")
    }

    /// Renders the frame the client draws (rim, silo, namespace, host, stale) around a status pane to a
    /// PNG in the temp folder, for a look by eye; checks only that it renders.
    func testFrameRenders() throws {
        let spec = Pane.Spec(silo: "payments-api", siloUID: "s1", pane: "overview", kind: "status", title: "claude · refactor",
                             state: "needs-you", progress: 0.57, message: "Keep legacy rounding in roundCents()?",
                             fields: [.init(label: "tests", value: "212/240")], bundle: nil, data: nil, ttl: "60s")
        let id = PaneIdentity(silo: "payments-api", siloUID: "s1", namespace: "team", host: "mac-mini-2")
        let v = NSHostingView(rootView: PaneFrame(identity: id, paneName: "overview", stale: true) {
            StatusPaneView(spec: spec, rim: id.rim)
        }.frame(width: 340, height: 220).padding(10).background(Color.black))
        v.frame = NSRect(x: 0, y: 0, width: 360, height: 240)
        v.layoutSubtreeIfNeeded()
        let rep = v.bitmapImageRepForCachingDisplay(in: v.bounds)!
        v.cacheDisplay(in: v.bounds, to: rep)
        let png = rep.representation(using: .png, properties: [:])!
        XCTAssertGreaterThan(png.count, 1000)
        let out = FileManager.default.temporaryDirectory.appendingPathComponent("kevaso-pane-frame.png")
        try png.write(to: out)
        print("FRAME \(out.path)")
    }
}
