import AppKit
import XCTest
@testable import PaneKit

/// The client against a fake control plane (a small loopback HTTP server with canned panes): listing,
/// watching, the bundle download, the digest check, and the refusal of a wrong digest.
@MainActor
final class PaneAPITests: XCTestCase {
    let ns = "team"
    var fake: FakeAPI!
    var api: PaneAPI!
    let bundleHTML = Data("""
    <!doctype html><meta charset=utf-8><body><div id=o></div><script>
    window.__got=[];window.kvoUpdate=d=>{window.__got.push(d);document.getElementById('o').textContent=JSON.stringify(d)}
    </script>
    """.utf8)

    override func setUp() async throws {
        fake = try FakeAPI()
        api = try PaneAPI(ServerConfig(server: fake.url, tokens: StaticToken("test-token-not-a-secret"), namespace: ns))
    }

    func paneJSON(_ name: String, kind: String = "html", bundle: String? = nil, data: String = #"{"progress":0.5,"lit":3}"#,
                  updatedAt: String = "2026-11-13T10:00:00.123456789Z", ttl: String = "30s") -> String {
        let silo = String(name.split(separator: ".")[0]), pane = String(name.split(separator: ".")[1])
        let b = bundle.map { #","bundle":"\#($0)","data":\#(data)"# } ?? #","title":"claude · refactor","state":"running","progress":0.4"#
        return #"{"apiVersion":"kevaso/v1","kind":"Pane","metadata":{"name":"\#(name)","namespace":"\#(ns)","uid":"u-\#(name)","resourceVersion":"7"},"spec":{"silo":"\#(silo)","siloUID":"s-\#(silo)","pane":"\#(pane)","kind":"\#(kind)"\#(b),"ttl":"\#(ttl)"},"status":{"updatedAt":"\#(updatedAt)","updates":3}}"#
    }

    var base: String { "/apis/kevaso/v1/namespaces/\(ns)/panes" }

    func route(_ path: String, _ body: String, status: Int = 200) {
        fake.routes.with { $0[path] = .init(status: status, body: Data(body.utf8)) }
    }

    func testListDecodesPanesAndSendsToken() async throws {
        let d = PaneBundle.digest(bundleHTML)
        route(base, #"{"items":[\#(paneJSON("api.fleet", bundle: d)),\#(paneJSON("api.overview", kind: "status"))],"metadata":{"resourceVersion":"42"}}"#)
        let (panes, rv) = try await api.list()
        XCTAssertEqual(rv, "42")
        XCTAssertEqual(panes.map(\.metadata.name), ["api.fleet", "api.overview"])
        XCTAssertEqual(panes[0].spec.bundle, d)
        XCTAssertTrue(panes[0].isHTML)
        let v = try panes[0].spec.data!.value() as! [String: Any]
        XCTAssertEqual(v["lit"] as? Int, 3)
        XCTAssertEqual(panes[1].spec.title, "claude · refactor")
        XCTAssertNotNil(panes[1].status?.updatedAt)
        XCTAssertEqual(fake.requests.value.first?.headers["authorization"], "Bearer test-token-not-a-secret")
    }

    func testStale() throws {
        let p = try Pane.decode(Data(paneJSON("api.overview", kind: "status", updatedAt: "2026-11-13T10:00:00Z", ttl: "30s").utf8))
        let at = p.status!.updatedAt!
        XCTAssertFalse(p.isStale(now: at.addingTimeInterval(29)))
        XCTAssertTrue(p.isStale(now: at.addingTimeInterval(31)))
        XCTAssertEqual(GoDuration.parse("1m30s"), 90)
        XCTAssertEqual(GoDuration.parse("250ms"), 0.25)
        XCTAssertNil(GoDuration.parse("soon"))
    }

    func testWatchStreamsUpsertsAndDeletes() async throws {
        let d = PaneBundle.digest(bundleHTML)
        let lines = [#"{"type":"ADDED","object":\#(paneJSON("api.fleet", bundle: d))}"#,
                     #"{"type":"MODIFIED","object":\#(paneJSON("api.fleet", bundle: d, data: #"{"progress":0.9}"#))}"#,
                     #"{"type":"DELETED","object":\#(paneJSON("api.fleet", bundle: d))}"#].map { Data($0.utf8) }
        fake.routes.with { $0[base + "?watch"] = .init(lines: lines) }
        var got: [String] = []
        for try await e in api.watch(from: "42") {
            switch e {
            case .upsert(let p): got.append("upsert \(p.metadata.name) \(String(decoding: p.spec.data!.raw, as: UTF8.self))")
            case .deleted(let p): got.append("deleted \(p.metadata.name)")
            }
        }
        XCTAssertEqual(got, [#"upsert api.fleet {"lit":3,"progress":0.5}"#, #"upsert api.fleet {"progress":0.9}"#, "deleted api.fleet"])
        XCTAssertTrue(fake.requests.value.last!.path.contains("resourceVersion=42"))
    }

    func testWatchGone() async throws {
        fake.routes.with { $0[base + "?watch"] = .init(status: 410, body: Data("{}".utf8)) }
        do {
            for try await _ in api.watch(from: "1") {}
            XCTFail("expected gone")
        } catch let e as APIError {
            XCTAssertEqual(e, .gone)
        }
    }

    /// The whole HTML path: download by name, check the digest, lay it out in a folder of its own, open
    /// it sealed and push the pane's data.
    func testBundleDownloadDigestCheckAndOpen() async throws {
        let d = PaneBundle.digest(bundleHTML)
        let p = try Pane.decode(Data(paneJSON("api.fleet", bundle: d).utf8))
        fake.routes.with { $0[base + "/api.fleet/bundle"] = .init(headers: ["Content-Type": "application/octet-stream"], body: bundleHTML) }
        let bytes = try await api.bundle(for: p)
        XCTAssertEqual(bytes, bundleHTML)
        let parent = FileManager.default.temporaryDirectory.appendingPathComponent("kevaso-api-\(UUID().uuidString.prefix(8))")
        let dir = try PaneBundle.materialize(bytes, expected: d, under: parent)
        let dir2 = try PaneBundle.materialize(bytes, expected: d, under: parent)
        XCTAssertNotEqual(dir, dir2, "each opened pane gets its own folder")
        let view = try SealedPaneView(paneID: "p-api-fleet", root: dir, ruleList: try await SealedPolicy.ruleList())
        let panel = TestPanel(contentRect: NSRect(x: 0, y: 0, width: 300, height: 180), styleMask: [.borderless], backing: .buffered, defer: false)
        panel.contentView = view; panel.isReleasedWhenClosed = false; panel.orderFrontRegardless()
        TestPane.ignoreOcclusion(view.web!)
        view.push(try p.spec.data!.value()) // before load: kept and pushed once loaded
        view.load()
        let running = await eventually(5) { view.state == .running }
        XCTAssertTrue(running)
        await sleep(0.3)
        let got = await view.probe("return JSON.stringify(window.__got.map(d => [d.lit, d.progress]))")
        XCTAssertEqual(got, "[[3,0.5]]")
        view.close(); panel.orderOut(nil); panel.close()
        try? FileManager.default.removeItem(at: parent)
    }

    func testWrongDigestRefused() async throws {
        let d = PaneBundle.digest(bundleHTML)
        let p = try Pane.decode(Data(paneJSON("api.fleet", bundle: d).utf8))
        let evil = Data("<script>/* swapped */</script>".utf8)
        fake.routes.with { $0[base + "/api.fleet/bundle"] = .init(headers: ["Content-Type": "application/octet-stream"], body: evil) }
        do {
            _ = try await api.bundle(for: p)
            XCTFail("a bundle that doesn't match its digest was accepted")
        } catch let PaneBundle.Failure.digestMismatch(expected, got) {
            XCTAssertEqual(expected, d)
            XCTAssertEqual(got, PaneBundle.digest(evil))
        }
        // a malformed digest is refused before anything is compared
        XCTAssertThrowsError(try PaneBundle.verify(bundleHTML, expected: "md5:abc"))
        XCTAssertThrowsError(try PaneBundle.materialize(evil, expected: d, under: FileManager.default.temporaryDirectory))
    }

    func testRefusesPlainHTTPToARemoteHostAndHTTPSWithoutACA() {
        XCTAssertThrowsError(try PaneAPI(ServerConfig(server: URL(string: "http://kevaso.example.com")!)))
        XCTAssertThrowsError(try PaneAPI(ServerConfig(server: URL(string: "https://kevaso.example.com")!)), "the system roots must never be used")
    }

    /// The silo's host and trust come from the Silo object (labels), read with the same token.
    func testSiloInfoAndTrustLabel() async throws {
        fake.routes.with {
            $0["/apis/kevaso/v1/namespaces/team/silos/scrape"] = .init(body: Data(#"{"metadata":{"name":"scrape","labels":{"kevaso.com/trust":"untrusted"}},"spec":{"runtime":"microvm"},"status":{"host":"w2"}}"#.utf8))
            $0["/apis/kevaso/v1/namespaces/team/silos/api"] = .init(body: Data(#"{"metadata":{"name":"api","labels":{"kevaso.com/trust":"trusted-ish"}},"status":{"host":"w1"}}"#.utf8))
        }
        let s = try await api.silo("scrape")
        XCTAssertEqual(s, SiloInfo(host: "w2", trust: .untrusted))
        let a = try await api.silo("api")
        XCTAssertEqual(a, SiloInfo(host: "w1", trust: .trusted))
        await XCTAssertThrowsAsync(try await api.silo("missing"))
    }

    /// A 401 drops the cached access token and the request is tried once more with a new one.
    func testUnauthorizedGetsANewToken() async throws {
        final class Counting: AccessTokens, @unchecked Sendable {
            var n = 0, invalidated = 0
            func token() async throws -> String { n += 1; return "t\(n)" }
            func invalidate() async { invalidated += 1 }
        }
        let t = Counting()
        let a = try PaneAPI(ServerConfig(server: fake.url, tokens: t, namespace: ns))
        fake.routes.with { $0[base] = .init(status: 401, body: Data("{}".utf8)) }
        await XCTAssertThrowsAsync(try await a.list())
        XCTAssertEqual(t.invalidated, 1)
        XCTAssertEqual(fake.requests.value.suffix(2).map { $0.headers["authorization"] ?? "" }, ["Bearer t1", "Bearer t2"])
    }
}

/// The bundle format, the scheme handler's path rules and plain text, without a web view.
final class PaneUnitTests: XCTestCase {
    func tar(_ files: [(String, String)], extra: (inout Data) -> Void = { _ in }) -> Data {
        var d = Data()
        for (name, body) in files {
            var h = [UInt8](repeating: 0, count: 512)
            func put(_ s: String, _ at: Int) { for (i, b) in s.utf8.enumerated() { h[at + i] = b } }
            put(name, 0); put("0000644", 100); put("0000000", 108); put("0000000", 116)
            put(String(format: "%011o", body.utf8.count), 124); put("00000000000", 136)
            h[156] = name.hasPrefix("LINK:") ? UInt8(ascii: "2") : UInt8(ascii: "0")
            put("ustar", 257); put("00", 263)
            for i in 148..<156 { h[i] = 32 }
            put(String(format: "%06o", h.reduce(0) { $0 + Int($1) }) + "\0 ", 148)
            d.append(contentsOf: h)
            var b = Array(body.utf8); b += [UInt8](repeating: 0, count: (512 - b.count % 512) % 512)
            d.append(contentsOf: b)
        }
        d.append(Data(count: 1024))
        return d
    }

    func testTarBundle() throws {
        let t = tar([("index.html", "<p>hi"), ("js/app.js", "1")])
        XCTAssertTrue(PaneBundle.isTar(t))
        let fs = try PaneBundle.files(t)
        XCTAssertEqual(fs["js/app.js"], Data("1".utf8))
        XCTAssertEqual(try PaneBundle.files(Data("<p>single".utf8))["index.html"], Data("<p>single".utf8))
    }

    func testTarRefusesEscapes() {
        for bad in [[("../x", "1"), ("index.html", "")], [("/etc/x", "1")], [("a/../../x", "1")], [("LINK:x", "")], [("js/app.js", "no index")]] {
            XCTAssertThrowsError(try PaneBundle.files(tar(bad)), "\(bad)")
        }
    }

    func testSchemeHandlerResolve() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("kevaso-scheme-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("a"), withIntermediateDirectories: true)
        try Data("x".utf8).write(to: root.appendingPathComponent("index.html"))
        try Data("y".utf8).write(to: root.appendingPathComponent("a/b.js"))
        try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("out").path, withDestinationPath: "/etc/hosts")
        let h = try PaneSchemeHandler(paneID: "p1", root: root)
        XCTAssertNotNil(h.resolve(URL(string: "kvpane://p1/index.html")!))
        XCTAssertNotNil(h.resolve(URL(string: "kvpane://p1/a/b.js")!))
        for u in ["kvpane://p2/index.html", "kvpane://p1/../index.html", "kvpane://p1/%2e%2e/etc/hosts", "kvpane://p1/out",
                  "kvpane://p1/a", "kvpane://p1/a//b.js", "file:///etc/hosts", "kvpane://p1:80/index.html", "kvpane://u@p1/index.html"] {
            XCTAssertNil(h.resolve(URL(string: u)!), u)
        }
        try? FileManager.default.removeItem(at: root)
    }

    func testPlainText() {
        XCTAssertEqual(PlainText.clean("a\u{202E}cod.exe\nb"), "acod.exe b")
        XCTAssertEqual(PlainText.clean("<b>x</b>"), "<b>x</b>")
        XCTAssertEqual(PlainText.clean(String(repeating: "x", count: 10), max: 4), "xxxx…")
    }

    func testIdentityRimIsStable() {
        let a = PaneIdentity(silo: "api", siloUID: "1", namespace: "team", host: "h1")
        XCTAssertEqual(a.rimIndex, PaneIdentity(silo: "api", siloUID: "2", namespace: "team", host: nil).rimIndex)
    }

    /// Striped unless the client read the Silo object and it isn't marked untrusted.
    func testStripedRim() {
        for (t, striped) in [(SiloTrust.trusted, false), (.untrusted, true), (.unknown, true)] {
            XCTAssertEqual(PaneIdentity(silo: "a", siloUID: "1", namespace: "n", host: nil, trust: t).striped, striped)
        }
        XCTAssertEqual(SiloTrust.from(labels: ["kevaso.com/trust": "untrusted"]), .untrusted)
        XCTAssertEqual(SiloTrust.from(labels: nil), .trusted)
        XCTAssertEqual(SiloTrust.from(labels: ["trust": "untrusted"]), .trusted)
    }
}
