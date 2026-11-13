import Foundation
import XCTest
@testable import PaneKit

/// Started as kvo's plugin: the context from the environment, tokens from `kvo plugin token`.
final class KvoPluginTests: XCTestCase {
    func testContextFromTheEnvironment() throws {
        XCTAssertNil(KvoPluginContext.fromEnvironment([:]))
        XCTAssertNil(KvoPluginContext.fromEnvironment(["KVO_PLUGIN_SERVER": "https://cp:6443"]), "no kvo to ask for tokens")
        let c = try XCTUnwrap(KvoPluginContext.fromEnvironment([
            "KVO_PLUGIN_SERVER": "https://cp:6443", "KVO_PLUGIN_KVO": "/usr/local/bin/kvo",
            "KVO_PLUGIN_CONTEXT": "work", "KVO_PLUGIN_NAMESPACE": "team", "KVO_PLUGIN_CA_FILE": "/nowhere/ca.pem",
        ]))
        XCTAssertEqual(c.context, "work")
        XCTAssertEqual(c.namespace, "team")
        XCTAssertEqual(c.server.absoluteString, "https://cp:6443")
        XCTAssertThrowsError(try c.serverConfig(), "an unreadable CA")
        var noCA = c
        noCA.caFile = nil
        XCTAssertThrowsError(try noCA.serverConfig(), "https without a CA to pin")
        let dev = try XCTUnwrap(KvoPluginContext.fromEnvironment(["KVO_PLUGIN_SERVER": "http://127.0.0.1:8080", "KVO_PLUGIN_KVO": "/k"]))
        XCTAssertEqual(dev.namespace, "default")
        XCTAssertNotNil(try dev.serverConfig().tokens)
    }

    final class Calls: @unchecked Sendable {
        let lock = NSLock()
        var n = 0
        var answers: [String]
        init(_ a: [String]) { answers = a }
        func next() -> Data {
            lock.lock(); defer { lock.unlock() }
            n += 1
            return Data(answers.removeFirst().utf8)
        }
        var count: Int { lock.lock(); defer { lock.unlock() }; return n }
    }

    final class Clock: @unchecked Sendable {
        var t = Date(timeIntervalSince1970: 1_800_000_000)
    }

    func testTokensAreReusedUntilShortlyBeforeExpiry() async throws {
        let clock = Clock()
        let exp = ISO8601DateFormatter().string(from: clock.t.addingTimeInterval(300))
        let calls = Calls([
            #"{"token":"a1","expiresAt":"\#(exp)"}"#,
            #"{"token":"a2","expiresAt":"\#(exp)"}"#,
            #"{"token":"a3"}"#,
        ])
        let tokens = KvoPluginTokens(fetch: { calls.next() }, now: { clock.t })
        let first = try await tokens.token()
        let again = try await tokens.token()
        XCTAssertEqual(first, "a1")
        XCTAssertEqual(again, "a1")
        XCTAssertEqual(calls.count, 1)
        clock.t = clock.t.addingTimeInterval(271) // within 30 s of expiry
        let renewed = try await tokens.token()
        XCTAssertEqual(renewed, "a2")
        await tokens.invalidate() // a 401
        let afterInvalidate = try await tokens.token()
        XCTAssertEqual(afterInvalidate, "a3")
        XCTAssertEqual(calls.count, 3)
    }

    func testConcurrentCallersShareOneRun() async throws {
        let calls = Calls([#"{"token":"only","expiresAt":"2099-01-01T00:00:00.123456789Z"}"#])
        let tokens = KvoPluginTokens(fetch: {
            try await Task.sleep(nanoseconds: 50_000_000)
            return calls.next()
        }, now: { Date() })
        async let a = tokens.token()
        async let b = tokens.token()
        let got = try await [a, b]
        XCTAssertEqual(got, ["only", "only"])
        XCTAssertEqual(calls.count, 1)
    }

    /// The real thing: a stand-in kvo that prints a token, and one that fails (its message is kept).
    func testRunsKvo() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("kvo-plugin-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        func script(_ name: String, _ body: String) throws -> String {
            let p = dir.appendingPathComponent(name).path
            try Data("#!/bin/sh\n\(body)\n".utf8).write(to: URL(fileURLWithPath: p))
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: p)
            return p
        }
        let good = try script("kvo", #"[ "$1 $2" = "plugin token" ] || exit 9; echo '{"token":"tok","expiresAt":"2099-01-01T00:00:00Z"}'"#)
        let token = try await KvoPluginTokens(kvo: good).token()
        XCTAssertEqual(token, "tok")
        let bad = try script("kvo-bad", "echo 'not signed in: run kvo login' >&2; exit 1")
        do {
            _ = try await KvoPluginTokens(kvo: bad).token()
            XCTFail("a failing kvo gave a token")
        } catch let e as KvoPluginError {
            XCTAssertEqual(e, .token("not signed in: run kvo login"))
        }
    }
}
