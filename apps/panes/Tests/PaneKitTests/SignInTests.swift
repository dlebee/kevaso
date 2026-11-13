import Foundation
import XCTest
@testable import PaneKit

/// Sign-in like `kvo login`, against a fake issuer over TLS pinned to a throwaway CA: the browser
/// flow with PKCE through the app's loopback relay, the refresh token in the keychain (a test
/// service, deleted afterwards), refresh and rotation, the race, reuse detection, and sign-out.
final class SignInTests: XCTestCase {
    var pki: TestPKI!
    var issuer: FakeIssuer!
    var vault: KeychainVault!
    var context: ClusterContext!

    override func setUp() async throws {
        pki = try TestPKI(name: "issuer")
        issuer = FakeIssuer(pki: pki)
        try await issuer.start()
        vault = KeychainVault(service: "com.kevaso.panes.test-\(UUID().uuidString.prefix(8))")
        context = ClusterContext(name: "test", server: issuer.url, ca: pki.ca, namespace: "team")
    }

    override func tearDown() async throws {
        issuer?.stop()
        try vault?.deleteAll()
        XCTAssertEqual(try vault?.accounts() ?? [], [], "the test keychain items must be gone")
    }

    /// Signs in, playing the browser; returns what the browser saw.
    @discardableResult
    func signIn(_ s: ClusterSession) async throws -> [String] {
        let seen = Locked<[String]>([])
        let opened = Locked<URL?>(nil)
        try await s.signIn(timeout: 10) { url in
            opened.with { $0 = url }
            seen.with { $0 = [] }
            let got = await FakeIssuer.browse(url)
            seen.with { $0 = got }
        }
        let u = try XCTUnwrap(opened.value)
        XCTAssertEqual(u.scheme, "http")
        XCTAssertEqual(u.host, "127.0.0.1", "the browser is sent to the app's loopback relay, never to the cluster itself")
        return seen.value
    }

    func testBrowserSignInWithPKCEStoresTheRefreshTokenInTheKeychain() async throws {
        let s = try ClusterSession(context: context, vault: vault)
        XCTAssertFalse(s.isSignedIn)
        let seen = try await signIn(s)
        // the page came through the relay with its CSP and without the cookie; the redirect reached the app
        XCTAssertEqual(seen, ["authorize 200 cookie=none csp=true", "login 302", "callback 200"])
        XCTAssertTrue(s.isSignedIn)
        let item = try XCTUnwrap(try vault.read(context.id))
        let stored = try JSONDecoder().decode(ClusterSession.Stored.self, from: item)
        XCTAssertTrue(stored.refreshToken.hasPrefix("kvr_"))
        XCTAssertEqual(issuer.state.value.sessions.values.first?.current, stored.refreshToken)
        // nothing secret anywhere else: not in the app's defaults, not in the contexts file
        let defaults = UserDefaults.standard.dictionaryRepresentation().values.map { "\($0)" }.joined()
        XCTAssertFalse(defaults.contains(stored.refreshToken))
        let ctxJSON = String(decoding: try JSONEncoder().encode(context), as: UTF8.self)
        XCTAssertFalse(ctxJSON.contains("kvr_"))
        // an access token straight away, without another round trip
        let calls = issuer.state.value.calls.count
        let t = try await s.token()
        XCTAssertTrue(t.hasPrefix("at_"))
        XCTAssertEqual(issuer.state.value.calls.count, calls)
        // the app's sign-in never touches kvo's keychain service
        XCTAssertNotEqual(vault.service, "com.kevaso.kvo")
        XCTAssertEqual(KeychainVault.appService, "com.kevaso.panes")
    }

    func testRefreshRotatesAndSavesTheNewToken() async throws {
        issuer.state.with { $0.accessTTL = 5 } // under the 30 s margin: every call refreshes
        let s = try ClusterSession(context: context, vault: vault)
        try await signIn(s)
        let first = try XCTUnwrap(try s.storedRefresh())
        let a1 = try await s.token()
        let second = try XCTUnwrap(try s.storedRefresh())
        XCTAssertNotEqual(first, second, "the refresh token rotates")
        let a2 = try await s.token()
        XCTAssertNotEqual(a1, a2)
        XCTAssertEqual(issuer.state.value.sessions.values.first?.current, try s.storedRefresh())
        // concurrent callers share one refresh (a second one would present a spent token)
        let before = issuer.state.value.calls.filter { $0 == "POST /oidc/token" }.count
        async let x = s.token(), y = s.token(), z = s.token()
        let all = try await [x, y, z]
        XCTAssertEqual(Set(all).count, 1)
        XCTAssertEqual(issuer.state.value.calls.filter { $0 == "POST /oidc/token" }.count, before + 1)
    }

    /// Another copy of the app refreshed a moment ago: the issuer says "raced", the session re-reads
    /// the keychain and goes on with the newer token.
    func testRaceRereadsTheKeychain() async throws {
        issuer.state.with { $0.accessTTL = 5 }
        let s = try ClusterSession(context: context, vault: vault)
        try await signIn(s)
        let old = try XCTUnwrap(try s.storedRefresh())
        // the other copy: refreshes with the same token, then (a moment later) saves its new one
        let other = OIDCClient(server: issuer.url, http: PinnedSession(ca: pki.ca))
        let fresh = try await other.refresh(old)
        Task {
            try? await Task.sleep(nanoseconds: 100_000_000)
            try? self.vault.write(self.context.id, JSONEncoder().encode(ClusterSession.Stored(refreshToken: fresh.refreshToken, server: "")))
        }
        let t = try await s.token()
        XCTAssertTrue(t.hasPrefix("at_"))
        XCTAssertTrue(s.isSignedIn)
        XCTAssertEqual(issuer.state.value.revoked, [])
    }

    /// An old refresh token coming back means a copy got out: the issuer revokes the session and the
    /// app signs out (keychain item deleted, the app told).
    func testReusedRefreshTokenSignsOut() async throws {
        issuer.state.with { $0.accessTTL = 5 }
        var clock = Date()
        let now = Locked(clock)
        issuer.now = { now.value }
        let s = try ClusterSession(context: context, vault: vault)
        let ended = Locked<[SessionError]>([])
        await s.setOnEnded { e in ended.with { $0.append(e) } }
        try await signIn(s)
        let stolen = try XCTUnwrap(try s.storedRefresh())
        _ = try await s.token() // rotates: `stolen` is now the previous token
        clock += 60
        now.with { $0 = clock }
        // the copy is presented (the app restored from an old backup, say)
        try vault.write(context.id, JSONEncoder().encode(ClusterSession.Stored(refreshToken: stolen, server: "")))
        do {
            _ = try await s.token()
            XCTFail("a reused refresh token was accepted")
        } catch let e as SessionError {
            guard case .revoked = e else { return XCTFail("\(e)") }
            XCTAssertTrue(e.endsSession)
        }
        XCTAssertFalse(s.isSignedIn, "the app signs out")
        XCTAssertEqual(ended.value.count, 1)
        XCTAssertEqual(issuer.state.value.revoked.count, 1, "the issuer ended the session for everyone")
        await XCTAssertThrowsAsync(try await s.token())
    }

    /// The session ended at the issuer (revoked elsewhere, expired): signed out too.
    func testEndedSessionSignsOut() async throws {
        issuer.state.with { $0.accessTTL = 5 }
        let s = try ClusterSession(context: context, vault: vault)
        try await signIn(s)
        issuer.state.with { $0.sessions = [:] }
        do {
            _ = try await s.token()
            XCTFail("refreshed an ended session")
        } catch let e as SessionError {
            guard case .ended = e else { return XCTFail("\(e)") }
        }
        XCTAssertFalse(s.isSignedIn)
    }

    func testSignOutRevokesAtTheIssuerAndDeletesTheItem() async throws {
        let s = try ClusterSession(context: context, vault: vault)
        try await signIn(s)
        let sid = try XCTUnwrap(issuer.state.value.sessions.keys.first)
        let confirmed = await s.signOut()
        XCTAssertTrue(confirmed)
        XCTAssertFalse(s.isSignedIn)
        XCTAssertNil(try vault.read(context.id))
        XCTAssertEqual(issuer.state.value.revoked, [sid])
        XCTAssertTrue(issuer.state.value.sessions.isEmpty)
        await XCTAssertThrowsAsync(try await s.token())
        // signing out when not signed in is harmless
        let again = await s.signOut()
        XCTAssertFalse(again)
    }

    func testSignInRefusals() async throws {
        let s = try ClusterSession(context: context, vault: vault)
        // nobody completes the sign-in: it times out and the port closes
        do {
            try await s.signIn(timeout: 0.5) { _ in }
            XCTFail("expected a timeout")
        } catch let e as SessionError { XCTAssertEqual(e, .timedOut) }

        // a forged callback (wrong state) and a request for another Host are refused; then a wrong
        // invite: the sign-in can't finish
        let probes = Locked<[Int]>([])
        do {
            try await s.signIn(timeout: 2) { url in
                let port = url.port!
                let sess = URLSession(configuration: .ephemeral)
                defer { sess.invalidateAndCancel() }
                if let (_, r) = try? await sess.data(from: URL(string: "http://127.0.0.1:\(port)/callback?code=evil&state=guess")!) {
                    probes.with { $0.append((r as! HTTPURLResponse).statusCode) }
                }
                var rebind = URLRequest(url: url)
                rebind.setValue("evil.example:\(port)", forHTTPHeaderField: "Host")
                if let (_, r) = try? await sess.data(for: rebind) { probes.with { $0.append((r as! HTTPURLResponse).statusCode) } }
                if let (_, r) = try? await sess.data(from: URL(string: "http://127.0.0.1:\(port)/anything")!) {
                    probes.with { $0.append((r as! HTTPURLResponse).statusCode) }
                }
                _ = await FakeIssuer.browse(url, invite: "kvi_wrong")
            }
            XCTFail("signed in without a valid callback")
        } catch let e as SessionError { XCTAssertEqual(e, .timedOut) }
        XCTAssertEqual(probes.value, [400, 421, 404])
        XCTAssertFalse(s.isSignedIn)

        // the cluster's page redirecting somewhere other than this sign-in's callback is refused
        issuer.state.with { $0.loginRedirectOverride = "https://evil.example/callback" }
        let seen = Locked<[String]>([])
        do {
            try await s.signIn(timeout: 2) { url in let got = await FakeIssuer.browse(url); seen.with { $0 = got } }
            XCTFail("followed a redirect elsewhere")
        } catch let e as SessionError { XCTAssertEqual(e, .timedOut) }
        XCTAssertEqual(seen.value.last, "login 502")
    }

    /// The relay talks to the cluster only over the pinned CA: a context pinned to another CA can't
    /// even show the sign-in page.
    func testSignInPagesNeedThePinnedCA() async throws {
        let other = try TestPKI(name: "not-the-issuer")
        let wrong = ClusterContext(name: "wrong", server: issuer.url, ca: other.ca)
        let s = try ClusterSession(context: wrong, vault: vault)
        let seen = Locked<[String]>([])
        do {
            try await s.signIn(timeout: 2) { url in let got = await FakeIssuer.browse(url); seen.with { $0 = got } }
            XCTFail("signed in through an unpinned TLS connection")
        } catch {}
        XCTAssertEqual(seen.value, ["authorize 502 cookie=none csp=false"])
        XCTAssertFalse(issuer.state.value.calls.contains { $0.hasPrefix("GET /oidc/authorize") }, "nothing reached the issuer")
    }
}

/// The keychain under a test service name of its own, deleted afterwards.
final class KeychainTests: XCTestCase {
    func testReadWriteDeleteUnderATestService() throws {
        let v = KeychainVault(service: "com.kevaso.panes.test-\(UUID().uuidString.prefix(8))")
        defer { try? v.deleteAll() }
        XCTAssertNil(try v.read("a"))
        try v.write("a", Data("one".utf8))
        try v.write("b", Data("two".utf8))
        XCTAssertEqual(try v.read("a"), Data("one".utf8))
        try v.write("a", Data("uno".utf8)) // update in place
        XCTAssertEqual(try v.read("a"), Data("uno".utf8))
        XCTAssertEqual(Set(try v.accounts()), ["a", "b"])
        try v.delete("a")
        XCTAssertNil(try v.read("a"))
        try v.delete("a") // deleting what isn't there is fine
        try v.deleteAll()
        XCTAssertEqual(try v.accounts(), [])
        // another service doesn't see these items
        let w = KeychainVault(service: v.service + "-other")
        try v.write("x", Data("1".utf8))
        XCTAssertNil(try w.read("x"))
    }
}
