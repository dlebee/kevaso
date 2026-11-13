import CryptoKit
import Foundation
@testable import PaneKit

/// A fake Kevaso issuer over TLS (a throwaway CA), with the rules of core's internal/issuer: client
/// `kvo`, redirect http://127.0.0.1:<port>/callback only, PKCE S256, an invite code on the login
/// page, single-use codes, refresh tokens that rotate on every use, a just-replaced token within the
/// race grace answered "raced", an older one revoking the whole session, and /oidc/revoke.
final class FakeIssuer: @unchecked Sendable {
    struct Session { var user: String; var current: String; var previous: String?; var rotatedAt: Date }
    struct State {
        var codes: [String: (redirect: String, challenge: String)] = [:]
        var sessions: [String: Session] = [:]
        var revoked: [String] = []
        var accessTTL = 900
        var calls: [String] = []
        var loginRedirectOverride: String?
    }
    static let invite = "kvi_test-invite"
    static let raceGrace: TimeInterval = 10

    let state = Locked(State())
    let pki: TestPKI
    private var server: LoopbackHTTP!
    private(set) var url: URL!
    var now: () -> Date = Date.init

    init(pki: TestPKI) { self.pki = pki }

    func start() async throws {
        server = try TestPKI.tlsServer(try pki.serverIdentity()) { [weak self] r in
            guard let self else { return .text(500, "gone") }
            return self.handle(r)
        }
        url = URL(string: "https://127.0.0.1:\(try await server.start())")!
    }

    func stop() { server?.stop() }

    static let loopback = try! NSRegularExpression(pattern: #"^http://127\.0\.0\.1:[0-9]{1,5}/callback$"#)
    static func isLoopback(_ s: String) -> Bool { loopback.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil }

    func handle(_ r: LoopbackHTTP.Request) -> LoopbackHTTP.Response {
        state.with { $0.calls.append(r.method + " " + r.path) }
        switch (r.method, r.path) {
        case ("GET", "/healthz"): return .text(200, "ok\n")
        case ("GET", "/ca.crt"): return LoopbackHTTP.Response(status: 200, body: pki.caPEM)
        case ("GET", "/oidc/authorize"):
            let q = r.query
            guard q["client_id"] == "kvo", Self.isLoopback(q["redirect_uri"] ?? ""), q["response_type"] == "code",
                  q["code_challenge_method"] == "S256", (q["code_challenge"] ?? "").count >= 43, !(q["state"] ?? "").isEmpty else {
                return .text(400, "authorize: bad request")
            }
            let hidden = ["redirect_uri", "state", "code_challenge", "nonce"].map {
                "<input type=hidden name=\($0) value=\"\(q[$0] ?? "")\">"
            }.joined()
            return LoopbackHTTP.Response(status: 200, headers: [("Content-Type", "text/html; charset=utf-8"),
                                                               ("Content-Security-Policy", "default-src 'none'; form-action 'self'"),
                                                               ("Set-Cookie", "tracking=1")],
                                         body: Data("<form method=post action=/oidc/login>\(hidden)<input name=invite></form>".utf8))
        case ("POST", "/oidc/login"):
            let f = r.form
            guard f["invite"] == Self.invite else { return .text(401, "bad invite", type: "text/html") }
            guard let redirect = f["redirect_uri"], Self.isLoopback(redirect), let ch = f["code_challenge"], let st = f["state"] else {
                return .text(400, "login: bad request")
            }
            let code = UUID().uuidString
            state.with { $0.codes[code] = (redirect, ch) }
            var c = URLComponents(string: state.value.loginRedirectOverride ?? redirect)!
            c.queryItems = [.init(name: "code", value: code), .init(name: "state", value: st)]
            return LoopbackHTTP.Response(status: 302, headers: [("Location", c.url!.absoluteString)])
        case ("POST", "/oidc/token"): return token(r.form)
        case ("POST", "/oidc/revoke"):
            let f = r.form
            guard f["client_id"] == "kvo" else { return .json(401, ["error": "invalid_client"]) }
            if let t = f["token"], let (sid, _) = split(t) {
                state.with { s in
                    if let ss = s.sessions[sid], ss.current == t || ss.previous == t {
                        s.sessions[sid] = nil
                        s.revoked.append(sid)
                    }
                }
            }
            return LoopbackHTTP.Response(status: 200)
        default: return .text(404, "no")
        }
    }

    func split(_ t: String) -> (String, String)? {
        guard t.hasPrefix("kvr_"), let dot = t.firstIndex(of: ".") else { return nil }
        return (String(t[t.index(t.startIndex, offsetBy: 4)..<dot]), String(t[t.index(after: dot)...]))
    }

    func bad(_ e: String, _ d: String) -> LoopbackHTTP.Response { .json(400, ["error": e, "error_description": d]) }

    func tokens(_ sid: String, _ refresh: String, ttl: Int) -> LoopbackHTTP.Response {
        .json(200, ["access_token": "at_\(sid)_\(UUID().uuidString.prefix(8))", "token_type": "Bearer",
                    "expires_in": ttl, "refresh_token": refresh, "id_token": "x.y.z"])
    }

    func token(_ f: [String: String]) -> LoopbackHTTP.Response {
        guard f["client_id"] == "kvo" else { return .json(401, ["error": "invalid_client", "error_description": "unknown client"]) }
        switch f["grant_type"] {
        case "authorization_code":
            guard let code = f["code"], let v = f["code_verifier"], v.count >= 43 else { return bad("invalid_request", "missing") }
            let entry = state.with { $0.codes.removeValue(forKey: code) }
            guard let e = entry else { return bad("invalid_grant", "unknown, used or expired code") }
            guard e.redirect == f["redirect_uri"] else { return bad("invalid_grant", "redirect_uri doesn't match") }
            guard BrowserSignIn.challenge(v) == e.challenge else { return bad("invalid_grant", "PKCE verifier does not match") }
            let sid = UUID().uuidString.prefix(8).lowercased(), rt = "kvr_\(sid).\(UUID().uuidString)"
            state.with { $0.sessions[String(sid)] = Session(user: "bob", current: rt, previous: nil, rotatedAt: now()) }
            return tokens(String(sid), rt, ttl: state.value.accessTTL)
        case "refresh_token":
            guard let t = f["refresh_token"], let (sid, _) = split(t) else { return bad("invalid_grant", "malformed refresh token") }
            let now = now(), ttl = state.value.accessTTL
            return state.with { s -> LoopbackHTTP.Response in
                guard var ss = s.sessions[sid] else { return bad("invalid_grant", "session ended; run kvo login again") }
                if t == ss.previous {
                    if now.timeIntervalSince(ss.rotatedAt) < Self.raceGrace { return bad("invalid_grant", "refresh raced with another; try again") }
                    s.sessions[sid] = nil
                    s.revoked.append(sid)
                    return bad("invalid_grant", "refresh token was already used; session revoked")
                }
                guard t == ss.current else { return bad("invalid_grant", "session ended; run kvo login again") }
                let next = "kvr_\(sid).\(UUID().uuidString)"
                ss.previous = ss.current
                ss.current = next
                ss.rotatedAt = now
                s.sessions[sid] = ss
                return tokens(sid, next, ttl: ttl)
            }
        default: return bad("unsupported_grant_type", "")
        }
    }

    /// Plays the browser: opens the sign-in URL (on the app's loopback port), submits the invite and
    /// follows the redirect to the callback. Returns what it saw at each step.
    static func browse(_ authURL: URL, invite: String = FakeIssuer.invite) async -> [String] {
        final class NoRedirect: NSObject, URLSessionTaskDelegate {
            func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                            newRequest request: URLRequest) async -> URLRequest? { nil }
        }
        let s = URLSession(configuration: .ephemeral, delegate: NoRedirect(), delegateQueue: nil)
        defer { s.invalidateAndCancel() }
        var seen: [String] = []
        do {
            let (page, r1) = try await s.data(from: authURL)
            let h1 = r1 as! HTTPURLResponse
            seen.append("authorize \(h1.statusCode) cookie=\(h1.value(forHTTPHeaderField: "Set-Cookie") ?? "none") csp=\(h1.value(forHTTPHeaderField: "Content-Security-Policy") != nil)")
            guard h1.statusCode == 200 else { return seen }
            // the form's hidden fields, as a browser would submit them
            let html = String(decoding: page, as: UTF8.self)
            let re = try NSRegularExpression(pattern: #"name=([a-z_]+) value="([^"]*)""#)
            var form = ["invite": invite]
            for m in re.matches(in: html, range: NSRange(html.startIndex..., in: html)) {
                form[String(html[Range(m.range(at: 1), in: html)!])] = String(html[Range(m.range(at: 2), in: html)!])
            }
            var post = URLRequest(url: URL(string: "/oidc/login", relativeTo: authURL)!.absoluteURL)
            post.httpMethod = "POST"
            post.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            post.httpBody = OIDCClient.form(form)
            let (_, r2) = try await s.data(for: post)
            let h2 = r2 as! HTTPURLResponse
            seen.append("login \(h2.statusCode)")
            guard let loc = h2.value(forHTTPHeaderField: "Location"), let cb = URL(string: loc) else { return seen }
            let (_, r3) = try await s.data(from: cb)
            seen.append("callback \((r3 as! HTTPURLResponse).statusCode)")
        } catch {
            seen.append("error \(error.localizedDescription)")
        }
        return seen
    }
}
