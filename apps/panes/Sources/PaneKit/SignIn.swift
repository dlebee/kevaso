import CryptoKit
import Foundation

// Signing in to a cluster like `kvo login` (core: internal/login; research E022): authorization code
// with PKCE (S256) on a loopback redirect, through the system browser. The browser never talks to the
// control plane itself: the app serves http://127.0.0.1:PORT, relays the two sign-in pages to the
// control plane over TLS pinned to the cluster's CA, and receives the redirect on the same port. So a
// private CA causes no certificate warning and nothing goes unverified. The refresh token goes to the
// keychain under the app's own service; access tokens stay in memory.

public enum SessionError: Error, Equatable, CustomStringConvertible {
    case notSignedIn
    /// An old refresh token came back to the issuer: someone has a copy. The issuer ended the session.
    case revoked(String)
    /// The session is over (expired, revoked, user disabled): sign in again.
    case ended(String)
    case signIn(String)
    case timedOut
    case http(Int, String)

    public var description: String {
        switch self {
        case .notSignedIn: return "not signed in"
        case .revoked(let s): return "signed out: the session was revoked (\(s))"
        case .ended(let s): return "signed out: \(s)"
        case .signIn(let s): return "sign-in failed: \(s)"
        case .timedOut: return "sign-in timed out"
        case .http(let c, let s): return "HTTP \(c): \(s)"
        }
    }

    /// Whether the session is gone for good (versus a network problem worth retrying).
    public var endsSession: Bool {
        switch self {
        case .revoked, .ended, .notSignedIn: return true
        default: return false
        }
    }
}

public struct Tokens: Sendable, Equatable {
    public var accessToken: String
    public var refreshToken: String
    public var expiry: Date
}

/// The issuer's token and revocation endpoints, over the pinned session.
public struct OIDCClient: Sendable {
    /// The app uses kvo's public client: the same rules (no secret, PKCE, a loopback redirect on any
    /// port) fit it exactly, and a second client id would buy nothing the issuer checks today.
    public static let clientID = "kvo"
    public static let scopes = "openid offline_access groups"
    public static let pathAuthorize = "/oidc/authorize"
    public static let pathLogin = "/oidc/login"
    public static let pathToken = "/oidc/token"
    public static let pathRevoke = "/oidc/revoke"

    public let server: URL
    let http: PinnedSession

    public init(server: URL, http: PinnedSession) {
        self.server = server
        self.http = http
    }

    func url(_ path: String) -> URL {
        URL(string: server.absoluteString.trimmingSuffix("/") + path)!
    }

    static func form(_ f: [String: String]) -> Data {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        let s = f.sorted { $0.key < $1.key }.map {
            "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: allowed) ?? "")"
        }.joined(separator: "&")
        return Data(s.utf8)
    }

    enum Failure: Error, Equatable {
        case raced
        case reused(String)
        case ended(String)
        case transient(Int, String)
    }

    func post(_ path: String, _ f: [String: String]) async throws -> (Data, HTTPURLResponse) {
        var r = URLRequest(url: url(path), timeoutInterval: 30)
        r.httpMethod = "POST"
        r.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        r.setValue("application/json", forHTTPHeaderField: "Accept")
        r.httpBody = Self.form(f)
        return try await http.data(for: r)
    }

    func token(_ f: [String: String], now: Date = Date()) async throws -> Tokens {
        var f = f
        f["client_id"] = Self.clientID
        let (d, h) = try await post(Self.pathToken, f)
        let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] ?? [:]
        guard h.statusCode == 200 else {
            let err = obj["error"] as? String ?? "", desc = obj["error_description"] as? String ?? ""
            switch (h.statusCode, err) {
            case (400, "invalid_grant") where desc.contains("raced"): throw Failure.raced
            case (400, "invalid_grant") where desc.contains("already used"): throw Failure.reused(desc)
            case (400, "invalid_grant"), (401, "invalid_client"): throw Failure.ended(desc.isEmpty ? err : desc)
            default: throw Failure.transient(h.statusCode, desc.isEmpty ? err : desc)
            }
        }
        guard let at = obj["access_token"] as? String, !at.isEmpty, let rt = obj["refresh_token"] as? String, !rt.isEmpty else {
            throw Failure.transient(200, "no tokens in the answer")
        }
        let ttl = (obj["expires_in"] as? NSNumber)?.doubleValue ?? 60
        return Tokens(accessToken: at, refreshToken: rt, expiry: now.addingTimeInterval(ttl))
    }

    func exchange(code: String, redirect: String, verifier: String) async throws -> Tokens {
        do {
            return try await token(["grant_type": "authorization_code", "code": code, "redirect_uri": redirect, "code_verifier": verifier])
        } catch let f as Failure {
            switch f {
            case .raced, .reused, .ended: throw SessionError.signIn("the issuer refused the code")
            case .transient(let c, let s): throw SessionError.http(c, s)
            }
        }
    }

    func refresh(_ refreshToken: String) async throws -> Tokens {
        try await token(["grant_type": "refresh_token", "refresh_token": refreshToken])
    }

    /// Ends the session at the issuer (RFC 7009). Best effort: signing out locally happens anyway.
    func revoke(_ refreshToken: String) async -> Bool {
        guard let (_, h) = try? await post(Self.pathRevoke, ["token": refreshToken, "token_type_hint": "refresh_token", "client_id": Self.clientID])
        else { return false }
        return h.statusCode == 200
    }
}

/// One sign-in through the browser.
public struct BrowserSignIn: Sendable {
    public let oidc: OIDCClient
    public let open: @Sendable (URL) async -> Void
    public var timeout: TimeInterval = 300

    public init(oidc: OIDCClient, timeout: TimeInterval = 300, open: @escaping @Sendable (URL) async -> Void) {
        self.oidc = oidc
        self.timeout = timeout
        self.open = open
    }

    static func random(_ n: Int) -> Data {
        var b = [UInt8](repeating: 0, count: n)
        _ = SecRandomCopyBytes(kSecRandomDefault, n, &b)
        return Data(b)
    }

    static func base64url(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func challenge(_ verifier: String) -> String { base64url(Data(SHA256.hash(data: Data(verifier.utf8)))) }

    static let donePage = "<!doctype html><meta charset=utf-8><title>Kevaso</title><body style=\"font:16px system-ui;padding:40px\"><p>Signed in. You can close this tab and go back to Kevaso Panes.</p>"
    static let failPage = "<!doctype html><meta charset=utf-8><title>Kevaso</title><body style=\"font:16px system-ui;padding:40px\"><p>Sign-in failed. Check Kevaso Panes.</p>"

    public func run() async throws -> Tokens {
        let state = Self.base64url(Self.random(16)), nonce = Self.base64url(Self.random(16))
        let verifier = Self.base64url(Self.random(32)) // 43 characters
        let result = ResultBox()
        let portBox = PortBox()
        let oidc = self.oidc

        let server = try LoopbackHTTP { req in
            let me = "127.0.0.1:\(portBox.port)"
            // DNS rebinding: a page elsewhere that resolves its own name to 127.0.0.1 sends its own Host.
            guard req.headers["host"] == me else { return .text(421, "wrong host") }
            switch (req.method, req.path) {
            case ("GET", OIDCClient.pathAuthorize), ("POST", OIDCClient.pathLogin):
                return await Self.relay(req, oidc: oidc, callback: "http://\(me)/callback")
            case ("GET", "/callback"):
                let q = req.query
                if q["state"] != state {
                    return .text(400, Self.failPage, type: "text/html; charset=utf-8") // a forged callback: ignored
                }
                if let e = q["error"] {
                    result.finish(.failure(SessionError.signIn(PlainText.clean(e + " " + (q["error_description"] ?? ""), max: 200))))
                    return .text(400, Self.failPage, type: "text/html; charset=utf-8")
                }
                guard let code = q["code"], !code.isEmpty else {
                    result.finish(.failure(SessionError.signIn("no code in the callback")))
                    return .text(400, Self.failPage, type: "text/html; charset=utf-8")
                }
                result.finish(.success(code))
                return .text(200, Self.donePage, type: "text/html; charset=utf-8")
            default:
                return .text(404, "not found")
            }
        }
        let port = try await server.start()
        portBox.port = port
        defer { server.stop() }
        let redirect = "http://127.0.0.1:\(port)/callback"

        var c = URLComponents(string: "http://127.0.0.1:\(port)\(OIDCClient.pathAuthorize)")!
        c.queryItems = [
            .init(name: "client_id", value: OIDCClient.clientID), .init(name: "response_type", value: "code"),
            .init(name: "redirect_uri", value: redirect), .init(name: "scope", value: OIDCClient.scopes),
            .init(name: "state", value: state), .init(name: "nonce", value: nonce),
            .init(name: "code_challenge", value: Self.challenge(verifier)), .init(name: "code_challenge_method", value: "S256"),
        ]
        await open(c.url!)
        let code = try await result.wait(timeout: timeout)
        return try await oidc.exchange(code: code, redirect: redirect, verifier: verifier)
    }

    /// Relays one sign-in page to the control plane over the pinned TLS session. Only the headers a
    /// page needs come back, and a redirect only to this sign-in's own callback.
    static func relay(_ req: LoopbackHTTP.Request, oidc: OIDCClient, callback: String) async -> LoopbackHTTP.Response {
        var r = URLRequest(url: URL(string: oidc.server.absoluteString.trimmingSuffix("/") + req.target)!, timeoutInterval: 30)
        r.httpMethod = req.method
        if req.method == "POST" {
            r.httpBody = req.body
            r.setValue(req.headers["content-type"] ?? "application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        }
        r.setValue("text/html", forHTTPHeaderField: "Accept")
        do {
            let (d, h) = try await oidc.http.data(for: r)
            var headers: [(String, String)] = []
            for k in ["Content-Type", "Cache-Control", "Content-Security-Policy", "X-Frame-Options"] {
                if let v = h.value(forHTTPHeaderField: k) { headers.append((k, v)) }
            }
            if let loc = h.value(forHTTPHeaderField: "Location") {
                guard loc.hasPrefix(callback + "?") else { return .text(502, "the control plane redirected elsewhere: refused") }
                headers.append(("Location", loc))
            }
            return LoopbackHTTP.Response(status: h.statusCode, headers: headers, body: d)
        } catch {
            return .text(502, "can't reach the control plane: \(error.localizedDescription)")
        }
    }
}

final class PortBox: @unchecked Sendable {
    private var p: UInt16 = 0
    private let lock = NSLock()
    var port: UInt16 {
        get { lock.lock(); defer { lock.unlock() }; return p }
        set { lock.lock(); p = newValue; lock.unlock() }
    }
}

/// The callback's outcome, delivered once.
final class ResultBox: @unchecked Sendable {
    private var result: Result<String, Error>?
    private var waiter: CheckedContinuation<String, Error>?
    private let lock = NSLock()

    func finish(_ r: Result<String, Error>) {
        lock.lock()
        guard result == nil else { lock.unlock(); return }
        result = r
        let w = waiter
        waiter = nil
        lock.unlock()
        w?.resume(with: r)
    }

    func wait(timeout: TimeInterval) async throws -> String {
        let timer = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1e9))
            self?.finish(.failure(SessionError.timedOut))
        }
        defer { timer.cancel() }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<String, Error>) in
                lock.lock()
                if let r = result { lock.unlock(); c.resume(with: r); return }
                waiter = c
                lock.unlock()
            }
        } onCancel: { [weak self] in
            self?.finish(.failure(CancellationError()))
        }
    }
}

/// What the API client asks for a bearer token.
public protocol AccessTokens: Sendable {
    func token() async throws -> String
    /// The server refused the last token (401): get a new one next time.
    func invalidate() async
}

/// `KVO_TOKEN`: a fixed token, for CI.
public struct StaticToken: AccessTokens {
    let value: String
    public init(_ value: String) { self.value = value }
    public func token() async throws -> String { value }
    public func invalidate() async {}
}

/// A signed-in cluster: the refresh token in the vault, access tokens in memory, refreshed when
/// they are about to expire. A refresh token that comes back reused, or a session the issuer ended,
/// signs the context out (its vault item is deleted). Network failures keep the session.
public actor ClusterSession: AccessTokens {
    public nonisolated let context: ClusterContext
    let vault: TokenVault
    let oidc: OIDCClient
    let now: @Sendable () -> Date
    private var access: (token: String, expiry: Date)?
    private var refreshing: Task<String, Error>?
    private var onEnded: (@Sendable (SessionError) -> Void)?

    public init(context: ClusterContext, vault: TokenVault, now: @escaping @Sendable () -> Date = { Date() }) throws {
        self.context = context
        self.vault = vault
        self.oidc = OIDCClient(server: context.server, http: PinnedSession(ca: try context.pinnedCA()))
        self.now = now
    }

    /// Called when the session ends by itself (reuse detected, expired, revoked elsewhere).
    public func setOnEnded(_ f: (@Sendable (SessionError) -> Void)?) { onEnded = f }

    struct Stored: Codable { var refreshToken: String; var server: String }

    public nonisolated var isSignedIn: Bool { ((try? vault.read(context.id)) ?? nil) != nil }

    nonisolated func storedRefresh() throws -> String? {
        guard let d = try vault.read(context.id) else { return nil }
        return try? JSONDecoder().decode(Stored.self, from: d).refreshToken
    }

    func store(_ t: Tokens) throws {
        try vault.write(context.id, JSONEncoder().encode(Stored(refreshToken: t.refreshToken, server: context.server.absoluteString)))
        access = (t.accessToken, t.expiry)
    }

    /// Signs in through the browser (`open` shows the URL: the system browser in the app).
    public func signIn(timeout: TimeInterval = 300, open: @escaping @Sendable (URL) async -> Void) async throws {
        let t = try await BrowserSignIn(oidc: oidc, timeout: timeout, open: open).run()
        try store(t)
    }

    public func token() async throws -> String {
        if let a = access, a.expiry.timeIntervalSince(now()) > 30 { return a.token }
        if let r = refreshing { return try await r.value }
        let t = Task { try await self.refresh() }
        refreshing = t
        defer { refreshing = nil }
        return try await t.value
    }

    public func invalidate() { access = nil }

    private func refresh() async throws -> String {
        for _ in 0..<3 {
            guard let rt = try storedRefresh() else { throw SessionError.notSignedIn }
            do {
                let t = try await oidc.refresh(rt)
                try store(t) // the rotated refresh token first: the old one is now worthless
                return t.accessToken
            } catch let f as OIDCClient.Failure {
                switch f {
                case .raced: // another copy of the app refreshed at the same moment: read its token
                    try? await Task.sleep(nanoseconds: 200_000_000)
                    continue
                case .reused(let s): throw end(.revoked(s))
                case .ended(let s): throw end(.ended(s))
                case .transient(let c, let s): throw SessionError.http(c, s)
                }
            }
        }
        throw SessionError.http(0, "couldn't refresh the session")
    }

    private func end(_ e: SessionError) -> SessionError {
        access = nil
        try? vault.delete(context.id)
        onEnded?(e)
        return e
    }

    /// Signs out: the issuer ends the session (best effort), then the keychain item is deleted.
    /// Returns whether the issuer confirmed.
    @discardableResult
    public func signOut() async -> Bool {
        refreshing?.cancel()
        let rt = try? storedRefresh()
        access = nil
        try? vault.delete(context.id)
        guard let rt else { return false }
        return await oidc.revoke(rt)
    }
}

extension String {
    func trimmingSuffix(_ s: String) -> String { hasSuffix(s) ? String(dropLast(s.count)) : self }
}
