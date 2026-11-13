import CryptoKit
import Foundation
import Security

/// The cluster's CA, pinned: the only certificate any request to that cluster trusts (no system
/// roots). Its fingerprint is the one `kvo login SERVER --ca sha256:…` takes: SHA-256 of the DER of
/// the first certificate in the PEM.
public struct PinnedCA: Equatable, @unchecked Sendable {
    public let pem: Data
    public let fingerprint: String
    let certificates: [SecCertificate]

    public init(pem: Data) throws {
        let ders = try Self.ders(pem)
        let certs = ders.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard !certs.isEmpty, certs.count == ders.count else { throw TrustError.badCA("no certificate in the PEM") }
        self.pem = pem
        self.fingerprint = Self.fingerprint(der: ders[0])
        self.certificates = certs
    }

    public init(file: String) throws {
        guard let raw = FileManager.default.contents(atPath: file) else { throw TrustError.badCA("can't read \(file)") }
        try self.init(pem: raw)
    }

    public static func == (a: PinnedCA, b: PinnedCA) -> Bool { a.pem == b.pem }

    public static func fingerprint(der: Data) -> String {
        "sha256:" + SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
    }

    /// `sha256:<64 hex>` in lowercase, from what a person may paste (any case, colons, spaces).
    public static func normalize(fingerprint s: String) -> String? {
        var hex = s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if hex.hasPrefix("sha256:") { hex.removeFirst(7) }
        hex = hex.filter { $0 != ":" && !$0.isWhitespace }
        guard hex.count == 64, hex.allSatisfy(\.isHexDigit) else { return nil }
        return "sha256:" + hex
    }

    /// The DER of every certificate in a PEM (or the bytes themselves, if they are one DER).
    static func ders(_ raw: Data) throws -> [Data] {
        let text = String(decoding: raw, as: UTF8.self)
        guard text.contains("-----BEGIN CERTIFICATE-----") else { return [raw] }
        var out: [Data] = []
        for block in text.components(separatedBy: "-----BEGIN CERTIFICATE-----").dropFirst() {
            guard let body = block.components(separatedBy: "-----END CERTIFICATE-----").first,
                  let d = Data(base64Encoded: body.filter { !$0.isWhitespace }) else { throw TrustError.badCA("bad PEM block") }
            out.append(d)
        }
        return out
    }

    /// Whether the server's chain leads to this CA, for `host` (hostname or IP checked). Nothing is
    /// fetched from the network (no AIA, no OCSP).
    func evaluate(_ trust: SecTrust, host: String) -> Bool {
        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
        SecTrustSetNetworkFetchAllowed(trust, false)
        SecTrustSetAnchorCertificates(trust, certificates as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        return SecTrustEvaluateWithError(trust, nil)
    }
}

public enum TrustError: Error, Equatable, CustomStringConvertible {
    case badCA(String)
    case badFingerprint(String)
    case fingerprintMismatch(got: String, want: String)
    case notFromThatCA(String)
    case insecure(String)

    public var description: String {
        switch self {
        case .badCA(let s): return "CA: \(s)"
        case .badFingerprint(let s): return "\(s) is not a sha256:… fingerprint"
        case .fingerprintMismatch(let got, let want): return "the cluster's CA is \(got), not the \(want) you were given: not trusting it"
        case .notFromThatCA(let s): return "the server's certificate isn't from that CA (\(s))"
        case .insecure(let s): return "refusing \(s): only https (plain http only to loopback, for tests)"
        }
    }
}

/// A URLSession that trusts only one CA and never follows redirects. With no CA it speaks plain
/// HTTP to loopback only (the tests' fake servers); https without a pinned CA is refused outright,
/// so the system roots are never used.
public final class PinnedSession: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    public let ca: PinnedCA?
    private let acceptAnyOnce: Bool
    private lazy var session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.urlCache = nil
        c.httpCookieStorage = nil
        c.httpShouldSetCookies = false
        c.urlCredentialStorage = nil
        c.tlsMinimumSupportedProtocolVersion = .TLSv12
        c.timeoutIntervalForRequest = 3600 // watches stay open; plain calls set their own timeout
        return URLSession(configuration: c, delegate: self, delegateQueue: nil)
    }()

    public init(ca: PinnedCA?) {
        self.ca = ca
        self.acceptAnyOnce = false
        super.init()
    }

    /// For the one request that fetches the CA before it is trusted: any certificate is accepted,
    /// and the caller checks what comes back against the fingerprint.
    private init(unverifiedForCAFetch: Void) {
        self.ca = nil
        self.acceptAnyOnce = true
        super.init()
    }

    public static func isLoopback(_ host: String?) -> Bool { ["127.0.0.1", "localhost", "::1", "[::1]"].contains(host ?? "") }

    /// Refuses a URL this session must not talk to.
    public func check(_ url: URL) throws {
        switch url.scheme {
        case "https" where ca != nil || acceptAnyOnce: return
        case "https": throw TrustError.badCA("no CA pinned for \(url.host ?? "?")")
        case "http" where Self.isLoopback(url.host): return
        default: throw TrustError.insecure(url.absoluteString)
        }
    }

    public func data(for r: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try check(r.url!)
        let (d, resp) = try await session.data(for: r)
        guard let h = resp as? HTTPURLResponse else { throw APIError.http(0, "no response") }
        return (d, h)
    }

    public func bytes(for r: URLRequest) async throws -> (URLSession.AsyncBytes, HTTPURLResponse) {
        try check(r.url!)
        let (b, resp) = try await session.bytes(for: r)
        guard let h = resp as? HTTPURLResponse else { throw APIError.http(0, "no response") }
        return (b, h)
    }

    public func invalidate() { session.invalidateAndCancel() }

    func answer(_ challenge: URLAuthenticationChallenge) -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            return (.cancelAuthenticationChallenge, nil) // no client certificates, no passwords: nothing else is answered
        }
        if acceptAnyOnce { return (.useCredential, URLCredential(trust: trust)) }
        guard let ca, ca.evaluate(trust, host: challenge.protectionSpace.host) else { return (.cancelAuthenticationChallenge, nil) }
        return (.useCredential, URLCredential(trust: trust))
    }

    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge) async
        -> (URLSession.AuthChallengeDisposition, URLCredential?) { answer(challenge) }

    public func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge) async
        -> (URLSession.AuthChallengeDisposition, URLCredential?) { answer(challenge) }

    public func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                           newRequest request: URLRequest) async -> URLRequest? {
        nil // never followed: the caller sees the redirect itself
    }

    /// Downloads the cluster's CA (`/ca.crt`, public) and accepts it only if it has the fingerprint
    /// the person was given; then checks the server really holds a certificate from it (`/healthz`
    /// over the pinned CA). The same steps as `kvo login --ca`.
    public static func fetchCA(server: URL, fingerprint: String) async throws -> PinnedCA {
        guard let want = PinnedCA.normalize(fingerprint: fingerprint) else { throw TrustError.badFingerprint(fingerprint) }
        guard server.scheme == "https" else { throw TrustError.insecure(server.absoluteString) }
        let open = PinnedSession(unverifiedForCAFetch: ())
        defer { open.invalidate() }
        var r = URLRequest(url: server.appendingPathComponent("ca.crt"), timeoutInterval: 15)
        r.setValue("application/x-pem-file", forHTTPHeaderField: "Accept")
        let (d, h) = try await open.data(for: r)
        guard h.statusCode == 200, d.count <= 64 << 10 else { throw TrustError.badCA("GET /ca.crt: HTTP \(h.statusCode)") }
        let ca = try PinnedCA(pem: d)
        guard ca.fingerprint == want else { throw TrustError.fingerprintMismatch(got: ca.fingerprint, want: want) }
        let pinned = PinnedSession(ca: ca)
        defer { pinned.invalidate() }
        do {
            _ = try await pinned.data(for: URLRequest(url: server.appendingPathComponent("healthz"), timeoutInterval: 15))
        } catch {
            throw TrustError.notFromThatCA(error.localizedDescription)
        }
        return ca
    }
}
