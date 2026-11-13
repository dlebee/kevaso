import Foundation
import Security

/// Where the app talks to: the control plane's URL, the CA that signs its certificate, and a bearer
/// token. Read from the environment (KVO_SERVER, KVO_CA_FILE, KVO_TOKEN, KVO_NAMESPACE) or the app's
/// settings. No keychain integration yet.
public struct ServerConfig: Equatable, Sendable {
    public var server: URL
    public var caFile: String?
    public var token: String?
    public var namespace: String

    public init(server: URL, caFile: String? = nil, token: String? = nil, namespace: String = "default") {
        self.server = server
        self.caFile = caFile
        self.token = token
        self.namespace = namespace
    }

    public static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) -> ServerConfig? {
        guard let s = env["KVO_SERVER"], let u = URL(string: s) else { return nil }
        return ServerConfig(server: u, caFile: env["KVO_CA_FILE"].flatMap { $0.isEmpty ? nil : $0 },
                            token: env["KVO_TOKEN"].flatMap { $0.isEmpty ? nil : $0 },
                            namespace: env["KVO_NAMESPACE"].flatMap { $0.isEmpty ? nil : $0 } ?? "default")
    }
}

public enum APIError: Error, Equatable, CustomStringConvertible {
    case insecure(String)
    case badCA(String)
    case http(Int, String)
    case gone // a watch's resourceVersion is too old: list again

    public var description: String {
        switch self {
        case .insecure(let s): return "refusing \(s): only https (plain http only to loopback, for tests)"
        case .badCA(let s): return "CA file: \(s)"
        case .http(let c, let m): return "HTTP \(c): \(m)"
        case .gone: return "watch expired"
        }
    }
}

/// A watch event on panes.
public enum PaneEvent: Equatable, Sendable {
    case upsert(Pane)
    case deleted(Pane)
}

/// The control plane's pane API: list, watch, get a silo's host, download a bundle.
public final class PaneAPI: NSObject, URLSessionDelegate, @unchecked Sendable {
    public let config: ServerConfig
    private var anchors: [SecCertificate] = []
    private lazy var session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.urlCache = nil
        c.httpCookieStorage = nil
        c.timeoutIntervalForRequest = 3600 // watches stay open; plain calls set their own timeout
        return URLSession(configuration: c, delegate: self, delegateQueue: nil)
    }()

    public init(_ config: ServerConfig) throws {
        let host = config.server.host ?? ""
        switch config.server.scheme {
        case "https": break
        case "http" where ["127.0.0.1", "localhost", "::1"].contains(host): break
        default: throw APIError.insecure(config.server.absoluteString)
        }
        let anchors = try config.caFile.map { try Self.loadCertificates(path: $0) } ?? []
        self.config = config
        self.anchors = anchors
        super.init()
    }

    /// Ends every request; the session holds its delegate (this object) until then.
    public func invalidate() { session.invalidateAndCancel() }

    /// Certificates from a PEM (or DER) file.
    public static func loadCertificates(path: String) throws -> [SecCertificate] {
        guard let raw = FileManager.default.contents(atPath: path) else { throw APIError.badCA("can't read \(path)") }
        let text = String(decoding: raw, as: UTF8.self)
        var ders: [Data] = []
        if text.contains("-----BEGIN CERTIFICATE-----") {
            for block in text.components(separatedBy: "-----BEGIN CERTIFICATE-----").dropFirst() {
                guard let body = block.components(separatedBy: "-----END CERTIFICATE-----").first,
                      let d = Data(base64Encoded: body.filter { !$0.isWhitespace }) else { throw APIError.badCA("bad PEM block") }
                ders.append(d)
            }
        } else {
            ders = [raw]
        }
        let certs = ders.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard !certs.isEmpty, certs.count == ders.count else { throw APIError.badCA("no certificate in \(path)") }
        return certs
    }

    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                           completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil); return
        }
        guard !anchors.isEmpty else { completionHandler(.performDefaultHandling, nil); return }
        // Trust only the configured CA (hostname checking stays on: the default SSL policy).
        SecTrustSetAnchorCertificates(trust, anchors as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        if SecTrustEvaluateWithError(trust, nil) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    func request(_ path: String, query: [URLQueryItem] = [], timeout: TimeInterval = 30) -> URLRequest {
        var c = URLComponents(url: config.server, resolvingAgainstBaseURL: false)!
        c.percentEncodedPath = (c.percentEncodedPath.hasSuffix("/") ? String(c.percentEncodedPath.dropLast()) : c.percentEncodedPath) + path
        if !query.isEmpty { c.queryItems = query }
        var r = URLRequest(url: c.url!, timeoutInterval: timeout)
        if let t = config.token { r.setValue("Bearer " + t, forHTTPHeaderField: "Authorization") }
        r.setValue("application/json", forHTTPHeaderField: "Accept")
        return r
    }

    static func seg(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-._~"))) ?? s
    }

    var panesPath: String { "/apis/kevaso/v1/namespaces/\(Self.seg(config.namespace))/panes" }

    func data(_ r: URLRequest, limit: Int = 16 << 20) async throws -> (Data, HTTPURLResponse) {
        let (d, resp) = try await session.data(for: r)
        guard let h = resp as? HTTPURLResponse else { throw APIError.http(0, "no response") }
        guard h.statusCode == 200 else {
            let msg = (try? JSONSerialization.jsonObject(with: d) as? [String: Any])?["message"] as? String
            throw APIError.http(h.statusCode, msg ?? HTTPURLResponse.localizedString(forStatusCode: h.statusCode))
        }
        guard d.count <= limit else { throw APIError.http(h.statusCode, "response too large") }
        return (d, h)
    }

    /// The panes in the namespace, and the resourceVersion to watch from.
    public func list() async throws -> ([Pane], String) {
        let (d, _) = try await data(request(panesPath))
        struct L: Decodable {
            struct M: Decodable { var resourceVersion: String? }
            var items: [Pane]?
            var metadata: M?
        }
        let l = try JSONDecoder.kevaso.decode(L.self, from: d)
        return (l.items ?? [], l.metadata?.resourceVersion ?? "")
    }

    /// Streams pane events after `resourceVersion` until the server ends the stream (then list again).
    public func watch(from resourceVersion: String) -> AsyncThrowingStream<PaneEvent, Error> {
        var q = [URLQueryItem(name: "watch", value: "true")]
        if !resourceVersion.isEmpty { q.append(URLQueryItem(name: "resourceVersion", value: resourceVersion)) }
        let r = request(panesPath, query: q, timeout: 3600)
        return AsyncThrowingStream { cont in
            let task = Task {
                do {
                    let (bytes, resp) = try await self.session.bytes(for: r)
                    guard let h = resp as? HTTPURLResponse else { throw APIError.http(0, "no response") }
                    if h.statusCode == 410 { throw APIError.gone }
                    guard h.statusCode == 200 else { throw APIError.http(h.statusCode, "watch") }
                    for try await line in bytes.lines {
                        guard line.utf8.count <= 8 << 20, let d = line.data(using: .utf8) else { break }
                        struct E: Decodable { var type: String }
                        struct O: Decodable { var object: Pane }
                        let t = try JSONDecoder.kevaso.decode(E.self, from: d).type
                        if t == "ERROR" { throw APIError.gone }
                        guard let p = try? JSONDecoder.kevaso.decode(O.self, from: d).object else { continue }
                        cont.yield(t == "DELETED" ? .deleted(p) : .upsert(p))
                    }
                    cont.finish()
                } catch {
                    cont.finish(throwing: error)
                }
            }
            cont.onTermination = { _ in task.cancel() }
        }
    }

    /// The host a silo runs on (status.host), for the identity the client draws.
    public func siloHost(_ silo: String) async throws -> String? {
        let (d, _) = try await data(request("/apis/kevaso/v1/namespaces/\(Self.seg(config.namespace))/silos/\(Self.seg(silo))"))
        struct S: Decodable { struct St: Decodable { var host: String? }; var status: St? }
        return try JSONDecoder.kevaso.decode(S.self, from: d).status?.host
    }

    /// Downloads an HTML pane's bundle and checks it against the digest the pane names. Bytes that
    /// don't match are refused here and never reach a web view.
    public func bundle(for pane: Pane) async throws -> Data {
        guard pane.isHTML, let digest = pane.spec.bundle else { throw PaneBundle.Failure.badDigest(pane.spec.bundle ?? "") }
        let (d, _) = try await data(request("\(panesPath)/\(Self.seg(pane.metadata.name))/bundle"), limit: PaneBundle.maxBytes)
        try PaneBundle.verify(d, expected: digest)
        return d
    }
}
