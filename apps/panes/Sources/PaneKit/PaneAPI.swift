import Foundation
import Security

/// Where the app talks to: the control plane's URL, the CA pinned for it (the only one trusted), a
/// source of bearer tokens, and a namespace. The app builds one per signed-in cluster; CI can set
/// KVO_SERVER, KVO_CA_FILE, KVO_TOKEN and KVO_NAMESPACE instead (KVO_TOKEN overrides any sign-in).
public struct ServerConfig: Sendable {
    public var server: URL
    public var ca: PinnedCA?
    public var tokens: AccessTokens?
    public var namespace: String

    public init(server: URL, ca: PinnedCA? = nil, tokens: AccessTokens? = nil, namespace: String = "default") {
        self.server = server
        self.ca = ca
        self.tokens = tokens
        self.namespace = namespace
    }

    /// KVO_SERVER and KVO_CA_FILE (both needed for https), KVO_TOKEN, KVO_NAMESPACE.
    public static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) throws -> ServerConfig? {
        guard let s = env["KVO_SERVER"], !s.isEmpty, let u = URL(string: s) else { return nil }
        let ca = try env["KVO_CA_FILE"].flatMap { $0.isEmpty ? nil : $0 }.map { try PinnedCA(file: $0) }
        return ServerConfig(server: u, ca: ca, tokens: env["KVO_TOKEN"].flatMap { $0.isEmpty ? nil : StaticToken($0) },
                            namespace: env["KVO_NAMESPACE"].flatMap { $0.isEmpty ? nil : $0 } ?? "default")
    }

    /// The KVO_TOKEN override alone (a token for CI on top of a signed-in cluster's server and CA).
    public static func tokenOverride(_ env: [String: String] = ProcessInfo.processInfo.environment) -> AccessTokens? {
        env["KVO_TOKEN"].flatMap { $0.isEmpty ? nil : StaticToken($0) }
    }
}

public enum APIError: Error, Equatable, CustomStringConvertible {
    case http(Int, String)
    case gone // a watch's resourceVersion is too old: list again

    public var description: String {
        switch self {
        case .http(let c, let m): return "HTTP \(c): \(m)"
        case .gone: return "watch expired"
        }
    }
}

/// What the client knows about a silo, read from the Silo object with the same token (never from
/// anything the silo reports): where it runs, and whether it is marked untrusted.
public struct SiloInfo: Equatable, Sendable {
    public var host: String?
    public var trust: SiloTrust
    public init(host: String?, trust: SiloTrust) {
        self.host = host
        self.trust = trust
    }
}

/// Whether a silo is trusted. The label `kevaso.com/trust: untrusted` on the Silo object marks it
/// untrusted; a silo the client couldn't read is `unknown` and drawn like an untrusted one.
public enum SiloTrust: String, Equatable, Sendable {
    case trusted, untrusted, unknown
    public static let label = "kevaso.com/trust"

    public static func from(labels: [String: String]?) -> SiloTrust {
        labels?[label] == "untrusted" ? .untrusted : .trusted
    }
}

/// A watch event on panes.
public enum PaneEvent: Equatable, Sendable {
    case upsert(Pane)
    case deleted(Pane)
}

/// The control plane's pane API: list, watch, get a silo's host and trust, download a bundle. Every
/// request goes through a session pinned to the cluster's CA.
public final class PaneAPI: @unchecked Sendable {
    public let config: ServerConfig
    let http: PinnedSession

    public init(_ config: ServerConfig) throws {
        let http = PinnedSession(ca: config.ca)
        try http.check(config.server)
        self.config = config
        self.http = http
    }

    /// Ends every request.
    public func invalidate() { http.invalidate() }

    func request(_ path: String, query: [URLQueryItem] = [], timeout: TimeInterval = 30) async throws -> URLRequest {
        var c = URLComponents(url: config.server, resolvingAgainstBaseURL: false)!
        c.percentEncodedPath = (c.percentEncodedPath.hasSuffix("/") ? String(c.percentEncodedPath.dropLast()) : c.percentEncodedPath) + path
        if !query.isEmpty { c.queryItems = query }
        var r = URLRequest(url: c.url!, timeoutInterval: timeout)
        if let t = config.tokens { r.setValue("Bearer " + (try await t.token()), forHTTPHeaderField: "Authorization") }
        r.setValue("application/json", forHTTPHeaderField: "Accept")
        return r
    }

    static func seg(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-._~"))) ?? s
    }

    var panesPath: String { "/apis/kevaso/v1/namespaces/\(Self.seg(config.namespace))/panes" }

    /// GET a path; a 401 drops the cached access token and tries once more with a fresh one.
    func get(_ path: String, query: [URLQueryItem] = [], limit: Int = 16 << 20) async throws -> (Data, HTTPURLResponse) {
        var (d, h) = try await http.data(for: try await request(path, query: query))
        if h.statusCode == 401, let t = config.tokens {
            await t.invalidate()
            (d, h) = try await http.data(for: try await request(path, query: query))
        }
        guard h.statusCode == 200 else {
            let msg = (try? JSONSerialization.jsonObject(with: d) as? [String: Any])?["message"] as? String
            throw APIError.http(h.statusCode, msg ?? HTTPURLResponse.localizedString(forStatusCode: h.statusCode))
        }
        guard d.count <= limit else { throw APIError.http(h.statusCode, "response too large") }
        return (d, h)
    }

    /// The panes in the namespace, and the resourceVersion to watch from.
    public func list() async throws -> ([Pane], String) {
        let (d, _) = try await get(panesPath)
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
        return AsyncThrowingStream { cont in
            let task = Task {
                do {
                    let r = try await self.request(self.panesPath, query: q, timeout: 3600)
                    let (bytes, h) = try await self.http.bytes(for: r)
                    if h.statusCode == 401 { await self.config.tokens?.invalidate() }
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

    /// A silo's host (status.host) and trust (its labels), for the identity the client draws.
    public func silo(_ silo: String) async throws -> SiloInfo {
        let (d, _) = try await get("/apis/kevaso/v1/namespaces/\(Self.seg(config.namespace))/silos/\(Self.seg(silo))")
        struct S: Decodable {
            struct M: Decodable { var labels: [String: String]? }
            struct St: Decodable { var host: String? }
            var metadata: M?
            var status: St?
        }
        let s = try JSONDecoder.kevaso.decode(S.self, from: d)
        return SiloInfo(host: s.status?.host, trust: SiloTrust.from(labels: s.metadata?.labels))
    }

    /// The namespaces this token can list (empty when it may not list them).
    public func namespaces() async throws -> [String] {
        let (d, _) = try await get("/apis/kevaso/v1/namespaces")
        struct L: Decodable { struct I: Decodable { struct M: Decodable { var name: String }; var metadata: M }; var items: [I]? }
        return (try JSONDecoder.kevaso.decode(L.self, from: d).items ?? []).map(\.metadata.name).sorted()
    }

    /// Downloads an HTML pane's bundle and checks it against the digest the pane names. Bytes that
    /// don't match are refused here and never reach a web view.
    public func bundle(for pane: Pane) async throws -> Data {
        guard pane.isHTML, let digest = pane.spec.bundle else { throw PaneBundle.Failure.badDigest(pane.spec.bundle ?? "") }
        let (d, _) = try await get("\(panesPath)/\(Self.seg(pane.metadata.name))/bundle", limit: PaneBundle.maxBytes)
        try PaneBundle.verify(d, expected: digest)
        return d
    }
}
