import Foundation

/// Started by kvo as its `panes` plugin (`kvo panes`, core ADR 0008): the cluster is kvo's current
/// context, handed over in the environment, and access tokens come from `kvo plugin token` when
/// needed. The app keeps no credential of its own then: no sign-in, no keychain item.
public struct KvoPluginContext: Equatable, Sendable {
    /// The kvo context ("" for a dev server without sign-in).
    public var context: String
    public var server: URL
    /// The cluster CA to pin (PEM file); nil only for plain-http dev servers.
    public var caFile: String?
    public var namespace: String
    /// kvo's own executable, to run `plugin token`.
    public var kvo: String

    /// KVO_PLUGIN_SERVER, KVO_PLUGIN_KVO, KVO_PLUGIN_CA_FILE, KVO_PLUGIN_CONTEXT, KVO_PLUGIN_NAMESPACE;
    /// nil unless kvo started the app.
    public static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) -> KvoPluginContext? {
        func v(_ k: String) -> String? { env[k].flatMap { $0.isEmpty ? nil : $0 } }
        guard let s = v("KVO_PLUGIN_SERVER"), let u = URL(string: s), u.host != nil, let kvo = v("KVO_PLUGIN_KVO") else { return nil }
        return KvoPluginContext(context: v("KVO_PLUGIN_CONTEXT") ?? "", server: u, caFile: v("KVO_PLUGIN_CA_FILE"),
                                namespace: v("KVO_PLUGIN_NAMESPACE") ?? "default", kvo: kvo)
    }

    /// Where to connect, and kvo as the source of tokens. https needs the CA (system roots are never used).
    public func serverConfig() throws -> ServerConfig {
        let ca = try caFile.map { try PinnedCA(file: $0) }
        if server.scheme == "https", ca == nil { throw TrustError.insecure(server.absoluteString) }
        return ServerConfig(server: server, ca: ca, tokens: KvoPluginTokens(kvo: kvo), namespace: namespace)
    }
}

public enum KvoPluginError: Error, Equatable, CustomStringConvertible {
    case token(String)
    public var description: String {
        switch self {
        case .token(let m): return "kvo plugin token: \(m)"
        }
    }
}

/// Short-lived access tokens from `kvo plugin token`, which prints {"token": "…", "expiresAt": "…"}.
/// One is reused until 30 s before it expires (60 s when kvo doesn't say); concurrent callers share
/// one run of kvo; a 401 drops it. The refresh token stays with kvo.
public actor KvoPluginTokens: AccessTokens {
    struct Answer: Decodable {
        var token: String
        var expiresAt: Date?
    }

    let fetch: @Sendable () async throws -> Data
    let now: @Sendable () -> Date
    private var cached: (token: String, until: Date)?
    private var running: Task<String, Error>?

    public init(kvo: String, now: @escaping @Sendable () -> Date = { Date() }) {
        self.init(fetch: { try await KvoPluginTokens.run(kvo) }, now: now)
    }

    init(fetch: @escaping @Sendable () async throws -> Data, now: @escaping @Sendable () -> Date) {
        self.fetch = fetch
        self.now = now
    }

    public func token() async throws -> String {
        if let c = cached, c.until > now() { return c.token }
        if let r = running { return try await r.value }
        let task = Task { () throws -> String in
            let a = try Self.decode(try await fetch())
            let until = a.expiresAt.map { $0.addingTimeInterval(-30) } ?? now().addingTimeInterval(60)
            cached = (a.token, until)
            return a.token
        }
        running = task
        defer { running = nil }
        return try await task.value
    }

    public func invalidate() async { cached = nil }

    static func decode(_ d: Data) throws -> Answer {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .custom { decoder in
            let s = try decoder.singleValueContainer().decode(String.self)
            let f = ISO8601DateFormatter()
            f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = f.date(from: s) { return date }
            f.formatOptions = [.withInternetDateTime]
            if let date = f.date(from: s) { return date }
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "bad time \(s)"))
        }
        do { return try dec.decode(Answer.self, from: d) } catch { throw KvoPluginError.token("unreadable answer") }
    }

    /// Runs `kvo plugin token` (with this process's environment, so kvo sees KVO_PLUGIN_CONTEXT).
    static func run(_ kvo: String) async throws -> Data {
        try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global().async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: kvo)
                p.arguments = ["plugin", "token"]
                let out = Pipe(), err = Pipe()
                p.standardOutput = out
                p.standardError = err
                p.standardInput = FileHandle.nullDevice
                do { try p.run() } catch {
                    cont.resume(throwing: KvoPluginError.token("can't run \(kvo): \(error.localizedDescription)"))
                    return
                }
                let data = out.fileHandleForReading.readDataToEndOfFile()
                let msg = err.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                if p.terminationStatus != 0 {
                    let text = String(decoding: msg.prefix(500), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                    cont.resume(throwing: KvoPluginError.token(text.isEmpty ? "exit \(p.terminationStatus)" : text))
                } else {
                    cont.resume(returning: data)
                }
            }
        }
    }
}
