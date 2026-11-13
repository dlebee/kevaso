import Foundation
import Network

/// A small HTTP/1.1 server bound to 127.0.0.1 on a free port: one request per connection, bodies by
/// Content-Length only, a size cap. The sign-in uses it for the browser's redirect and to relay the
/// sign-in pages; the tests also run it over TLS as a fake control plane.
public final class LoopbackHTTP: @unchecked Sendable {
    public struct Request: Sendable {
        public var method: String
        public var target: String            // path and query, as sent
        public var headers: [String: String] // lowercased names
        public var body: Data
        public var path: String { String(target.split(separator: "?", maxSplits: 1).first ?? "") }
        public var query: [String: String] {
            var out: [String: String] = [:]
            for i in URLComponents(string: "http://x" + target)?.queryItems ?? [] where out[i.name] == nil { out[i.name] = i.value ?? "" }
            return out
        }
        /// An application/x-www-form-urlencoded body.
        public var form: [String: String] {
            var c = URLComponents()
            c.percentEncodedQuery = String(decoding: body, as: UTF8.self).replacingOccurrences(of: "+", with: "%20")
            var out: [String: String] = [:]
            for i in c.queryItems ?? [] where out[i.name] == nil { out[i.name] = i.value ?? "" }
            return out
        }
    }

    public struct Response: Sendable {
        public var status: Int
        public var headers: [(String, String)]
        public var body: Data
        public init(status: Int = 200, headers: [(String, String)] = [], body: Data = Data()) {
            self.status = status
            self.headers = headers
            self.body = body
        }
        public static func text(_ status: Int, _ s: String, type: String = "text/plain; charset=utf-8") -> Response {
            Response(status: status, headers: [("Content-Type", type)], body: Data(s.utf8))
        }
        public static func json(_ status: Int, _ obj: Any) -> Response {
            Response(status: status, headers: [("Content-Type", "application/json"), ("Cache-Control", "no-store")],
                     body: (try? JSONSerialization.data(withJSONObject: obj)) ?? Data())
        }
    }

    public typealias Handler = @Sendable (Request) async -> Response

    public static let maxRequest = 256 << 10
    private let listener: NWListener
    private let queue = DispatchQueue(label: "kevaso.loopback-http")
    private let handler: Handler
    public private(set) var port: UInt16 = 0

    /// Plain HTTP on 127.0.0.1.
    public convenience init(handler: @escaping Handler) throws {
        try self.init(parameters: NWParameters(tls: nil, tcp: NWProtocolTCP.Options()), handler: handler)
    }

    init(parameters: NWParameters, handler: @escaping Handler) throws {
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        parameters.allowLocalEndpointReuse = true
        listener = try NWListener(using: parameters)
        self.handler = handler
    }

    /// Starts listening; returns the port.
    @discardableResult
    public func start() async throws -> UInt16 {
        let l = listener
        let q = queue
        let p: UInt16 = try await withCheckedThrowingContinuation { cont in
            let once = OnceBox()
            l.stateUpdateHandler = { s in
                switch s {
                case .ready: if once.take() { cont.resume(returning: l.port?.rawValue ?? 0) }
                case .failed(let e): if once.take() { cont.resume(throwing: e) }
                case .cancelled: if once.take() { cont.resume(throwing: CancellationError()) }
                default: break
                }
            }
            l.newConnectionHandler = { [weak self] c in self?.serve(c) }
            l.start(queue: q)
        }
        port = p
        return p
    }

    public func stop() { listener.cancel() }

    private func serve(_ c: NWConnection) {
        // Loopback only: a connection from anywhere else is dropped (the bind already ensures it).
        if case .hostPort(let host, _) = c.endpoint, "\(host)" != "127.0.0.1" && "\(host)" != "::1" { c.cancel(); return }
        c.start(queue: queue)
        receive(c, Data())
    }

    private func receive(_ c: NWConnection, _ buf: Data) {
        c.receive(minimumIncompleteLength: 1, maximumLength: 64 << 10) { [weak self] d, _, done, err in
            guard let self else { c.cancel(); return }
            var buf = buf
            if let d { buf.append(d) }
            if err != nil || buf.count > Self.maxRequest { c.cancel(); return }
            switch Self.parse(buf) {
            case .incomplete:
                if done { c.cancel() } else { self.receive(c, buf) }
            case .bad:
                self.send(c, .text(400, "bad request"))
            case .ok(let r):
                let h = self.handler
                Task { self.send(c, await h(r)) }
            }
        }
    }

    private func send(_ c: NWConnection, _ r: Response) {
        var head = "HTTP/1.1 \(r.status) \(HTTPURLResponse.localizedString(forStatusCode: r.status).capitalized)\r\n"
        for (k, v) in r.headers where !k.contains("\r") && !k.contains("\n") && !v.contains("\r") && !v.contains("\n") {
            head += "\(k): \(v)\r\n"
        }
        head += "Content-Length: \(r.body.count)\r\nConnection: close\r\n\r\n"
        c.send(content: Data(head.utf8) + r.body, contentContext: .finalMessage, isComplete: true,
               completion: .contentProcessed { _ in c.cancel() })
    }

    enum Parsed { case incomplete, bad, ok(Request) }

    static func parse(_ buf: Data) -> Parsed {
        guard let end = buf.range(of: Data("\r\n\r\n".utf8)) else { return .incomplete }
        let lines = String(decoding: buf[..<end.lowerBound], as: UTF8.self).components(separatedBy: "\r\n")
        let first = lines[0].split(separator: " ")
        guard first.count == 3, first[2].hasPrefix("HTTP/1."), first[1].hasPrefix("/") else { return .bad }
        var headers: [String: String] = [:]
        for l in lines.dropFirst() {
            guard let i = l.firstIndex(of: ":") else { return .bad }
            headers[l[..<i].lowercased()] = l[l.index(after: i)...].trimmingCharacters(in: .whitespaces)
        }
        if headers["transfer-encoding"] != nil { return .bad }
        let n = Int(headers["content-length"] ?? "0") ?? -1
        guard n >= 0, n <= maxRequest else { return .bad }
        let body = buf[end.upperBound...]
        if body.count < n { return .incomplete }
        return .ok(Request(method: String(first[0]), target: String(first[1]), headers: headers, body: Data(body.prefix(n))))
    }
}

/// True the first time only.
final class OnceBox: @unchecked Sendable {
    private var done = false
    private let lock = NSLock()
    func take() -> Bool { lock.lock(); defer { lock.unlock() }; if done { return false }; done = true; return true }
}
