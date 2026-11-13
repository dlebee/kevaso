import Foundation

// The Pane object as the control plane serves it (core: api/v1/panes.go). Everything in `spec` comes
// from the silo and is untrusted: text is shown as plain text only, `data` is handed to the sealed view
// as a value, and the identity (rim, silo, namespace, host) is never taken from it.

public struct Pane: Decodable, Identifiable, Equatable, Sendable {
    public struct Metadata: Decodable, Equatable, Sendable {
        public var name: String
        public var namespace: String
        public var uid: String?
        public var resourceVersion: String?
    }
    public struct Field: Decodable, Equatable, Sendable {
        public var label: String
        public var value: String
    }
    public struct Spec: Decodable, Equatable, Sendable {
        public var silo: String
        public var siloUID: String
        public var pane: String
        public var kind: String
        public var title: String?
        public var state: String?
        public var progress: Double?
        public var message: String?
        public var fields: [Field]?
        public var bundle: String?
        /// The raw JSON `data` of an HTML pane, kept as bytes: decoded only right before it is pushed.
        public var data: JSONBytes?
        public var ttl: String?
    }
    public struct Status: Decodable, Equatable, Sendable {
        public var updatedAt: Date?
        public var updates: Int64?
    }

    public var metadata: Metadata
    public var spec: Spec
    public var status: Status?

    public var id: String { metadata.namespace + "/" + metadata.name }
    public var isHTML: Bool { spec.kind == "html" }

    /// Past its TTL without an update (same rule as the server's Pane.Stale).
    public func isStale(now: Date = Date()) -> Bool {
        guard let ttl = spec.ttl.flatMap(GoDuration.parse), ttl > 0, let at = status?.updatedAt else { return false }
        return now.timeIntervalSince(at) > ttl
    }

    public static func decode(_ data: Data) throws -> Pane {
        try JSONDecoder.kevaso.decode(Pane.self, from: data)
    }
}

/// A JSON value kept as its bytes.
public struct JSONBytes: Decodable, Equatable, Sendable {
    public var raw: Data
    public init(raw: Data) { self.raw = raw }
    public init(from decoder: Decoder) throws {
        // Re-encode whatever JSON value is there: we only ever need it as a value for the pane.
        let v = try decoder.singleValueContainer().decode(AnyJSON.self)
        raw = try JSONSerialization.data(withJSONObject: v.value, options: [.fragmentsAllowed, .sortedKeys])
    }
    /// The value as Foundation objects (String, NSNumber, NSNull, [Any], [String: Any]): the only form
    /// WebKit accepts as a call argument.
    public func value() throws -> Any {
        try JSONSerialization.jsonObject(with: raw, options: [.fragmentsAllowed])
    }
}

struct AnyJSON: Decodable {
    let value: Any
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { value = NSNull() }
        else if let b = try? c.decode(Bool.self) { value = b }
        else if let i = try? c.decode(Int64.self) { value = NSNumber(value: i) }
        else if let n = try? c.decode(Decimal.self) { value = NSDecimalNumber(decimal: n) } // keeps 0.9 as 0.9
        else if let s = try? c.decode(String.self) { value = s }
        else if let a = try? c.decode([AnyJSON].self) { value = a.map(\.value) }
        else { value = try c.decode([String: AnyJSON].self).mapValues(\.value) }
    }
}

extension JSONDecoder {
    static var kevaso: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { dec in
            let s = try dec.singleValueContainer().decode(String.self)
            let f = ISO8601DateFormatter()
            f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let d = f.date(from: s) { return d }
            f.formatOptions = [.withInternetDateTime]
            if let d = f.date(from: s) { return d }
            // Go writes up to nanoseconds; ISO8601DateFormatter takes milliseconds at most.
            if let dot = s.firstIndex(of: "."), let end = s[dot...].firstIndex(where: { $0 == "Z" || $0 == "+" || $0 == "-" }) {
                let frac = s[s.index(after: dot)..<end].prefix(3)
                f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                if let d = f.date(from: String(s[..<dot]) + "." + frac + String(s[end...])) { return d }
            }
            throw DecodingError.dataCorrupted(.init(codingPath: dec.codingPath, debugDescription: "bad time \(s)"))
        }
        return d
    }
}

/// Go's time.ParseDuration, for the units a pane TTL uses (h, m, s, ms, us, ns; may be combined).
public enum GoDuration {
    public static func parse(_ s: String) -> TimeInterval? {
        var rest = Substring(s), total = 0.0
        guard !rest.isEmpty else { return nil }
        let units: [(String, Double)] = [("ns", 1e-9), ("us", 1e-6), ("µs", 1e-6), ("ms", 1e-3), ("h", 3600), ("m", 60), ("s", 1)]
        while !rest.isEmpty {
            let num = rest.prefix { $0.isNumber || $0 == "." }
            guard !num.isEmpty, let v = Double(num) else { return nil }
            rest = rest.dropFirst(num.count)
            guard let (u, mul) = units.first(where: { rest.hasPrefix($0.0) }) else { return nil }
            rest = rest.dropFirst(u.count)
            total += v * mul
        }
        return total
    }
}
