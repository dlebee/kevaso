import CryptoKit
import Foundation

/// An HTML pane's bundle: opaque bytes on the server, checked against their digest here before
/// anything else, then laid out in a fresh folder of the pane's own.
///
/// Formats (the server never looks inside): a POSIX tar archive (ustar) of regular files and folders,
/// which must hold `index.html`; anything else is taken as the pane's single `index.html`.
/// Archive entries that are links, devices, absolute, contain `..`, or exceed the limits are refused.
public enum PaneBundle {
    public enum Failure: Error, Equatable {
        case digestMismatch(expected: String, got: String)
        case badDigest(String)
        case tooLarge(Int)
        case badArchive(String)
    }

    /// The server's limit (core internal/panes Defaults.MaxBundle) is 512 KiB.
    public static let maxBytes = 512 << 10
    public static let maxFiles = 256
    public static let maxUnpacked = 8 << 20

    public static func digest(_ b: Data) -> String {
        "sha256:" + SHA256.hash(data: b).map { String(format: "%02x", $0) }.joined()
    }

    /// Refuses bytes that aren't what `expected` names.
    public static func verify(_ b: Data, expected: String) throws {
        guard expected.range(of: "^sha256:[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw Failure.badDigest(expected)
        }
        guard b.count <= maxBytes else { throw Failure.tooLarge(b.count) }
        let got = digest(b)
        guard got == expected else { throw Failure.digestMismatch(expected: expected, got: got) }
    }

    /// The files of a verified bundle: relative path → contents.
    public static func files(_ b: Data) throws -> [String: Data] {
        isTar(b) ? try untar(b) : ["index.html": b]
    }

    /// Writes a verified bundle into a new folder under `parent` and returns it. Each opened pane gets
    /// its own folder, so no two panes ever share files.
    public static func materialize(_ b: Data, expected: String, under parent: URL) throws -> URL {
        try verify(b, expected: expected)
        let fs = try files(b)
        let dir = parent.appendingPathComponent(UUID().uuidString.lowercased(), isDirectory: true)
        let fm = FileManager.default
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        for (rel, data) in fs {
            let f = dir.appendingPathComponent(rel)
            try fm.createDirectory(at: f.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: f, options: .withoutOverwriting)
        }
        return dir
    }

    static func isTar(_ b: Data) -> Bool {
        b.count >= 512 && b.subdata(in: b.startIndex + 257..<b.startIndex + 262) == Data("ustar".utf8)
    }

    static func untar(_ b: Data) throws -> [String: Data] {
        let bytes = [UInt8](b)
        var out: [String: Data] = [:]
        var off = 0, total = 0
        func str(_ r: Range<Int>) -> String {
            let s = bytes[r].prefix { $0 != 0 }
            return String(decoding: s, as: UTF8.self)
        }
        while off + 512 <= bytes.count {
            let h = Array(bytes[off..<off + 512])
            if h.allSatisfy({ $0 == 0 }) { break }
            // checksum: sum of the header with the checksum field taken as spaces
            let sum = h.enumerated().reduce(0) { $0 + ((148..<156).contains($1.offset) ? 32 : Int($1.element)) }
            guard let stored = Int(str(off + 148..<off + 156).trimmingCharacters(in: .whitespaces), radix: 8), stored == sum else {
                throw Failure.badArchive("bad header checksum")
            }
            var name = str(off..<off + 100)
            let prefix = str(off + 345..<off + 500)
            if !prefix.isEmpty { name = prefix + "/" + name }
            guard let size = Int(str(off + 124..<off + 136).trimmingCharacters(in: .whitespaces), radix: 8), size >= 0 else {
                throw Failure.badArchive("bad size")
            }
            let type = h[156]
            let start = off + 512
            guard start + size <= bytes.count else { throw Failure.badArchive("truncated") }
            off = start + (size + 511) / 512 * 512
            if name.hasPrefix("./") { name.removeFirst(2) }
            switch type {
            case UInt8(ascii: "5"):
                let d = name.hasSuffix("/") ? String(name.dropLast()) : name
                if d.isEmpty || d == "." { continue } // the archive's own root
                try check(d)
            case 0, UInt8(ascii: "0"):
                try check(name)
                total += size
                guard total <= maxUnpacked else { throw Failure.badArchive("unpacks to more than \(maxUnpacked) bytes") }
                guard out[name] == nil else { throw Failure.badArchive("duplicate \(name)") }
                out[name] = Data(bytes[start..<start + size])
                guard out.count <= maxFiles else { throw Failure.badArchive("more than \(maxFiles) files") }
            case UInt8(ascii: "x"), UInt8(ascii: "g"):
                continue // pax headers: ignored (a long name would then fail the plain name check)
            default:
                throw Failure.badArchive("entry \(name.prefix(60)) is not a regular file or folder (type \(type))")
            }
        }
        guard out["index.html"] != nil else { throw Failure.badArchive("no index.html") }
        return out
    }

    static func check(_ name: String) throws {
        let parts = name.split(separator: "/", omittingEmptySubsequences: false)
        guard !name.isEmpty, name.count < 256, !name.hasPrefix("/"), !name.contains("\\"),
              !parts.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }),
              name.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7f }) else {
            throw Failure.badArchive("bad path \(name.prefix(60))")
        }
    }
}
