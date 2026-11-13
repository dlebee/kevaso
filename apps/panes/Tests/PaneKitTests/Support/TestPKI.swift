import Foundation
import Network
import Security
import XCTest
@testable import PaneKit

/// A throwaway CA and server certificates, made with the system's openssl in a temp folder, shaped
/// like Kevaso's own (internal/pki): ECDSA P-256, a CA with keyCertSign, a server leaf with
/// digitalSignature, serverAuth, a SAN and a validity well under Apple's limit. Nothing is imported
/// into a keychain: the server identity is loaded into memory only (macOS 15+).
final class TestPKI {
    let dir: URL
    let caPEM: Data
    var ca: PinnedCA { try! PinnedCA(pem: caPEM) }

    init(name: String = "ca") throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("kevaso-pki-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n".utf8)
            .write(to: dir.appendingPathComponent("ca.cnf"))
        try Self.run(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key"], in: dir)
        try Self.run(["req", "-x509", "-new", "-key", "ca.key", "-subj", "/CN=test-\(name)", "-days", "30", "-sha256",
                 "-config", "ca.cnf", "-extensions", "v3_ca", "-out", "ca.crt"], in: dir)
        caPEM = try Data(contentsOf: dir.appendingPathComponent("ca.crt"))
    }

    deinit { try? FileManager.default.removeItem(at: dir) }

    @discardableResult
    func run(_ args: [String]) throws -> String { try Self.run(args, in: dir) }

    @discardableResult
    static func run(_ args: [String], in dir: URL) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p.arguments = args
        p.currentDirectoryURL = dir
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        try p.run()
        p.waitUntilExit()
        let s = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        guard p.terminationStatus == 0 else { throw NSError(domain: "openssl", code: Int(p.terminationStatus), userInfo: [NSLocalizedDescriptionKey: s]) }
        return s
    }

    /// A server identity for `san` (e.g. "IP:127.0.0.1" or "DNS:other.example"), signed by this CA.
    func serverIdentity(san: String = "IP:127.0.0.1") throws -> SecIdentity {
        let n = UUID().uuidString.prefix(6)
        try Data("keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=\(san)\n".utf8)
            .write(to: dir.appendingPathComponent("\(n).ext"))
        try run(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "\(n).key"])
        try run(["req", "-new", "-key", "\(n).key", "-subj", "/CN=kevaso-apiserver", "-out", "\(n).csr"])
        try run(["x509", "-req", "-in", "\(n).csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-set_serial", "\(Int.random(in: 1000...999999))",
                 "-days", "30", "-sha256", "-extfile", "\(n).ext", "-out", "\(n).crt"])
        try run(["pkcs12", "-export", "-inkey", "\(n).key", "-in", "\(n).crt", "-out", "\(n).p12", "-passout", "pass:test-only"])
        let p12 = try Data(contentsOf: dir.appendingPathComponent("\(n).p12"))
        guard #available(macOS 15, *) else { throw XCTSkip("in-memory PKCS#12 import needs macOS 15") }
        var items: CFArray?
        let s = SecPKCS12Import(p12 as CFData, [kSecImportExportPassphrase as String: "test-only",
                                                kSecImportToMemoryOnly as String: true] as CFDictionary, &items)
        guard s == errSecSuccess, let first = (items as? [[String: Any]])?.first,
              let id = first[kSecImportItemIdentity as String] else { throw NSError(domain: "pkcs12", code: Int(s)) }
        return id as! SecIdentity // swiftlint:disable:this force_cast
    }

    /// An HTTPS server on 127.0.0.1 presenting `identity`.
    static func tlsServer(_ identity: SecIdentity, handler: @escaping LoopbackHTTP.Handler) throws -> LoopbackHTTP {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, sec_identity_create(identity)!)
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        return try LoopbackHTTP(parameters: NWParameters(tls: tls, tcp: NWProtocolTCP.Options()), handler: handler)
    }
}
