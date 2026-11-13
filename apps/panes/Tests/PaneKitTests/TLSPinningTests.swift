import Foundation
import XCTest
@testable import PaneKit

/// Every request trusts only the CA pinned for its cluster: tested against local TLS servers with
/// throwaway CAs, including a wrong CA, a wrong host, a wrong fingerprint and no CA at all.
final class TLSPinningTests: XCTestCase {
    static let pki = Result { try TestPKI(name: "cluster") }
    static let other = Result { try TestPKI(name: "other") }
    var servers: [LoopbackHTTP] = []

    override func tearDown() {
        for s in servers { s.stop() }
        servers = []
    }

    /// A control plane: /ca.crt (public), /healthz, a redirect, and an API path that wants a token.
    func server(_ pki: TestPKI, san: String = "IP:127.0.0.1", serving ca: Data? = nil) async throws -> URL {
        let id = try pki.serverIdentity(san: san)
        let caPEM = ca ?? pki.caPEM
        let s = try TestPKI.tlsServer(id) { r in
            switch r.path {
            case "/ca.crt": return LoopbackHTTP.Response(status: 200, headers: [("Content-Type", "application/x-pem-file")], body: caPEM)
            case "/healthz": return .text(200, "ok\n")
            case "/elsewhere": return LoopbackHTTP.Response(status: 302, headers: [("Location", "https://example.com/")])
            case "/apis/kevaso/v1/namespaces":
                return r.headers["authorization"] == "Bearer t0k" ? .json(200, ["items": [["metadata": ["name": "team"]], ["metadata": ["name": "default"]]]])
                    : .json(401, ["message": "no token"])
            default: return .text(404, "no")
            }
        }
        servers.append(s)
        let port = try await s.start()
        return URL(string: "https://127.0.0.1:\(port)")!
    }

    func testFingerprintMatchesKvos() throws {
        let pki = try Self.pki.get()
        let der = try PinnedCA.ders(pki.caPEM)[0]
        // openssl's own SHA-256 of the DER, the same thing kvo's client.Fingerprint computes
        let out = try pki.run(["x509", "-in", "ca.crt", "-noout", "-fingerprint", "-sha256"])
        let hex = out.split(separator: "=").last!.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: ":", with: "").lowercased()
        XCTAssertEqual(PinnedCA.fingerprint(der: der), "sha256:" + hex)
        XCTAssertEqual(pki.ca.fingerprint, "sha256:" + hex)
        XCTAssertEqual(PinnedCA.normalize(fingerprint: "SHA256:" + hex.uppercased()), "sha256:" + hex)
        XCTAssertNil(PinnedCA.normalize(fingerprint: "sha1:abcd"))
        XCTAssertNil(PinnedCA.normalize(fingerprint: "sha256:" + hex.dropLast()))
    }

    func testFetchCAAcceptsOnlyTheGivenFingerprint() async throws {
        let pki = try Self.pki.get(), other = try Self.other.get()
        let u = try await server(pki)
        let ca = try await PinnedSession.fetchCA(server: u, fingerprint: pki.ca.fingerprint)
        XCTAssertEqual(ca.pem, pki.caPEM)
        do {
            _ = try await PinnedSession.fetchCA(server: u, fingerprint: other.ca.fingerprint)
            XCTFail("a CA with another fingerprint was accepted")
        } catch TrustError.fingerprintMismatch(let got, let want) {
            XCTAssertEqual(got, pki.ca.fingerprint)
            XCTAssertEqual(want, other.ca.fingerprint)
        }
        await XCTAssertThrowsAsync(try await PinnedSession.fetchCA(server: u, fingerprint: "not-one"))
    }

    /// A server that hands out a CA matching the fingerprint but holds a certificate from another
    /// CA: the second step (healthz over the pinned CA) refuses it.
    func testFetchCARefusesAServerWhoseCertificateIsntFromThatCA() async throws {
        let pki = try Self.pki.get(), other = try Self.other.get()
        let u = try await server(other, serving: pki.caPEM)
        do {
            _ = try await PinnedSession.fetchCA(server: u, fingerprint: pki.ca.fingerprint)
            XCTFail("accepted a server whose certificate isn't from the pinned CA")
        } catch TrustError.notFromThatCA {}
    }

    func testPinnedRequestsTrustOnlyThatCA() async throws {
        let pki = try Self.pki.get(), other = try Self.other.get()
        let u = try await server(pki)
        // the right CA: works
        let api = try PaneAPI(ServerConfig(server: u, ca: pki.ca, tokens: StaticToken("t0k")))
        let ns = try await api.namespaces()
        XCTAssertEqual(ns, ["default", "team"])
        api.invalidate()
        // another CA: refused at the TLS layer, nothing is sent
        let wrong = try PaneAPI(ServerConfig(server: u, ca: other.ca, tokens: StaticToken("t0k")))
        await XCTAssertThrowsAsync(try await wrong.namespaces())
        wrong.invalidate()
        // the system roots are never consulted: https with no CA is refused before any request
        XCTAssertThrowsError(try PaneAPI(ServerConfig(server: u)))
        XCTAssertThrowsError(try PaneAPI(ServerConfig(server: URL(string: "https://kevaso.example.com")!)))
        XCTAssertThrowsError(try PaneAPI(ServerConfig(server: URL(string: "http://kevaso.example.com")!, ca: pki.ca)))
    }

    func testHostnameIsChecked() async throws {
        let pki = try Self.pki.get()
        let u = try await server(pki, san: "DNS:other.example")
        let api = try PaneAPI(ServerConfig(server: u, ca: pki.ca, tokens: StaticToken("t0k")))
        await XCTAssertThrowsAsync(try await api.namespaces())
        api.invalidate()
    }

    func testRedirectsAreNotFollowed() async throws {
        let pki = try Self.pki.get()
        let u = try await server(pki)
        let s = PinnedSession(ca: pki.ca)
        let (_, h) = try await s.data(for: URLRequest(url: u.appendingPathComponent("elsewhere")))
        XCTAssertEqual(h.statusCode, 302)
        s.invalidate()
    }

    func testEnvironmentConfig() throws {
        let pki = try Self.pki.get()
        let caFile = pki.dir.appendingPathComponent("ca.crt").path
        let c = try ServerConfig.fromEnvironment(["KVO_SERVER": "https://cp.example:6443", "KVO_CA_FILE": caFile,
                                                  "KVO_NAMESPACE": "team", "KVO_TOKEN": "t"])
        XCTAssertEqual(c?.server.absoluteString, "https://cp.example:6443")
        XCTAssertEqual(c?.namespace, "team")
        XCTAssertEqual(c?.ca, pki.ca)
        XCTAssertNotNil(c?.tokens)
        XCTAssertNil(try ServerConfig.fromEnvironment([:]))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["KVO_SERVER": "https://x", "KVO_CA_FILE": "/nonexistent"]))
        XCTAssertNotNil(ServerConfig.tokenOverride(["KVO_TOKEN": "t"]))
        XCTAssertNil(ServerConfig.tokenOverride(["KVO_TOKEN": ""]))
    }
}

func XCTAssertThrowsAsync<T>(_ e: @autoclosure () async throws -> T, file: StaticString = #filePath, line: UInt = #line) async {
    do {
        _ = try await e()
        XCTFail("expected an error", file: file, line: line)
    } catch {}
}
