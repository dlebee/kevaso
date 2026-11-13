import Darwin
import Foundation

/// Tiny socket servers for the tests: no admin rights, ephemeral ports.

final class Locked<T>: @unchecked Sendable {
    private var v: T
    private let l = NSLock()
    init(_ v: T) { self.v = v }
    func with<R>(_ f: (inout T) -> R) -> R { l.lock(); defer { l.unlock() }; return f(&v) }
    var value: T { with { $0 } }
}

enum Sock {
    static func address(_ ip: String, _ port: UInt16) -> sockaddr_in {
        var a = sockaddr_in()
        a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        a.sin_family = sa_family_t(AF_INET)
        a.sin_port = port.bigEndian
        inet_pton(AF_INET, ip, &a.sin_addr)
        return a
    }

    /// Binds a socket on ip:port (0 = any free port) and returns it with the port it got.
    static func bind(_ type: Int32, _ ip: String, _ port: UInt16 = 0) throws -> (Int32, UInt16) {
        let fd = socket(AF_INET, type, 0)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var a = address(ip, port)
        let r = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard r == 0 else { close(fd); throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EADDRINUSE) }
        var got = sockaddr_in(), len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &got) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        if type == SOCK_STREAM { listen(fd, 64) }
        return (fd, UInt16(bigEndian: got.sin_port))
    }

    /// The Mac's first IPv4 LAN address, if it has one.
    static func lanAddress() -> String? {
        var ifs: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifs) == 0, let first = ifs else { return nil }
        defer { freeifaddrs(ifs) }
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let i = p.pointee
            guard let sa = i.ifa_addr, sa.pointee.sa_family == sa_family_t(AF_INET),
                  i.ifa_flags & UInt32(IFF_UP) != 0, i.ifa_flags & UInt32(IFF_LOOPBACK) == 0 else { continue }
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            var sin = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            inet_ntop(AF_INET, &sin.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN))
            let s = String(cString: buf)
            let name = String(cString: i.ifa_name)
            if name.hasPrefix("en") { return s }
        }
        return nil
    }

    static func thread(_ f: @escaping @Sendable () -> Void) {
        let t = Thread(block: f)
        t.stackSize = 1 << 20
        t.start()
    }
}

/// "The outside": listens on loopback (and the LAN address when there is one) over TCP and UDP, and
/// records every TCP connection (even one that sends nothing), every request line and every datagram.
/// Any hit while a hostile pane runs is a leak.
final class Collector: @unchecked Sendable {
    struct Hit: CustomStringConvertible {
        var kind: String
        var detail: String
        var at: Date
        var description: String { "\(kind) \(detail)" }
    }
    let lan: String?
    private(set) var tcpPort: UInt16 = 0
    private(set) var udpPort: UInt16 = 0
    private let hits = Locked<[Hit]>([])
    private var fds: [Int32] = []

    init() throws {
        lan = Sock.lanAddress()
        let ips = ["127.0.0.1"] + (lan.map { [$0] } ?? [])
        // the same ports on every address, so one placeholder fits all
        let (t0, tp) = try Sock.bind(SOCK_STREAM, ips[0])
        let (u0, up) = try Sock.bind(SOCK_DGRAM, ips[0])
        tcpPort = tp; udpPort = up
        var tcp = [t0], udp = [u0]
        for ip in ips.dropFirst() {
            if let (t, _) = try? Sock.bind(SOCK_STREAM, ip, tp) { tcp.append(t) }
            if let (u, _) = try? Sock.bind(SOCK_DGRAM, ip, up) { udp.append(u) }
        }
        fds = tcp + udp
        for fd in tcp { Sock.thread { [hits] in Self.acceptLoop(fd, hits) } }
        for fd in udp { Sock.thread { [hits] in Self.udpLoop(fd, hits) } }
    }

    private static func acceptLoop(_ fd: Int32, _ hits: Locked<[Hit]>) {
        while true {
            let c = accept(fd, nil, nil)
            if c < 0 { if errno == EINTR { continue }; return }
            hits.with { $0.append(Hit(kind: "tcp-accept", detail: "", at: Date())) }
            Sock.thread {
                var tv = timeval(tv_sec: 2, tv_usec: 0)
                setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                var buf = [UInt8](repeating: 0, count: 4096)
                let n = read(c, &buf, buf.count)
                if n > 0 {
                    let line = String(decoding: buf[0..<n], as: UTF8.self).split(separator: "\r\n").first.map(String.init) ?? ""
                    hits.with { $0.append(Hit(kind: "request", detail: String(line.prefix(120)), at: Date())) }
                    let body = "collector"
                    let resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n\(body)"
                    _ = resp.withCString { write(c, $0, strlen($0)) }
                }
                close(c)
            }
        }
    }

    private static func udpLoop(_ fd: Int32, _ hits: Locked<[Hit]>) {
        var buf = [UInt8](repeating: 0, count: 2048)
        while true {
            let n = recv(fd, &buf, buf.count, 0)
            if n < 0 { if errno == EINTR { continue }; return }
            hits.with { $0.append(Hit(kind: "udp", detail: "\(n) bytes", at: Date())) }
        }
    }

    var count: Int { hits.value.count }
    func hits(since i: Int) -> [Hit] { Array(hits.value.dropFirst(i)) }
}

/// A fake control plane: answers canned responses by path, and records the requests it got.
final class FakeAPI: @unchecked Sendable {
    struct Request { var method: String; var path: String; var headers: [String: String] }
    struct Response {
        var status = 200
        var headers: [String: String] = ["Content-Type": "application/json"]
        var body = Data()
        /// For a watch: lines written one by one, then the connection closes.
        var lines: [Data]? = nil
    }
    let port: UInt16
    let routes = Locked<[String: Response]>([:])
    let requests = Locked<[Request]>([])
    private let fd: Int32

    init() throws {
        (fd, port) = try Sock.bind(SOCK_STREAM, "127.0.0.1")
        let fd = self.fd
        Sock.thread { [routes, requests] in
            while true {
                let c = accept(fd, nil, nil)
                if c < 0 { if errno == EINTR { continue }; return }
                Sock.thread { Self.serve(c, routes, requests) }
            }
        }
    }

    var url: URL { URL(string: "http://127.0.0.1:\(port)")! }

    private static func serve(_ c: Int32, _ routes: Locked<[String: Response]>, _ requests: Locked<[Request]>) {
        defer { close(c) }
        var data = Data(), buf = [UInt8](repeating: 0, count: 4096)
        while !data.contains("\r\n\r\n".data(using: .utf8)!) {
            let n = read(c, &buf, buf.count)
            if n <= 0 { return }
            data.append(contentsOf: buf[0..<n])
        }
        let head = String(decoding: data, as: UTF8.self).components(separatedBy: "\r\n\r\n")[0].components(separatedBy: "\r\n")
        let parts = head[0].split(separator: " ")
        guard parts.count >= 2 else { return }
        var headers: [String: String] = [:]
        for h in head.dropFirst() {
            if let i = h.firstIndex(of: ":") { headers[h[..<i].lowercased()] = h[h.index(after: i)...].trimmingCharacters(in: .whitespaces) }
        }
        let path = String(parts[1])
        requests.with { $0.append(Request(method: String(parts[0]), path: path, headers: headers)) }
        let key = String(path.split(separator: "?").first ?? "") + (path.contains("watch=true") ? "?watch" : "")
        let r = routes.value[key] ?? Response(status: 404, body: Data(#"{"message":"not found"}"#.utf8))
        func send(_ d: Data) { d.withUnsafeBytes { p in var o = 0; while o < d.count { let n = write(c, p.baseAddress! + o, d.count - o); if n <= 0 { return }; o += n } } }
        var h = "HTTP/1.1 \(r.status) X\r\nConnection: close\r\n"
        for (k, v) in r.headers { h += "\(k): \(v)\r\n" }
        if let lines = r.lines {
            send(Data((h + "\r\n").utf8))
            for l in lines { send(l + Data("\n".utf8)); usleep(50_000) }
        } else {
            send(Data((h + "Content-Length: \(r.body.count)\r\n\r\n").utf8) + r.body)
        }
    }
}
