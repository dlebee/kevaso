import Foundation
import WebKit

/// Serves one pane's folder, and nothing else, at `kvpane://<pane id>/…`. Each sealed view gets its
/// own handler that knows only its own id and folder: a request for another pane, a path that leaves
/// the folder (`..`, encoded or not, or a symlink pointing out), a directory or anything but GET is
/// refused. Every response carries the client's CSP.
final class PaneSchemeHandler: NSObject, WKURLSchemeHandler {
    let paneID: String
    let root: URL
    private let rootPath: String
    /// What the handler served or refused, for diagnostics and the hostile suite.
    private(set) var log: [String] = []

    init(paneID: String, root: URL) throws {
        self.paneID = paneID
        let r = root.standardizedFileURL.resolvingSymlinksInPath()
        var dir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: r.path, isDirectory: &dir), dir.boolValue else { throw SealedError.badRoot }
        self.root = r
        self.rootPath = r.path
    }

    static let mimeTypes: [String: String] = [
        "html": "text/html", "htm": "text/html", "js": "text/javascript", "mjs": "text/javascript",
        "css": "text/css", "json": "application/json", "txt": "text/plain", "svg": "image/svg+xml",
        "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
        "woff": "font/woff", "woff2": "font/woff2", "ttf": "font/ttf", "otf": "font/otf",
    ]

    /// The file a URL maps to, or nil when the request must be refused.
    func resolve(_ url: URL) -> URL? {
        guard url.scheme == SealedPolicy.scheme, url.host == paneID, url.user == nil, url.port == nil else { return nil }
        let path = url.path // percent-decoded
        let rel = (path.isEmpty || path == "/") ? "index.html" : String(path.dropFirst())
        let parts = rel.split(separator: "/", omittingEmptySubsequences: false)
        if parts.contains(where: { $0 == ".." || $0 == "." || $0.isEmpty }) || rel.contains("\0") || rel.contains("\\") { return nil }
        let file = root.appendingPathComponent(rel).standardizedFileURL.resolvingSymlinksInPath()
        guard file.path.hasPrefix(rootPath + "/") else { return nil }
        var dir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: file.path, isDirectory: &dir), !dir.boolValue else { return nil }
        return file
    }

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        let req = task.request
        guard let url = req.url, (req.httpMethod ?? "GET") == "GET", let file = resolve(url),
              let data = try? Data(contentsOf: file) else {
            log.append("DENY \(req.url?.absoluteString ?? "?")")
            task.didFailWithError(NSError(domain: "kvpane", code: 403))
            return
        }
        log.append("serve \(url.path)")
        let mime = Self.mimeTypes[file.pathExtension.lowercased()] ?? "application/octet-stream"
        let headers = [
            "Content-Type": mime, "Content-Length": "\(data.count)",
            "Content-Security-Policy": SealedPolicy.contentSecurityPolicy,
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
        ]
        task.didReceive(HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers)!)
        task.didReceive(data)
        task.didFinish()
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {}
}
