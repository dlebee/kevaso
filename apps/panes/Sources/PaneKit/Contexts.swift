import Foundation

/// One cluster the app signs in to, like a `kvo` context: a server, the CA pinned for it, a
/// namespace. Nothing secret: the refresh token is in the keychain under `id`.
public struct ClusterContext: Codable, Identifiable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var server: URL
    public var caPEM: String
    public var namespace: String

    public init(id: String = UUID().uuidString.lowercased(), name: String, server: URL, ca: PinnedCA, namespace: String = "default") {
        self.id = id
        self.name = name
        self.server = server
        self.caPEM = String(decoding: ca.pem, as: UTF8.self)
        self.namespace = namespace
    }

    public func pinnedCA() throws -> PinnedCA { try PinnedCA(pem: Data(caPEM.utf8)) }
    public var fingerprint: String { (try? pinnedCA().fingerprint) ?? "?" }
}

/// The clusters, kept as JSON in the app's support folder (0600), and which one is current.
@MainActor
public final class ContextStore: ObservableObject {
    struct File: Codable {
        var current: String?
        var contexts: [ClusterContext]
    }

    @Published public private(set) var contexts: [ClusterContext] = []
    @Published public var currentID: String? { didSet { save() } }
    public let folder: URL
    var path: URL { folder.appendingPathComponent("contexts.json") }

    nonisolated public static var defaultFolder: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("KevasoPanes", isDirectory: true)
    }

    public init(folder: URL = ContextStore.defaultFolder) {
        self.folder = folder
        if let d = try? Data(contentsOf: path), let f = try? JSONDecoder().decode(File.self, from: d) {
            contexts = f.contexts
            currentID = f.current
        }
    }

    public var current: ClusterContext? { contexts.first { $0.id == currentID } ?? contexts.first }

    public func upsert(_ c: ClusterContext) {
        if let i = contexts.firstIndex(where: { $0.id == c.id }) { contexts[i] = c } else { contexts.append(c) }
        save()
    }

    public func remove(_ id: String) {
        contexts.removeAll { $0.id == id }
        if currentID == id { currentID = contexts.first?.id } else { save() }
    }

    func save() {
        let fm = FileManager.default
        try? fm.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        guard let d = try? JSONEncoder().encode(File(current: currentID, contexts: contexts)) else { return }
        try? d.write(to: path, options: .atomic)
        try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
    }
}
