import AppKit
import Foundation
import SwiftUI

/// The app's state: the panes in one namespace (listed, then watched), which ones the person turned
/// on, the hosts of their silos, and one sealed view per open HTML pane.
@MainActor
public final class PaneStore: ObservableObject {
    @Published public private(set) var panes: [String: Pane] = [:]
    @Published public private(set) var hosts: [String: String] = [:]   // silo uid → host
    @Published public private(set) var status = "not connected"
    @Published public private(set) var now = Date()
    @Published public var enabled: Set<String> {
        didSet {
            UserDefaults.standard.set(Array(enabled), forKey: "enabledPanes")
            syncControllers()
        }
    }

    public private(set) var controllers: [String: HTMLPaneController] = [:]
    private var api: PaneAPI?
    private var loop: Task<Void, Never>?
    private var clock: Timer?

    public init() {
        enabled = Set(UserDefaults.standard.stringArray(forKey: "enabledPanes") ?? [])
        let t = Timer(timeInterval: 1, repeats: true) { [weak self] _ in MainActor.assumeIsolated { self?.now = Date() } }
        RunLoop.main.add(t, forMode: .common)
        clock = t
    }

    public var sorted: [Pane] { panes.values.sorted { $0.id < $1.id } }
    public var shown: [Pane] { sorted.filter { enabled.contains($0.id) } }

    public func identity(_ p: Pane) -> PaneIdentity {
        PaneIdentity(silo: p.spec.silo, siloUID: p.spec.siloUID, namespace: p.metadata.namespace, host: hosts[p.spec.siloUID])
    }

    public func connect(_ config: ServerConfig) {
        disconnect()
        do {
            api = try PaneAPI(config)
        } catch {
            status = "\(error)"
            return
        }
        let api = api!
        loop = Task { [weak self] in
            var backoff = 1.0
            while !Task.isCancelled {
                do {
                    let (items, rv) = try await api.list()
                    self?.replace(items)
                    self?.status = "watching \(config.namespace) on \(config.server.host ?? "?")"
                    backoff = 1
                    for try await e in api.watch(from: rv) {
                        self?.apply(e)
                    }
                } catch is CancellationError {
                    return
                } catch {
                    if Task.isCancelled { return }
                    self?.status = "\(error) (retrying)"
                }
                try? await Task.sleep(nanoseconds: UInt64(backoff * 1e9))
                backoff = min(backoff * 2, 30)
            }
        }
    }

    public func disconnect() {
        loop?.cancel()
        loop = nil
        api?.invalidate()
        api = nil
        for c in controllers.values { c.close() }
        controllers = [:]
        panes = [:]
        status = "not connected"
    }

    private func replace(_ items: [Pane]) {
        panes = Dictionary(items.map { ($0.id, $0) }, uniquingKeysWith: { _, b in b })
        syncControllers()
        lookUpHosts()
    }

    private func apply(_ e: PaneEvent) {
        switch e {
        case .upsert(let p): panes[p.id] = p
        case .deleted(let p): panes[p.id] = nil
        }
        syncControllers()
        lookUpHosts()
    }

    private func lookUpHosts() {
        guard let api else { return }
        for p in panes.values where hosts[p.spec.siloUID] == nil {
            let uid = p.spec.siloUID, silo = p.spec.silo
            hosts[uid] = "…"
            Task { [weak self] in
                let h = (try? await api.siloHost(silo)) ?? nil
                self?.hosts[uid] = h ?? "?"
            }
        }
    }

    /// One controller per pane that is HTML, present and turned on; the rest are closed.
    private func syncControllers() {
        for (id, c) in controllers where panes[id] == nil || !enabled.contains(id) || panes[id]?.isHTML != true {
            c.close()
            controllers[id] = nil
        }
        guard let api else { return }
        for p in panes.values where p.isHTML && enabled.contains(p.id) {
            if let c = controllers[p.id] { c.update(p) } else {
                let c = HTMLPaneController(api: api)
                controllers[p.id] = c
                c.update(p)
            }
        }
    }
}

/// One open HTML pane: downloads its bundle by digest, checks it, lays it out in a folder of its own
/// and opens it in a sealed view; later reports only push `data`, a new digest reopens the pane.
@MainActor
public final class HTMLPaneController: ObservableObject {
    @Published public private(set) var problem: String?
    @Published public private(set) var view: SealedPaneView?
    private let api: PaneAPI
    private var digest: String?
    private var folder: URL?
    private var opening: Task<Void, Never>?

    static var cacheRoot: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("KevasoPanes/open", isDirectory: true)
    }

    init(api: PaneAPI) { self.api = api }

    func update(_ p: Pane) {
        let data = try? p.spec.data?.value()
        if p.spec.bundle == digest, let view {
            if let data { view.push(data) }
            return
        }
        reopen(p, data: data)
    }

    private func reopen(_ p: Pane, data: Any?) {
        closeView()
        digest = p.spec.bundle
        problem = nil
        opening = Task { [weak self] in
            guard let self else { return }
            do {
                let bytes = try await api.bundle(for: p)
                let rules = try await SealedPolicy.ruleList()
                guard !Task.isCancelled, let d = p.spec.bundle else { return }
                let dir = try PaneBundle.materialize(bytes, expected: d, under: Self.cacheRoot)
                // a fresh, unguessable origin per opening
                let id = "p-" + UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "").prefix(20)
                let v = try SealedPaneView(paneID: String(id), root: dir, ruleList: rules)
                v.onStateChange = { [weak self] s in
                    if case .stopped(let why) = s, why != "closed" { self?.problem = "stopped: \(why)" }
                }
                if let data { v.push(data) }
                v.load()
                self.folder = dir
                self.view = v
            } catch {
                self.problem = "\(error)"
            }
        }
    }

    private func closeView() {
        opening?.cancel()
        view?.close()
        view = nil
        if let folder { try? FileManager.default.removeItem(at: folder) }
        folder = nil
    }

    func close() {
        closeView()
        digest = nil
    }
}
