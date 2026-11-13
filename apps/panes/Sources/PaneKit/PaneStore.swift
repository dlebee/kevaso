import AppKit
import Foundation
import SwiftUI

/// The app's state: the panes in one namespace of one cluster (listed, then watched), which ones the
/// person turned on (remembered per cluster), what the client knows of their silos (host, trust),
/// and one controller per open HTML pane.
@MainActor
public final class PaneStore: ObservableObject {
    @Published public private(set) var panes: [String: Pane] = [:]
    @Published public private(set) var silos: [String: SiloInfo] = [:]   // silo uid → info
    @Published public private(set) var namespaces: [String] = []
    @Published public private(set) var status = "not connected"
    @Published public private(set) var now = Date()
    /// Turned-on panes, as "<scope>|<namespace>/<name>".
    @Published public private(set) var enabledKeys: Set<String>

    /// A pane that's turned on went into `state: needs-you` (the app may raise a notification).
    public var onNeedsYou: ((Pane, PaneIdentity) -> Void)?
    /// The session behind the connection ended (signed out, revoked).
    public var onSessionEnded: ((Error) -> Void)?

    public private(set) var controllers: [String: HTMLPaneController] = [:]
    public private(set) var scope = ""
    public private(set) var namespace = ""
    private let defaults: UserDefaults
    private var api: PaneAPI?
    private var loop: Task<Void, Never>?
    private var clock: Timer?

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        enabledKeys = Set(defaults.stringArray(forKey: "enabledPanes") ?? [])
        let t = Timer(timeInterval: 1, repeats: true) { [weak self] _ in MainActor.assumeIsolated { self?.now = Date() } }
        RunLoop.main.add(t, forMode: .common)
        clock = t
    }

    func key(_ id: String) -> String { scope + "|" + id }
    public func isEnabled(_ p: Pane) -> Bool { enabledKeys.contains(key(p.id)) }
    public func setEnabled(_ id: String, _ on: Bool) {
        if on { enabledKeys.insert(key(id)) } else { enabledKeys.remove(key(id)) }
        defaults.set(Array(enabledKeys).sorted(), forKey: "enabledPanes")
        syncControllers()
    }

    public var sorted: [Pane] { panes.values.sorted { $0.id < $1.id } }
    public var shown: [Pane] { sorted.filter(isEnabled) }

    public func identity(_ p: Pane) -> PaneIdentity {
        let info = silos[p.spec.siloUID]
        return PaneIdentity(silo: p.spec.silo, siloUID: p.spec.siloUID, namespace: p.metadata.namespace,
                            host: info?.host, trust: info?.trust ?? .unknown)
    }

    /// Lists and watches the panes of `config.namespace`. `scope` names the cluster, so switches and
    /// window places are kept per cluster.
    public func connect(_ config: ServerConfig, scope: String = "") {
        disconnect()
        self.scope = scope
        self.namespace = config.namespace
        do {
            api = try PaneAPI(config)
        } catch {
            status = "\(error)"
            return
        }
        let api = api!
        Task { [weak self] in
            let ns = (try? await api.namespaces()) ?? []
            guard let self, self.api === api else { return }
            self.namespaces = ns.isEmpty ? [config.namespace] : Array(Set(ns + [config.namespace])).sorted()
        }
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
                } catch let e as SessionError where e.endsSession {
                    self?.status = "\(e)"
                    self?.onSessionEnded?(e)
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
        silos = [:]
        namespaces = []
        status = "not connected"
    }

    private func replace(_ items: [Pane]) {
        let old = panes
        panes = Dictionary(items.map { ($0.id, $0) }, uniquingKeysWith: { _, b in b })
        for p in panes.values { noticeState(old[p.id], p) }
        syncControllers()
        lookUpSilos()
    }

    private func apply(_ e: PaneEvent) {
        switch e {
        case .upsert(let p):
            let old = panes[p.id]
            panes[p.id] = p
            noticeState(old, p)
        case .deleted(let p): panes[p.id] = nil
        }
        syncControllers()
        lookUpSilos()
    }

    /// Only a change into needs-you counts, and only for a pane that's turned on: a silo repeating
    /// its report doesn't ring again.
    private func noticeState(_ old: Pane?, _ new: Pane) {
        guard new.spec.state == "needs-you", old?.spec.state != "needs-you", isEnabled(new) else { return }
        onNeedsYou?(new, identity(new))
    }

    private func lookUpSilos() {
        guard let api else { return }
        for p in panes.values where silos[p.spec.siloUID] == nil {
            let uid = p.spec.siloUID, silo = p.spec.silo
            silos[uid] = SiloInfo(host: "…", trust: .unknown)
            Task { [weak self] in
                let info = (try? await api.silo(silo)) ?? SiloInfo(host: "?", trust: .unknown)
                self?.silos[uid] = info
            }
        }
    }

    /// One controller per pane that is HTML, present and turned on; the rest are closed.
    private func syncControllers() {
        for (id, c) in controllers where panes[id].map({ !$0.isHTML || !isEnabled($0) }) ?? true {
            c.close()
            controllers[id] = nil
        }
        guard let api else { return }
        for p in panes.values where p.isHTML && isEnabled(p) {
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
