// Kevaso Panes (design §7, §10.1): sign in to your clusters like `kvo login`, pick a namespace, turn
// panes on; each one floats in its own small always-on-top window with the identity drawn by the app.
//
//   swift run KevasoPanes
//   KVO_SERVER=https://… KVO_CA_FILE=ca.pem KVO_TOKEN=… KVO_NAMESPACE=team swift run KevasoPanes   (CI)
import AppKit
import PaneKit
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    let contexts = ContextStore()
    let store = PaneStore()
    let vault = KeychainVault()
    let floating: FloatingPanes
    let notifier: NeedsYouNotifier
    /// KVO_SERVER (and friends): a cluster from the environment, no sign-in.
    let environment: ServerConfig?
    /// KVO_TOKEN: overrides any sign-in, for CI.
    let tokenOverride = ServerConfig.tokenOverride()

    @Published var signedIn: Set<String> = []
    @Published var message = ""
    @Published var busy = false
    @Published var notify: Bool { didSet { UserDefaults.standard.set(notify, forKey: "notifyNeedsYou"); notifier.enabled = notify } }
    private var sessions: [String: ClusterSession] = [:]

    init() {
        var env: ServerConfig?
        var problem = ""
        do { env = try ServerConfig.fromEnvironment() } catch { problem = "\(error)" }
        environment = env
        floating = FloatingPanes(store: store, places: WindowPlaces(file: ContextStore.defaultFolder.appendingPathComponent("windows.json")))
        let on = UserDefaults.standard.bool(forKey: "notifyNeedsYou")
        notifier = NeedsYouNotifier(enabled: on)
        notify = on
        message = problem
        store.onNeedsYou = { [weak self] p, id in self?.notifier.needsYou(p, id) }
        store.onSessionEnded = { [weak self] e in self?.sessionEnded(e) }
        for c in contexts.contexts where (try? vault.read(c.id)) ?? nil != nil { signedIn.insert(c.id) }
        connect()
    }

    func session(_ c: ClusterContext) throws -> ClusterSession {
        if let s = sessions[c.id], s.context == c { return s }
        let s = try ClusterSession(context: c, vault: vault)
        Task { await s.setOnEnded { [weak self] e in Task { @MainActor in self?.sessionEnded(e) } } }
        sessions[c.id] = s
        return s
    }

    func sessionEnded(_ e: Error) {
        guard let c = contexts.current else { return }
        signedIn.remove(c.id)
        message = "\(e)"
        floating.closeAll()
        store.disconnect()
    }

    /// Connects to the current cluster when it can: the environment's, or a signed-in context.
    func connect() {
        if let environment {
            store.connect(environment, scope: "env")
            return
        }
        floating.closeAll()
        guard let c = contexts.current else { store.disconnect(); return }
        guard signedIn.contains(c.id) || tokenOverride != nil else { store.disconnect(); return }
        do {
            let tokens: AccessTokens = try tokenOverride ?? session(c)
            store.connect(ServerConfig(server: c.server, ca: try c.pinnedCA(), tokens: tokens, namespace: c.namespace), scope: c.id)
        } catch {
            message = "\(error)"
        }
    }

    func select(_ id: String?) {
        guard id != contexts.currentID else { return }
        contexts.currentID = id
        message = ""
        connect()
    }

    func setNamespace(_ ns: String) {
        guard var c = contexts.current, c.namespace != ns else { return }
        c.namespace = ns
        contexts.upsert(c)
        connect()
    }

    func add(name: String, server: String, fingerprint: String, namespace: String) async {
        busy = true
        defer { busy = false }
        do {
            guard let u = URL(string: server.trimmingCharacters(in: .whitespaces)), u.scheme == "https", u.host != nil else {
                throw TrustError.insecure(server)
            }
            let ca = try await PinnedSession.fetchCA(server: u, fingerprint: fingerprint)
            let c = ClusterContext(name: name.isEmpty ? (u.host ?? "cluster") : name, server: u, ca: ca,
                                   namespace: namespace.isEmpty ? "default" : namespace)
            contexts.upsert(c)
            contexts.currentID = c.id
            message = "CA \(ca.fingerprint) pinned for \(c.name)."
            await signIn(c)
        } catch {
            message = "\(error)"
        }
    }

    func signIn(_ c: ClusterContext) async {
        busy = true
        defer { busy = false }
        do {
            message = "Sign in in your browser…"
            try await session(c).signIn { url in await MainActor.run { _ = NSWorkspace.shared.open(url) } }
            signedIn.insert(c.id)
            message = "Signed in to \(c.name)."
            NSApp.activate(ignoringOtherApps: true)
            if contexts.current?.id == c.id { connect() }
        } catch {
            message = "\(error)"
        }
    }

    func signOut(_ c: ClusterContext) async {
        let s = try? session(c)
        if contexts.current?.id == c.id { floating.closeAll(); store.disconnect() }
        let confirmed = await s?.signOut() ?? false
        try? vault.delete(c.id)
        signedIn.remove(c.id)
        message = confirmed ? "Signed out of \(c.name)." : "Signed out of \(c.name) here (the cluster didn't confirm; its session ends when idle)."
    }

    func remove(_ c: ClusterContext) async {
        if signedIn.contains(c.id) { await signOut(c) }
        sessions[c.id] = nil
        contexts.remove(c.id)
        connect()
    }

    func setNotify(_ on: Bool) async {
        if on, SystemNotifications.available, !(await SystemNotifications.requestAuthorization()) {
            message = "Notifications are off for Kevaso Panes in System Settings."
        }
        notify = on
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel?
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { model?.floating.closeAll() }
    }
}

struct MainView: View {
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var store: PaneStore
    @EnvironmentObject var contexts: ContextStore
    @State private var adding = false

    var body: some View {
        NavigationSplitView {
            List(selection: Binding(get: { contexts.current?.id }, set: { model.select($0) })) {
                Section("Clusters") {
                    if model.environment != nil {
                        Label("From the environment (KVO_SERVER)", systemImage: "terminal").foregroundStyle(.secondary)
                    }
                    ForEach(contexts.contexts) { c in
                        HStack(spacing: 7) {
                            Circle().fill(model.signedIn.contains(c.id) ? Brand.green : Brand.ink3).frame(width: 7, height: 7)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(verbatim: c.name).font(.system(size: 12, weight: .medium))
                                Text(verbatim: c.server.host ?? c.server.absoluteString).font(.system(size: 10.5)).foregroundStyle(.secondary)
                            }
                        }
                        .tag(c.id)
                        .contextMenu {
                            if model.signedIn.contains(c.id) {
                                Button("Sign Out") { Task { await model.signOut(c) } }
                            } else {
                                Button("Sign In…") { Task { await model.signIn(c) } }
                            }
                            Divider()
                            Button("Remove", role: .destructive) { Task { await model.remove(c) } }
                        }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 230)
            .safeAreaInset(edge: .bottom) {
                Button { adding = true } label: { Label("Add Cluster…", systemImage: "plus") }
                    .buttonStyle(.borderless).padding(10).frame(maxWidth: .infinity, alignment: .leading)
            }
        } detail: {
            DetailView()
        }
        .sheet(isPresented: $adding) { AddClusterView(done: { adding = false }) }
    }
}

struct DetailView: View {
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var store: PaneStore
    @EnvironmentObject var contexts: ContextStore

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let c = contexts.current, model.environment == nil {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: c.name).font(.headline)
                        Text(verbatim: c.server.absoluteString + " · CA " + c.fingerprint.prefix(23) + "…")
                            .font(.system(size: 10.5, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                    Spacer()
                    if model.signedIn.contains(c.id) {
                        Button("Sign Out") { Task { await model.signOut(c) } }
                    } else {
                        Button("Sign In…") { Task { await model.signIn(c) } }.keyboardShortcut(.defaultAction).disabled(model.busy)
                    }
                }
                .padding(14)
                Divider()
            }
            if store.namespaces.count > 0 {
                Picker("Namespace", selection: Binding(get: { store.namespace }, set: { model.setNamespace($0) })) {
                    ForEach(store.namespaces, id: \.self) { Text(verbatim: $0).tag($0) }
                }
                .disabled(model.environment != nil)
                .frame(maxWidth: 320).padding(.horizontal, 14).padding(.vertical, 10)
            }
            List {
                ForEach(store.sorted) { p in
                    let ident = store.identity(p)
                    Toggle(isOn: Binding(get: { store.isEnabled(p) }, set: { store.setEnabled(p.id, $0) })) {
                        HStack(spacing: 8) {
                            Circle().fill(ident.rim).frame(width: 9, height: 9)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(verbatim: ident.silo + " · " + PlainText.clean(p.spec.pane, max: 60)).font(.system(size: 12, weight: .medium))
                                Text(verbatim: [p.spec.kind, PlainText.clean(p.spec.state, max: 20), p.isStale(now: store.now) ? "stale" : "",
                                                ident.striped ? (ident.trust == .untrusted ? "untrusted" : "trust unknown") : ""]
                                    .filter { !$0.isEmpty }.joined(separator: " · "))
                                    .font(.system(size: 10.5)).foregroundStyle(p.spec.state == "needs-you" ? Brand.amber : .secondary)
                            }
                        }
                    }
                    .toggleStyle(.switch)
                }
            }
            .overlay {
                if store.panes.isEmpty {
                    Text(contexts.contexts.isEmpty && model.environment == nil ? "Add a cluster to start." : "No panes here yet.")
                        .foregroundStyle(.secondary)
                }
            }
            Divider()
            HStack {
                Toggle("Notify me when a pane needs me", isOn: Binding(get: { model.notify }, set: { on in Task { await model.setNotify(on) } }))
                    .toggleStyle(.checkbox).font(.caption)
                Spacer()
                Text(verbatim: model.message.isEmpty ? store.status : model.message).font(.caption).foregroundStyle(.secondary)
                    .lineLimit(2).textSelection(.enabled)
            }
            .padding(10)
        }
    }
}

struct AddClusterView: View {
    @EnvironmentObject var model: AppModel
    let done: () -> Void
    @State private var name = ""
    @State private var server = ""
    @State private var fingerprint = ""
    @State private var namespace = "default"

    var body: some View {
        Form {
            Text("Like `kvo login SERVER --ca FINGERPRINT`: your admin gives you both.").font(.callout).foregroundStyle(.secondary)
            TextField("Name", text: $name, prompt: Text("home"))
            TextField("Server", text: $server, prompt: Text("https://203.0.113.10:6443"))
            TextField("CA fingerprint", text: $fingerprint, prompt: Text("sha256:…")).font(.system(.body, design: .monospaced))
            TextField("Namespace", text: $namespace)
            if !model.message.isEmpty { Text(verbatim: model.message).font(.caption).foregroundStyle(.secondary) }
            HStack {
                Spacer()
                Button("Cancel", action: done).keyboardShortcut(.cancelAction)
                Button("Add and Sign In") {
                    Task {
                        await model.add(name: name, server: server, fingerprint: fingerprint, namespace: namespace)
                        if model.contexts.current?.server.absoluteString == server.trimmingCharacters(in: .whitespaces) { done() }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(model.busy || server.isEmpty || PinnedCA.normalize(fingerprint: fingerprint) == nil)
            }
        }
        .padding(20)
        .frame(width: 480)
    }
}

struct KevasoPanesApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject var model = AppModel()

    var body: some Scene {
        Window("Kevaso Panes", id: "main") {
            MainView()
                .environmentObject(model).environmentObject(model.store).environmentObject(model.contexts)
                .frame(minWidth: 680, minHeight: 420)
                .onAppear { delegate.model = model }
        }
    }
}

KevasoPanesApp.main()
