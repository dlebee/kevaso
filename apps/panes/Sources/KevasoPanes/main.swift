// Kevaso Panes: one window that owns many panes (design §7, §10.1). It lists and watches the panes of
// one namespace, shows only the ones the person turned on, draws each pane's identity itself, and
// opens HTML panes in the sealed view.
//
//   KVO_SERVER=https://… KVO_CA_FILE=ca.pem KVO_TOKEN=… KVO_NAMESPACE=team swift run KevasoPanes
import AppKit
import PaneKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

/// Settings, overridden by the environment. The token is kept in the app's defaults until keychain
/// integration lands (README: what is not done).
@MainActor
final class AppSettings: ObservableObject {
    @AppStorage("server") var server = ""
    @AppStorage("caFile") var caFile = ""
    @AppStorage("token") var token = ""
    @AppStorage("namespace") var namespace = "default"

    var config: ServerConfig? {
        if let env = ServerConfig.fromEnvironment() { return env }
        guard let u = URL(string: server), u.host != nil else { return nil }
        return ServerConfig(server: u, caFile: caFile.isEmpty ? nil : caFile, token: token.isEmpty ? nil : token,
                            namespace: namespace.isEmpty ? "default" : namespace)
    }
    var fromEnvironment: Bool { ServerConfig.fromEnvironment() != nil }
}

struct ContentView: View {
    @EnvironmentObject var store: PaneStore
    @EnvironmentObject var settings: AppSettings

    var body: some View {
        NavigationSplitView {
            List {
                Section("Panes in \(settings.config?.namespace ?? "–")") {
                    ForEach(store.sorted) { p in
                        Toggle(isOn: Binding(get: { store.enabled.contains(p.id) },
                                             set: { on in if on { store.enabled.insert(p.id) } else { store.enabled.remove(p.id) } })) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(verbatim: p.metadata.name).font(.system(size: 12, weight: .medium))
                                Text(verbatim: p.spec.kind + (p.isStale(now: store.now) ? " · stale" : ""))
                                    .font(.system(size: 10.5)).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 240)
            .safeAreaInset(edge: .bottom) {
                Text(verbatim: store.status).font(.caption).foregroundStyle(.secondary).padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        } detail: {
            if store.shown.isEmpty {
                Text(store.panes.isEmpty ? "No panes yet." : "Turn a pane on in the list.").foregroundStyle(.secondary)
            } else {
                ScrollView {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 300, maximum: 420), spacing: 14)], spacing: 14) {
                        ForEach(store.shown) { p in
                            PaneFrame(identity: store.identity(p), paneName: p.spec.pane, stale: p.isStale(now: store.now)) {
                                if p.isHTML, let c = store.controllers[p.id] {
                                    HTMLPaneSlot(controller: c)
                                } else {
                                    StatusPaneView(spec: p.spec, rim: store.identity(p).rim)
                                }
                            }
                            .frame(height: 220)
                        }
                    }
                    .padding(14)
                }
                .background(Color(red: 0x15 / 255, green: 0x1a / 255, blue: 0x22 / 255))
            }
        }
        .onAppear { if let c = settings.config { store.connect(c) } }
    }
}

/// Where an HTML pane's sealed view sits, or why it isn't there.
struct HTMLPaneSlot: View {
    @ObservedObject var controller: HTMLPaneController
    var body: some View {
        if let p = controller.problem {
            Text(verbatim: p).font(.caption).foregroundStyle(Brand.rose).padding(10)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else if let v = controller.view {
            SealedViewHost(view: v)
        } else {
            ProgressView().controlSize(.small)
        }
    }
}

struct SealedViewHost: NSViewRepresentable {
    let view: SealedPaneView
    func makeNSView(context: Context) -> NSView {
        let box = NSView()
        view.frame = box.bounds
        view.autoresizingMask = [.width, .height]
        box.addSubview(view)
        return box
    }
    func updateNSView(_ box: NSView, context: Context) {
        if view.superview !== box {
            box.subviews.forEach { $0.removeFromSuperview() }
            view.frame = box.bounds
            box.addSubview(view)
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject var settings: AppSettings
    @EnvironmentObject var store: PaneStore

    var body: some View {
        Form {
            if settings.fromEnvironment {
                Text("KVO_SERVER is set: the environment wins over these settings.").foregroundStyle(.secondary)
            }
            TextField("Server URL", text: $settings.server, prompt: Text("https://control-plane:6443"))
            TextField("CA file (PEM)", text: $settings.caFile, prompt: Text("/path/to/ca.pem"))
            SecureField("Bearer token", text: $settings.token)
            TextField("Namespace", text: $settings.namespace)
            HStack {
                Spacer()
                Button("Connect") { if let c = settings.config { store.connect(c) } }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}

struct KevasoPanesApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject var store = PaneStore()
    @StateObject var settings = AppSettings()

    var body: some Scene {
        Window("Kevaso Panes", id: "main") { // one window owns every pane
            ContentView().environmentObject(store).environmentObject(settings)
                .frame(minWidth: 720, minHeight: 440)
        }
        Settings {
            SettingsView().environmentObject(store).environmentObject(settings)
        }
    }
}

KevasoPanesApp.main()
