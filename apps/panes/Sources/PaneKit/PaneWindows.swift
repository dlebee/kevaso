import AppKit
import Combine
import SwiftUI

/// Where each pane's window was, per pane and cluster, as JSON in the app's support folder.
@MainActor
public final class WindowPlaces {
    public struct Place: Codable, Equatable, Sendable {
        public var x, y, w, h: Double
        public init(_ r: NSRect) { x = r.origin.x; y = r.origin.y; w = r.size.width; h = r.size.height }
        public var rect: NSRect { NSRect(x: x, y: y, width: w, height: h) }
    }

    public static let minSize = NSSize(width: 220, height: 140)
    public static let maxSize = NSSize(width: 1400, height: 1000)
    public static let defaultSize = NSSize(width: 320, height: 220)

    public let file: URL
    private(set) var places: [String: Place] = [:]
    private var pending: DispatchWorkItem?

    public init(file: URL) {
        self.file = file
        if let d = try? Data(contentsOf: file), let p = try? JSONDecoder().decode([String: Place].self, from: d) { places = p }
    }

    public func place(_ key: String) -> NSRect? { places[key]?.rect }

    public func set(_ key: String, _ r: NSRect) {
        places[key] = Place(r)
        pending?.cancel()
        let w = DispatchWorkItem { [weak self] in MainActor.assumeIsolated { self?.saveNow() } }
        pending = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4, execute: w)
    }

    public func saveNow() {
        pending?.cancel()
        pending = nil
        try? FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let d = try? JSONEncoder().encode(places) { try? d.write(to: file, options: .atomic) }
    }

    /// A remembered frame made fit for the screens there are now: sized within the limits, and moved
    /// onto the screen it overlaps most (or nil when it overlaps none, e.g. a display was unplugged).
    public static func fit(_ r: NSRect, screens: [NSRect]) -> NSRect? {
        var r = r
        r.size.width = min(max(r.width, minSize.width), maxSize.width)
        r.size.height = min(max(r.height, minSize.height), maxSize.height)
        let best = screens.max { $0.intersection(r).area < $1.intersection(r).area }
        guard let s = best, s.intersection(r).area >= 40 * 40 else { return nil }
        r.size.width = min(r.width, s.width)
        r.size.height = min(r.height, s.height)
        r.origin.x = min(max(r.minX, s.minX), s.maxX - r.width)
        r.origin.y = min(max(r.minY, s.minY), s.maxY - r.height)
        return r
    }

    /// Where a new pane goes: stacked up from the bottom right of the screen, like the mockup.
    public static func cascade(_ index: Int, screen: NSRect) -> NSRect {
        let s = defaultSize, gap: CGFloat = 14
        let perColumn = max(1, Int((screen.height - gap) / (s.height + gap)))
        let col = index / perColumn, row = index % perColumn
        return NSRect(x: screen.maxX - (s.width + gap) * CGFloat(col + 1), y: screen.minY + gap + (s.height + gap) * CGFloat(row),
                      width: s.width, height: s.height)
    }
}

extension NSRect {
    var area: CGFloat { isNull ? 0 : width * height }
}

/// A pane's window: a small floating panel that never becomes key or main and never activates the
/// app, so nothing typed goes to a pane and a click in one can't take focus from another app. Its
/// size and place belong to the person (the frame header drags it, the edges resize it); the pane's
/// content has no way to change them: WebKit's window.resizeTo/moveTo/close/focus reach UI delegate
/// methods the sealed view doesn't implement.
public final class PanePanel: NSPanel {
    public override var canBecomeKey: Bool { false }
    public override var canBecomeMain: Bool { false }

    public init(frame: NSRect) {
        super.init(contentRect: frame, styleMask: [.titled, .resizable, .fullSizeContentView, .nonactivatingPanel],
                   backing: .buffered, defer: false)
        isFloatingPanel = true
        level = .floating
        hidesOnDeactivate = false
        becomesKeyOnlyIfNeeded = true
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .fullScreenDisallowsTiling]
        titleVisibility = .hidden
        titlebarAppearsTransparent = true
        for b in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] { standardWindowButton(b)?.isHidden = true }
        isMovableByWindowBackground = false
        isReleasedWhenClosed = false
        isOpaque = false
        backgroundColor = .clear
        hasShadow = true
        minSize = WindowPlaces.minSize
        maxSize = WindowPlaces.maxSize
        animationBehavior = .utilityWindow
        tabbingMode = .disallowed
    }

    // Only the person (through the window's own frame) and the app place it.
    public override func toggleFullScreen(_ sender: Any?) {}
}

/// One pane window and its SwiftUI content.
@MainActor
public final class PaneWindowController: NSObject, NSWindowDelegate {
    public let key: String
    public let panel: PanePanel
    var onMoved: ((NSRect) -> Void)?

    public init<V: View>(key: String, frame: NSRect, rootView: V) {
        self.key = key
        panel = PanePanel(frame: frame)
        super.init()
        let host = NSHostingView(rootView: rootView.ignoresSafeArea())
        host.sizingOptions = [] // the window's size is the person's, not the content's
        panel.contentView = host
        panel.delegate = self
        panel.setFrame(frame, display: false)
    }

    public func show() { panel.orderFrontRegardless() }

    public func close() {
        panel.delegate = nil
        panel.orderOut(nil)
        panel.close()
    }

    public func windowDidMove(_ notification: Notification) { onMoved?(panel.frame) }
    public func windowDidResize(_ notification: Notification) { onMoved?(panel.frame) }
}

/// The pane windows of the panes turned on: one floating window each, placed where the person left
/// it (per pane and cluster), closed when the pane is turned off or disappears.
@MainActor
public final class FloatingPanes {
    public let store: PaneStore
    public let places: WindowPlaces
    public private(set) var windows: [String: PaneWindowController] = [:]
    private var sub: AnyCancellable?
    private var scheduled = false
    var screens: () -> [NSRect] = { NSScreen.screens.map(\.visibleFrame) }

    public init(store: PaneStore, places: WindowPlaces) {
        self.store = store
        self.places = places
        sub = store.objectWillChange.sink { [weak self] _ in self?.scheduleSync() }
    }

    func scheduleSync() {
        guard !scheduled else { return }
        scheduled = true
        DispatchQueue.main.async { [weak self] in MainActor.assumeIsolated { self?.scheduled = false; self?.sync() } }
    }

    func placeKey(_ id: String) -> String { store.scope + "|" + id }

    public func sync() {
        let shown = Set(store.shown.map(\.id))
        for (id, w) in windows where !shown.contains(id) {
            w.close()
            windows[id] = nil
        }
        for p in store.shown where windows[p.id] == nil {
            let key = placeKey(p.id)
            let screens = screens()
            let main = screens.first ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
            let frame = places.place(key).flatMap { WindowPlaces.fit($0, screens: screens) }
                ?? WindowPlaces.cascade(windows.count, screen: main)
            let id = p.id
            let w = PaneWindowController(key: key, frame: frame, rootView: PaneWindowContent(store: store, id: id))
            w.onMoved = { [weak self] r in self?.places.set(key, r) }
            windows[id] = w
            w.show()
        }
    }

    public func closeAll() {
        places.saveNow()
        for w in windows.values { w.close() }
        windows = [:]
    }
}

/// What a pane window shows: the frame the client draws (identity, rim, marks) around the pane.
struct PaneWindowContent: View {
    @ObservedObject var store: PaneStore
    let id: String

    var body: some View {
        if let p = store.panes[id] {
            let ident = store.identity(p)
            PaneFrame(identity: ident, paneName: p.spec.pane, stale: p.isStale(now: store.now),
                      needsYou: p.spec.state == "needs-you",
                      trailing: AnyView(Button { store.setEnabled(id, false) } label: {
                          Image(systemName: "xmark").font(.system(size: 9, weight: .bold))
                      }.buttonStyle(.plain).foregroundStyle(.secondary).help("Turn this pane off"))) {
                if p.isHTML, let c = store.controllers[p.id] {
                    HTMLPaneSlot(controller: c)
                } else {
                    StatusPaneView(spec: p.spec, rim: ident.rim)
                }
            }
        } else {
            Color.clear
        }
    }
}

/// Where an HTML pane's sealed view sits, or why it isn't there.
public struct HTMLPaneSlot: View {
    @ObservedObject var controller: HTMLPaneController
    public init(controller: HTMLPaneController) { self.controller = controller }
    public var body: some View {
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

/// Puts a sealed view into SwiftUI. The sealed view is a plain child of a box the app owns.
public struct SealedViewHost: NSViewRepresentable {
    let view: SealedPaneView
    public init(view: SealedPaneView) { self.view = view }
    public func makeNSView(context: Context) -> NSView {
        let box = NSView()
        view.frame = box.bounds
        view.autoresizingMask = [.width, .height]
        box.addSubview(view)
        return box
    }
    public func updateNSView(_ box: NSView, context: Context) {
        if view.superview !== box {
            box.subviews.forEach { $0.removeFromSuperview() }
            view.frame = box.bounds
            box.addSubview(view)
        }
    }
}
