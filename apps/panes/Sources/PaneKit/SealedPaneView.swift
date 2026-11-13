import AppKit
import WebKit

/// A WKWebView that takes no keyboard focus, accepts no drops and shows no context menu. Panes may be
/// interactive locally with the mouse (rotate a view, switch a tab), but nothing typed or dropped by
/// the person reaches them, so a pane can't log keys or read a dropped file.
final class SealedWebView: WKWebView {
    override var acceptsFirstResponder: Bool { false }
    override func becomeFirstResponder() -> Bool { false }
    override func willOpenMenu(_ menu: NSMenu, with event: NSEvent) { menu.removeAllItems() }
    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation { [] }
    override func draggingUpdated(_ sender: NSDraggingInfo) -> NSDragOperation { [] }
    override func prepareForDragOperation(_ sender: NSDraggingInfo) -> Bool { false }
    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool { false }
}

/// One HTML pane in a sealed web view (design §10.1, the rules measured in research E034):
/// - its own CSP on every response (the bundle's is never trusted) and a block-all content rule list;
/// - a script at document start that removes WebRTC, clipboard access, link clicks and drags;
/// - peer connections, media devices, clipboard and DNS prefetching off in WebKit itself
///   (private settings, `SealedPolicy.privatePreferences`);
/// - a non-persistent data store of its own, and no script message handlers at all (one way);
/// - its own folder behind a scheme handler that refuses anything outside it;
/// - `data` pushed only as a call argument, never pasted into code;
/// - a watchdog that kills the pane when it stops answering;
/// - only its first page load is allowed: no navigation, no new windows, no dialogs, no downloads,
///   no media capture, no file picker, no fullscreen.
@MainActor
public final class SealedPaneView: NSView, WKNavigationDelegate, WKUIDelegate {
    public enum State: Equatable, Sendable {
        case loading
        case running
        case stopped(String)
    }

    public let paneID: String
    public private(set) var state: State = .loading { didSet { if state != oldValue { onStateChange?(state) } } }
    public var onStateChange: ((State) -> Void)?
    /// The private settings that were applied to this view (key → applied).
    public private(set) var appliedPrivatePreferences: [String: Bool] = [:]

    /// What the view refused or suppressed (navigations, windows, dialogs…), for diagnostics.
    public private(set) var events: [String] = []
    var schemeLog: [String] { handler.log }

    private let handler: PaneSchemeHandler
    private(set) var web: SealedWebView?
    private var latestData: Any?
    private var loadedOnce = false
    private var watchdog: Timer?
    private var pingSince: Date?
    private let watchdogInterval: TimeInterval
    private let watchdogTimeout: TimeInterval

    /// - Parameters:
    ///   - paneID: the host of the pane's origin, `kvpane://<paneID>/`; lowercase letters, digits and dashes.
    ///   - root: the pane's own folder (holding `index.html`); nothing outside it is ever served.
    ///   - watchdogTimeout: how long the pane may leave a ping unanswered before it is killed.
    public init(paneID: String, root: URL, ruleList: WKContentRuleList,
                watchdogInterval: TimeInterval = 1, watchdogTimeout: TimeInterval = 3) throws {
        guard paneID.range(of: "^[a-z0-9][a-z0-9-]{0,62}$", options: .regularExpression) != nil else { throw SealedError.badRoot }
        self.paneID = paneID
        self.handler = try PaneSchemeHandler(paneID: paneID, root: root)
        self.watchdogInterval = watchdogInterval
        self.watchdogTimeout = watchdogTimeout
        super.init(frame: NSRect(x: 0, y: 0, width: 300, height: 180))
        wantsLayer = true
        layer?.backgroundColor = NSColor.black.cgColor

        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()                 // nothing on disk, nothing shared
        config.userContentController = WKUserContentController()   // and no message handlers, ever
        config.userContentController.add(ruleList)
        config.userContentController.addUserScript(WKUserScript(source: SealedPolicy.hardeningScript,
            injectionTime: .atDocumentStart, forMainFrameOnly: false))
        config.setURLSchemeHandler(handler, forURLScheme: SealedPolicy.scheme)
        config.preferences.javaScriptCanOpenWindowsAutomatically = false
        config.preferences.isElementFullscreenEnabled = false
        config.preferences.isFraudulentWebsiteWarningEnabled = false // no Safe Browsing lookups
        config.preferences.isTextInteractionEnabled = false          // no text selection to copy
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        config.mediaTypesRequiringUserActionForPlayback = .all
        config.allowsAirPlayForMediaPlayback = false
        for p in SealedPolicy.privatePreferences {
            let ok = config.preferences.responds(to: NSSelectorFromString(p.setter))
            if ok { config.preferences.setValue(false, forKey: p.key) }
            appliedPrivatePreferences[p.key] = ok
        }

        let w = SealedWebView(frame: bounds, configuration: config)
        w.autoresizingMask = [.width, .height]
        w.navigationDelegate = self
        w.uiDelegate = self
        w.allowsBackForwardNavigationGestures = false
        w.allowsMagnification = false
        w.allowsLinkPreview = false
        w.unregisterDraggedTypes()
        addSubview(w)
        web = w
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError() }

    /// Load the pane's `index.html` and start the watchdog.
    public func load() {
        guard let web else { return }
        loadedOnce = false
        state = .loading
        web.load(URLRequest(url: URL(string: "\(SealedPolicy.scheme)://\(paneID)/index.html")!))
        startWatchdog()
    }

    /// Hand the pane its latest `data`. It arrives as the argument of `window.kvoUpdate(data)` and is
    /// never pasted into source. Must be JSON-shaped Foundation values (`JSONBytes.value()`).
    public func push(_ data: Any) {
        latestData = data
        guard state == .running, let web else { return }
        web.callAsyncJavaScript("if (typeof window.kvoUpdate === 'function') window.kvoUpdate(data)",
                                arguments: ["data": data], in: nil, in: .page) { _ in }
    }

    /// Close the pane: stop the watchdog, end its web content process, drop the web view.
    public func close(reason: String = "closed") {
        tearDown(kill: true)
        state = .stopped(reason)
    }

    private func tearDown(kill: Bool) {
        watchdog?.invalidate()
        watchdog = nil
        guard let web else { return }
        if kill { Self.killProcess(of: web) }
        web.stopLoading()
        web.navigationDelegate = nil
        web.uiDelegate = nil
        web.removeFromSuperview()
        self.web = nil
    }

    /// Private API: ends the web view's content process right away (closing alone leaves a busy loop
    /// running). Without it, the process ends only when WebKit decides to.
    static func killProcess(of web: WKWebView) {
        let sel = NSSelectorFromString(SealedPolicy.killSelector)
        if web.responds(to: sel) { web.perform(sel) }
    }

    // MARK: watchdog

    private func startWatchdog() {
        watchdog?.invalidate()
        pingSince = nil
        let t = Timer(timeInterval: watchdogInterval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
        RunLoop.main.add(t, forMode: .common)
        watchdog = t
    }

    private func tick() {
        guard let web else { return }
        if let since = pingSince {
            if Date().timeIntervalSince(since) > watchdogTimeout {
                events.append("WATCHDOG-KILL after \(String(format: "%.1f", Date().timeIntervalSince(since))) s")
                tearDown(kill: true)
                state = .stopped("unresponsive")
            }
            return
        }
        pingSince = Date()
        // A world of the client's own, so the page can't fake an answer; a hung page can't run it.
        web.callAsyncJavaScript("return 1", arguments: [:], in: nil, in: .defaultClient) { [weak self] _ in
            MainActor.assumeIsolated { self?.pingSince = nil }
        }
    }

    // MARK: navigation: only the pane's own first load

    public func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                        preferences: WKWebpagePreferences,
                        decisionHandler: @escaping @MainActor (WKNavigationActionPolicy, WKWebpagePreferences) -> Void) {
        let u = action.request.url
        let main = action.targetFrame?.isMainFrame ?? false
        if !loadedOnce && main && !action.shouldPerformDownload && u?.scheme == SealedPolicy.scheme && u?.host == paneID
            && (u?.path == "/index.html") {
            loadedOnce = true
            decisionHandler(.allow, preferences)
            return
        }
        events.append("NAV-CANCEL main=\(main) download=\(action.shouldPerformDownload) \(u?.absoluteString.prefix(120) ?? "?")")
        decisionHandler(.cancel, preferences)
    }

    public func webView(_ webView: WKWebView, decidePolicyFor response: WKNavigationResponse,
                        decisionHandler: @escaping @MainActor (WKNavigationResponsePolicy) -> Void) {
        let u = response.response.url
        if response.isForMainFrame && response.canShowMIMEType && u?.scheme == SealedPolicy.scheme && u?.host == paneID {
            decisionHandler(.allow)
        } else {
            events.append("RESPONSE-CANCEL \(u?.absoluteString.prefix(120) ?? "?")")
            decisionHandler(.cancel)
        }
    }

    public func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        events.append("DOWNLOAD-CANCEL"); download.cancel { _ in }
    }
    public func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        events.append("DOWNLOAD-CANCEL"); download.cancel { _ in }
    }

    public func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard webView === web else { return }
        state = .running
        if let d = latestData { push(d) }
    }

    public func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        events.append("LOAD-FAILED")
    }

    public func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        // Never reload by itself: a pane that crashes its process on purpose would loop.
        events.append("WEBCONTENT-TERMINATED")
        tearDown(kill: false)
        if case .stopped = state {} else { state = .stopped("crashed") }
    }

    // MARK: UI: refuse everything

    public func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                        for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        events.append("NEW-WINDOW-REFUSED")
        return nil
    }
    public func webView(_ webView: WKWebView, requestMediaCapturePermissionFor origin: WKSecurityOrigin,
                        initiatedByFrame frame: WKFrameInfo, type: WKMediaCaptureType,
                        decisionHandler: @escaping @MainActor (WKPermissionDecision) -> Void) {
        events.append("MEDIA-CAPTURE-DENIED"); decisionHandler(.deny)
    }
    public func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                        initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping @MainActor () -> Void) {
        events.append("ALERT-SUPPRESSED"); completionHandler()
    }
    public func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                        initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping @MainActor (Bool) -> Void) {
        events.append("CONFIRM-SUPPRESSED"); completionHandler(false)
    }
    public func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String, defaultText: String?,
                        initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping @MainActor (String?) -> Void) {
        events.append("PROMPT-SUPPRESSED"); completionHandler(nil)
    }
    public func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
                        initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping @MainActor ([URL]?) -> Void) {
        events.append("FILE-PICKER-REFUSED"); completionHandler(nil)
    }

    // MARK: test-only probes (the app never reads anything back from a pane)

    /// Runs `js` in the page world and returns its result as a string; nil on timeout.
    func probe(_ js: String, timeout: TimeInterval = 3) async -> String? {
        guard let web else { return nil }
        return await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
            var done = false
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) {
                if !done { done = true; cont.resume(returning: nil) }
            }
            web.callAsyncJavaScript(js, arguments: [:], in: nil, in: .page) { r in
                if done { return }
                done = true
                switch r {
                case .success(let v): cont.resume(returning: (v as? String) ?? "\(v)")
                case .failure(let e): cont.resume(returning: "ERROR \(e.localizedDescription)")
                }
            }
        }
    }

    /// Private, measurement only: the pid of the pane's web content process.
    var webProcessID: Int32 {
        (web?.value(forKey: "_webProcessIdentifier") as? NSNumber)?.int32Value ?? 0
    }
}
