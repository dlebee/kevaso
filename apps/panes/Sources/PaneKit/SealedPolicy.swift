import Foundation
import WebKit

/// Every rule the sealed view applies, in one place (design §10.1, measured in research E034).
/// Change any of it only together with the hostile suite (`swift test`), and rerun the suite on every
/// macOS / WebKit update: two of the protections rely on private WebKit settings (see `privatePreferences`).
public enum SealedPolicy {
    /// The URL scheme bundles are served from: `kvpane://<pane id>/…`, one origin per opened pane.
    public static let scheme = "kvpane"

    /// The content security policy, set by the client as a response header on every file of the bundle.
    /// A bundle's own policy (a meta tag) can only add restrictions, never loosen this one.
    /// 'unsafe-inline' is deliberate: the whole document is untrusted, so nonces or hashes would protect
    /// nothing; what matters is that nothing can leave.
    public static let contentSecurityPolicy = [
        "default-src 'none'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob:",
        "font-src 'self' data:",
        "media-src 'none'", "object-src 'none'", "frame-src 'none'", "child-src 'none'", "worker-src 'none'",
        "connect-src 'none'", "manifest-src 'none'",
        "form-action 'none'", "base-uri 'none'", "frame-ancestors 'none'",
    ].joined(separator: "; ")

    /// A second layer under the CSP: block every URL WebKit would load, except the pane's own scheme.
    public static let contentRules = """
    [{"trigger":{"url-filter":".*"},"action":{"type":"block"}},
     {"trigger":{"url-filter":"^kvpane:"},"action":{"type":"ignore-previous-rules"}}]
    """

    /// Runs before any of the page's own script, in every frame (including the synchronous
    /// `about:blank` realm of a fresh iframe, where WebKit runs user scripts too).
    /// - WebRTC: E034 round 1 sent STUN over UDP; neither CSP nor content rules cover ICE.
    /// - Clipboard: readable and writable after one click; the private `javaScriptCanAccessClipboard`
    ///   setting only covers access without a gesture.
    /// - Links: WebKit opens a TCP connection to a link's host on mousedown, before the navigation
    ///   policy can cancel the click. Panes never navigate, so pointer and click defaults on links are
    ///   cancelled before WebKit's own handler runs.
    /// - Drags: a page could put data on the drag pasteboard and have it dropped in another app.
    public static let hardeningScript = """
    (() => {
      const kill = (o, k) => { try { delete o[k] } catch (e) {} try { Object.defineProperty(o, k, { value: undefined, writable: false, configurable: false }) } catch (e) {} };
      for (const k of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel', 'RTCRtpSender', 'RTCRtpReceiver',
                       'RTCRtpTransceiver', 'RTCIceTransport', 'RTCDtlsTransport', 'RTCSctpTransport']) kill(window, k);
      try { delete Navigator.prototype.clipboard } catch (e) {}
      kill(navigator, 'clipboard');
      const ex = Document.prototype.execCommand;
      Object.defineProperty(Document.prototype, 'execCommand', { value: function (c, ...a) {
        if (/^(copy|cut|paste)$/i.test(String(c))) return false; return ex.call(this, c, ...a) }, writable: false, configurable: false });
      for (const t of ['copy', 'cut', 'paste']) window.addEventListener(t, e => { e.preventDefault(); e.stopImmediatePropagation() }, true);
      for (const t of ['dragstart', 'drop']) window.addEventListener(t, e => { e.preventDefault(); e.stopImmediatePropagation() }, true);
      const linky = e => e.composedPath().some(n => n && n.nodeType === 1 &&
        (n.localName === 'a' || n.localName === 'area' || (n.namespaceURI === 'http://www.w3.org/2000/svg' && n.localName === 'a')));
      for (const t of ['pointerdown', 'mousedown', 'mouseup', 'click', 'auxclick', 'dblclick', 'contextmenu'])
        window.addEventListener(t, e => { if (linky(e)) { e.preventDefault(); e.stopImmediatePropagation() } }, true);
    })();
    """

    /// WebKit's private preferences the view turns off. **Private API (SPI)**: not documented, may
    /// change or vanish in any macOS update, and not allowed on the Mac App Store. Each is set through
    /// key-value coding only when its setter exists; `SealedPaneView.appliedPrivatePreferences` reports
    /// which were, and the suite fails if any is missing.
    public static let privatePreferences: [(key: String, setter: String)] = [
        ("peerConnectionEnabled", "_setPeerConnectionEnabled:"),        // WebRTC removed in the engine
        ("mediaDevicesEnabled", "_setMediaDevicesEnabled:"),            // navigator.mediaDevices
        ("javaScriptCanAccessClipboard", "_setJavaScriptCanAccessClipboard:"),
        ("DOMPasteAllowed", "_setDOMPasteAllowed:"),
        ("DNSPrefetchingEnabled", "_setDNSPrefetchingEnabled:"),        // <link rel=dns-prefetch>
    ]

    /// The private call the watchdog uses to end a hung pane's web content process. Without it, closing
    /// a pane stuck in a busy loop leaves its process burning a core (E034, t10a).
    public static let killSelector = "_killWebContentProcess"

    /// Whether each private setting exists on this WebKit.
    public static func privatePreferencesAvailable() -> [String: Bool] {
        let probe = WKPreferences()
        var out: [String: Bool] = [:]
        for p in privatePreferences { out[p.key] = probe.responds(to: NSSelectorFromString(p.setter)) }
        return out
    }

    public static var killAvailable: Bool {
        WKWebView.instancesRespond(to: NSSelectorFromString(killSelector))
    }

    @MainActor private static var compiled: WKContentRuleList?

    /// The block-all rule list, compiled once per process.
    @MainActor public static func ruleList() async throws -> WKContentRuleList {
        if let compiled { return compiled }
        let list: WKContentRuleList = try await withCheckedThrowingContinuation { cont in
            WKContentRuleListStore.default().compileContentRuleList(
                forIdentifier: "kevaso-pane-block-all-v1", encodedContentRuleList: contentRules) { list, err in
                if let list { cont.resume(returning: list) } else { cont.resume(throwing: err ?? SealedError.ruleList) }
            }
        }
        compiled = list
        return list
    }
}

public enum SealedError: Error, Equatable {
    case ruleList
    case badRoot
}
