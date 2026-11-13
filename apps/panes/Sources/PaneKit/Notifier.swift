import AppKit
import Foundation
import UserNotifications

/// Tells the person a pane they turned on needs them. Raised by the app only, when the Pane object
/// (relayed by the control plane) changes into `state: needs-you`; a pane's own content has no way
/// to reach it (the sealed view has no message handlers and refuses the Notification API).
///
/// The text is the client's: the silo's name and namespace (server-set) and the pane's name, made
/// plain. Never the silo's message, which could read like a system prompt ("enter your password").
@MainActor
public final class NeedsYouNotifier {
    public struct Note: Equatable, Sendable {
        public var id: String
        public var title: String
        public var body: String
    }

    /// The person's choice ("Notify me when a pane needs me"); off until they turn it on.
    public var enabled: Bool
    public var minimumInterval: TimeInterval = 60
    private let post: @MainActor (Note) -> Void
    private var last: [String: Date] = [:]
    let now: () -> Date

    public init(enabled: Bool, now: @escaping () -> Date = Date.init, post: @escaping @MainActor (Note) -> Void = SystemNotifications.post) {
        self.enabled = enabled
        self.now = now
        self.post = post
    }

    public func needsYou(_ p: Pane, _ id: PaneIdentity) {
        guard enabled else { return }
        let t = now()
        if let l = last[p.id], t.timeIntervalSince(l) < minimumInterval { return }
        last[p.id] = t
        post(Note(id: p.id, title: PlainText.clean(id.silo, max: 60) + " needs you",
                  body: PlainText.clean(p.spec.pane, max: 60) + " · " + PlainText.clean(id.namespace, max: 60)))
    }
}

/// macOS notifications when the app runs as a bundle (UserNotifications needs a bundle identifier);
/// run with `swift run`, it bounces the Dock icon instead.
public enum SystemNotifications {
    public static var available: Bool { Bundle.main.bundleIdentifier != nil && Bundle.main.bundleURL.pathExtension == "app" }

    /// Asks macOS for permission; true when granted.
    public static func requestAuthorization() async -> Bool {
        guard available else { return false }
        return (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])) ?? false
    }

    @MainActor
    public static func post(_ n: NeedsYouNotifier.Note) {
        guard available else {
            NSApp?.requestUserAttention(.informationalRequest)
            return
        }
        let c = UNMutableNotificationContent()
        c.title = n.title
        c.body = n.body
        c.threadIdentifier = "needs-you"
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "needs-you." + n.id, content: c, trigger: nil))
    }
}
