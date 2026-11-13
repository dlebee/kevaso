import SwiftUI

/// Silo text, made safe to show as plain text: no control characters, no bidirectional overrides
/// (which could make one string read as another), one line where one line is expected, and a cap.
public enum PlainText {
    static let bidi: Set<Unicode.Scalar> = Set("\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}\u{200E}\u{200F}\u{061C}".unicodeScalars)

    public static func clean(_ s: String?, max: Int = 500, singleLine: Bool = true) -> String {
        guard let s else { return "" }
        var out = String.UnicodeScalarView()
        for u in s.unicodeScalars {
            if bidi.contains(u) { continue }
            if u == "\n" || u == "\t" || u == "\r" { out.append(singleLine ? " " : (u == "\r" ? "\n" : u)); continue }
            if u.properties.generalCategory == .control || u.properties.generalCategory == .format { continue }
            out.append(u)
        }
        let t = String(out)
        return t.count > max ? String(t.prefix(max)) + "…" : t
    }
}

/// A status pane, drawn natively by the client from the report's fields: no web view and no
/// JavaScript, and every string from the silo is shown verbatim as plain text (never as markdown,
/// HTML or a link).
public struct StatusPaneView: View {
    public let spec: Pane.Spec
    public let rim: Color

    public init(spec: Pane.Spec, rim: Color) {
        self.spec = spec
        self.rim = rim
    }

    /// The strings shown, in order (what the hostile suite checks).
    public static func lines(_ s: Pane.Spec) -> [String] {
        var out = [PlainText.clean(s.title, max: 120), PlainText.clean(s.state, max: 20)]
        if let m = s.message { out.append(PlainText.clean(m, max: 1000, singleLine: false)) }
        for f in s.fields ?? [] { out.append(PlainText.clean(f.label, max: 60) + ": " + PlainText.clean(f.value, max: 200)) }
        return out
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Circle().fill(stateColor).frame(width: 8, height: 8)
                Text(verbatim: PlainText.clean(spec.state, max: 20)).font(.caption).foregroundStyle(.secondary)
                Spacer()
            }
            Text(verbatim: PlainText.clean(spec.title, max: 120)).font(.headline).lineLimit(1)
            if let p = spec.progress {
                ProgressView(value: min(max(p, 0), 1)).tint(rim)
            }
            if let m = spec.message, !m.isEmpty {
                Text(verbatim: PlainText.clean(m, max: 1000, singleLine: false)).font(.callout).lineLimit(4)
                    .textSelection(.disabled)
            }
            ForEach(Array((spec.fields ?? []).prefix(16).enumerated()), id: \.offset) { _, f in
                HStack {
                    Text(verbatim: PlainText.clean(f.label, max: 60)).foregroundStyle(.secondary)
                    Spacer()
                    Text(verbatim: PlainText.clean(f.value, max: 200)).monospacedDigit()
                }.font(.caption)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    var stateColor: Color {
        switch spec.state {
        case "running": return Brand.teal
        case "needs-you": return Brand.amber
        case "done": return Brand.green
        case "failed": return Brand.rose
        default: return Brand.ink3
        }
    }
}

/// The brand palette (idealization/brand, mockups/panes.html).
public enum Brand {
    public static let amber = Color(red: 0xf0 / 255, green: 0xa9 / 255, blue: 0x4b / 255)
    public static let teal = Color(red: 0x3c / 255, green: 0xc7 / 255, blue: 0xb4 / 255)
    public static let violet = Color(red: 0xa9 / 255, green: 0x8b / 255, blue: 0xf0 / 255)
    public static let rose = Color(red: 0xf0 / 255, green: 0x7a / 255, blue: 0x8a / 255)
    public static let green = Color(red: 0x6f / 255, green: 0xd3 / 255, blue: 0x8f / 255)
    public static let ink = Color(red: 0xee / 255, green: 0xf0 / 255, blue: 0xf4 / 255)
    public static let ink3 = Color(red: 0x7a / 255, green: 0x81 / 255, blue: 0x91 / 255)
    public static let panel = Color(red: 0x0d / 255, green: 0x10 / 255, blue: 0x17 / 255)
    public static let rims = [amber, teal, violet, rose, green]
}

/// Who a pane belongs to, as the client knows it: from the Pane object's server-set fields and the
/// silo's status, never from what the silo reported.
public struct PaneIdentity: Equatable, Sendable {
    public var silo: String
    public var siloUID: String
    public var namespace: String
    public var host: String?
    /// From the Silo object's labels, read by the client (never from the pane): anything but
    /// `.trusted` gets the striped rim.
    public var trust: SiloTrust

    public init(silo: String, siloUID: String, namespace: String, host: String?, trust: SiloTrust = .unknown) {
        self.silo = silo
        self.siloUID = siloUID
        self.namespace = namespace
        self.host = host
        self.trust = trust
    }

    public var striped: Bool { trust != .trusted }

    /// A stable rim colour per silo (FNV-1a of namespace/silo), so the same silo keeps its colour.
    public var rimIndex: Int {
        var h: UInt32 = 2166136261
        for b in (namespace + "/" + silo).utf8 { h = (h ^ UInt32(b)) &* 16777619 }
        return Int(h % UInt32(Brand.rims.count))
    }
    public var rim: Color { Brand.rims[rimIndex] }
}

/// The frame the client draws around every pane: the rim, the silo name, namespace and host, and a
/// stale mark. The content sits inside it and can't draw over it.
public struct PaneFrame<Content: View>: View {
    let identity: PaneIdentity
    let paneName: String
    let stale: Bool
    let needsYou: Bool
    let trailing: AnyView?
    let content: Content

    public init(identity: PaneIdentity, paneName: String, stale: Bool, needsYou: Bool = false,
                trailing: AnyView? = nil, @ViewBuilder content: () -> Content) {
        self.identity = identity
        self.paneName = paneName
        self.stale = stale
        self.needsYou = needsYou
        self.trailing = trailing
        self.content = content()
    }

    public var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                Circle().fill(identity.rim).frame(width: 9, height: 9).shadow(color: identity.rim, radius: 4)
                Text(verbatim: identity.silo).font(.system(size: 12, weight: .semibold))
                Text(verbatim: "· " + paneName).font(.system(size: 11)).foregroundStyle(.secondary)
                Spacer()
                if identity.striped {
                    Text(identity.trust == .untrusted ? "untrusted" : "trust unknown").font(.system(size: 10.5))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Capsule().fill(identity.rim.opacity(0.22)))
                }
                if needsYou {
                    Text("needs you").font(.system(size: 10.5, weight: .semibold)).padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Capsule().fill(Brand.amber.opacity(0.35)))
                }
                if stale {
                    Text("stale").font(.system(size: 10.5)).padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Capsule().fill(Brand.ink3.opacity(0.3)))
                }
                Text(verbatim: identity.namespace + (identity.host.map { " · " + $0 } ?? ""))
                    .font(.system(size: 10.5)).foregroundStyle(.secondary).lineLimit(1)
                if let trailing { trailing }
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(LinearGradient(colors: [identity.rim.opacity(0.16), .clear], startPoint: .top, endPoint: .bottom))
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .clipped()
                .opacity(stale ? 0.55 : 1)
        }
        .background(Brand.panel)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RimView(color: identity.rim, striped: identity.striped, glow: needsYou))
        .foregroundStyle(Brand.ink)
    }
}

/// The rim the client draws around a pane (mockups/panes.html): solid for a trusted silo; hatched,
/// with diagonal stripes along the top and bottom edges, for an untrusted (or unknown) one.
public struct RimView: View {
    let color: Color
    let striped: Bool
    let glow: Bool

    public init(color: Color, striped: Bool, glow: Bool = false) {
        self.color = color
        self.striped = striped
        self.glow = glow
    }

    public var body: some View {
        ZStack {
            if striped {
                RoundedRectangle(cornerRadius: 12).strokeBorder(color.opacity(0.9), style: StrokeStyle(lineWidth: 2, dash: [6, 6]))
                VStack(spacing: 0) {
                    Stripes(color: color).frame(height: 3)
                    Spacer()
                    Stripes(color: color).frame(height: 3)
                }
                .clipShape(RoundedRectangle(cornerRadius: 12))
            } else {
                RoundedRectangle(cornerRadius: 12).strokeBorder(color.opacity(0.85), lineWidth: 1.5)
            }
            if glow {
                RoundedRectangle(cornerRadius: 12).strokeBorder(Brand.amber.opacity(0.7), lineWidth: 3).blur(radius: 2)
            }
        }
        .allowsHitTesting(false)
    }
}

/// Diagonal stripes, 6 points on, 6 off (the mockup's repeating-linear-gradient at 45°).
struct Stripes: View {
    let color: Color
    var body: some View {
        Canvas { ctx, size in
            var x: CGFloat = -size.height
            while x < size.width + size.height {
                var p = Path()
                p.move(to: CGPoint(x: x, y: size.height))
                p.addLine(to: CGPoint(x: x + size.height, y: 0))
                p.addLine(to: CGPoint(x: x + size.height + 6, y: 0))
                p.addLine(to: CGPoint(x: x + 6, y: size.height))
                p.closeSubpath()
                ctx.fill(p, with: .color(color))
                x += 12
            }
        }
    }
}
