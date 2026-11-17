import SwiftUI
import UIKit

extension Color {
    init(hex: UInt32, alpha: Double = 1) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xff) / 255,
                  green: Double((hex >> 8) & 0xff) / 255,
                  blue: Double(hex & 0xff) / 255,
                  opacity: alpha)
    }
    static let redHat = Color(hex: 0xEE0000)
    static let bg = Color(hex: 0x0A0A0C)
    static let surface = Color(hex: 0x141418)
    static let surfaceHi = Color(hex: 0x1D1D23)
    static let ok = Color(hex: 0x2EE59D)
    static let warn = Color(hex: 0xFFB020)
    static let bad = Color(hex: 0xFF453A)
    static let info = Color(hex: 0x4DA6FF)
    static let dim = Color(hex: 0x8A8A93)
}

enum Sev: String, Codable, CaseIterable, Comparable, Identifiable {
    case critical, high, medium, low, info
    var id: String { rawValue }
    var color: Color {
        switch self {
        case .critical: return .redHat
        case .high: return .bad
        case .medium: return .warn
        case .low: return .info
        case .info: return .dim
        }
    }
    private var rank: Int { Sev.allCases.firstIndex(of: self)! }
    static func < (l: Sev, r: Sev) -> Bool { l.rank < r.rank } // critical-first coerente con rank
}

enum Haptics {
    static func tap() { UIImpactFeedbackGenerator(style: .light).impactOccurred() }
    static func heavy() { UIImpactFeedbackGenerator(style: .heavy).impactOccurred() }
    static func win() { UINotificationFeedbackGenerator().notificationOccurred(.success) }
    static func fail() { UINotificationFeedbackGenerator().notificationOccurred(.error) }
}

struct CardBG: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: RH.radius, style: .continuous)
                    .fill(LinearGradient(colors: [Color.surfaceHi, Color.surface],
                                         startPoint: .topLeading, endPoint: .bottomTrailing))
                    .shadow(color: .black.opacity(0.35), radius: 12, y: 8)
            )
            .overlay(
                RoundedRectangle(cornerRadius: RH.radius, style: .continuous)
                    .strokeBorder(
                        LinearGradient(colors: [Color.white.opacity(0.10), Color.white.opacity(0.03)],
                                       startPoint: .top, endPoint: .bottom),
                        lineWidth: 1)
            )
    }
}

extension View {
    func card() -> some View { modifier(CardBG()) }

    func glow(_ color: Color, radius: CGFloat = 12, on: Bool = true) -> some View {
        shadow(color: on ? color.opacity(0.55) : .clear, radius: radius)
    }
}

struct Shimmer: ViewModifier {
    @State private var phase: CGFloat = -1
    func body(content: Content) -> some View {
        content
            .overlay(
                GeometryReader { g in
                    LinearGradient(colors: [.clear, .white.opacity(0.25), .clear],
                                   startPoint: .leading, endPoint: .trailing)
                        .frame(width: g.size.width * 0.6)
                        .offset(x: phase * g.size.width * 1.6)
                        .blendMode(.plusLighter)
                }
                .allowsHitTesting(false)
            )
            .clipped()
            .onAppear {
                withAnimation(.linear(duration: 1.4).repeatForever(autoreverses: false)) {
                    phase = 1
                }
            }
    }
}

extension View {
    func shimmering() -> some View { modifier(Shimmer()) }
}

// MARK: - Design tokens

enum RH {
    static let pad: CGFloat = 16
    static let gap: CGFloat = 14
    static let radius: CGFloat = 18
    static let radiusSm: CGFloat = 12
}

extension Font {
    static func rhsTitle(_ size: CGFloat = 15) -> Font { .system(size: size, weight: .heavy, design: .rounded) }
    static func rhsBody(_ size: CGFloat = 14) -> Font { .system(size: size, weight: .semibold, design: .rounded) }
    static func rhsCaption(_ size: CGFloat = 11) -> Font { .system(size: size, weight: .semibold, design: .rounded) }
    static func rhsMono(_ size: CGFloat = 11) -> Font { .system(size: size, weight: .medium, design: .monospaced) }
}

// MARK: - App chrome (nav bar / tab bar)

enum RHAppearance {
    static func configure() {
        let bg = UIColor(Color.bg)
        let surface = UIColor(Color.surface)
        let accent = UIColor(Color.redHat)

        let nav = UINavigationBarAppearance()
        nav.configureWithOpaqueBackground()
        nav.backgroundColor = bg
        nav.shadowColor = .clear
        nav.titleTextAttributes = [.foregroundColor: UIColor.white]
        nav.largeTitleTextAttributes = [.foregroundColor: UIColor.white]
        UINavigationBar.appearance().standardAppearance = nav
        UINavigationBar.appearance().scrollEdgeAppearance = nav
        UINavigationBar.appearance().compactAppearance = nav
        UINavigationBar.appearance().tintColor = accent

        let tab = UITabBarAppearance()
        tab.configureWithOpaqueBackground()
        tab.backgroundColor = surface
        tab.shadowColor = UIColor.white.withAlphaComponent(0.08)
        for item in [tab.stackedLayoutAppearance, tab.inlineLayoutAppearance, tab.compactInlineLayoutAppearance] {
            item.selected.iconColor = accent
            item.selected.titleTextAttributes = [.foregroundColor: accent]
            item.normal.iconColor = UIColor(Color.dim)
            item.normal.titleTextAttributes = [.foregroundColor: UIColor(Color.dim)]
        }
        UITabBar.appearance().standardAppearance = tab
        UITabBar.appearance().scrollEdgeAppearance = tab
    }
}

// MARK: - Shared components

// sfondo comune: nero + due aloni radiali (rosso in alto, blu in basso)
struct RHBackground: View {
    var body: some View {
        ZStack {
            Color.bg
            RadialGradient(colors: [Color.redHat.opacity(0.14), .clear],
                           center: .topLeading, startRadius: 8, endRadius: 430)
            RadialGradient(colors: [Color.info.opacity(0.08), .clear],
                           center: .bottomTrailing, startRadius: 8, endRadius: 380)
        }
        .ignoresSafeArea()
    }
}

struct SectionHeader: View {
    let title: String
    var icon: String? = nil
    var color: Color = .dim
    var trailing: String? = nil
    var body: some View {
        HStack(spacing: 7) {
            if let icon {
                Image(systemName: icon).font(.system(size: 11, weight: .heavy)).foregroundColor(color)
            }
            Text(title.uppercased())
                .font(.system(size: 11, weight: .heavy, design: .rounded))
                .tracking(0.8)
                .foregroundColor(color)
            Rectangle().fill(Color.white.opacity(0.07)).frame(height: 1)
            if let trailing {
                Text(trailing).font(.rhsMono(10)).foregroundColor(.dim)
            }
        }
    }
}

struct EmptyState: View {
    let icon: String
    let title: String
    var subtitle: String? = nil
    var actionTitle: String? = nil
    var action: (() -> Void)? = nil
    var body: some View {
        VStack(spacing: 14) {
            ZStack {
                Circle().fill(Color.surfaceHi).frame(width: 84, height: 84)
                Circle().strokeBorder(Color.white.opacity(0.06), lineWidth: 1).frame(width: 84, height: 84)
                Image(systemName: icon).font(.system(size: 34, weight: .light)).foregroundColor(.dim)
            }
            Text(title).font(.system(size: 17, weight: .heavy, design: .rounded))
            if let subtitle {
                Text(subtitle).font(.rhsCaption(12)).foregroundColor(.dim)
                    .multilineTextAlignment(.center).padding(.horizontal, 24)
            }
            if let actionTitle, let action {
                Button {
                    Haptics.tap(); action()
                } label: {
                    Text(actionTitle)
                        .font(.system(size: 13, weight: .heavy, design: .rounded))
                        .padding(.horizontal, 18).padding(.vertical, 10)
                        .background(Capsule().fill(Color.redHat))
                        .foregroundColor(.white)
                }
                .buttonStyle(ScaleButton())
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 36)
    }
}
