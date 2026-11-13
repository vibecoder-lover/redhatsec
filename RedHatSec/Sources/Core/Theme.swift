import SwiftUI

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
    static func < (l: Sev, r: Sev) -> Bool { l.rank > r.rank }
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
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .fill(Color.surface)
                    .shadow(color: .black.opacity(0.4), radius: 10, y: 6)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.07), lineWidth: 1)
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
