import SwiftUI

struct CatalogView: View {
    @EnvironmentObject var o: Orchestrator
    @State private var filter: Proto?
    @State private var query = ""
    @State private var selected: AttackVector?

    private let vectors = VectorDB.all()

    var filtered: [AttackVector] {
        vectors.filter { v in
            (filter == nil || v.proto == filter) &&
            (query.isEmpty || v.name.lowercased().contains(query.lowercased())
                || v.ref.lowercased().contains(query.lowercased())
                || v.id.lowercased().contains(query.lowercased()))
        }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    chips
                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                        ForEach(filtered) { v in
                            VectorCard(v: v) { withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) { selected = v } }
                        }
                    }
                }
                .padding(16)
            }
            .background(Color.bg.ignoresSafeArea())
            .navigationTitle("\(vectors.count) vectors")
            .searchable(text: $query, prompt: "nome, CVE, id…")
            .sheet(item: $selected) { v in VectorDetailSheet(v: v) }
        }
    }

    private var chips: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                Chip(text: "TUTTI", active: filter == nil) { filter = nil }
                ForEach(Proto.allCases) { p in
                    Chip(text: p.rawValue.uppercased(), active: filter == p) { filter = p }
                }
            }.padding(.horizontal, 2)
        }
    }
}

struct Chip: View {
    let text: String
    let active: Bool
    let action: () -> Void
    var body: some View {
        Button(action: { Haptics.tap(); action() }) {
            Text(text)
                .font(.system(size: 11, weight: .bold, design: .rounded))
                .padding(.horizontal, 12).padding(.vertical, 7)
                .background(Capsule().fill(active ? Color.redHat : Color.surface))
                .overlay(Capsule().strokeBorder(active ? .clear : Color.white.opacity(0.1), lineWidth: 1))
                .foregroundColor(active ? .white : .dim)
        }
        .buttonStyle(ScaleButton())
    }
}

struct VectorCard: View {
    let v: AttackVector
    let tap: () -> Void
    var body: some View {
        Button(action: { Haptics.tap(); tap() }) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Image(systemName: v.proto.icon).font(.system(size: 12, weight: .bold))
                        .foregroundColor(protoColor(v.proto))
                    Spacer()
                    Circle().fill(v.sev.color).frame(width: 8, height: 8)
                        .glow(v.sev.color, radius: 5)
                }
                Text(v.name).font(.system(size: 13, weight: .bold, design: .rounded))
                    .lineLimit(2).multilineTextAlignment(.leading)
                    .foregroundColor(.white)
                Spacer(minLength: 0)
                HStack(spacing: 6) {
                    Text(v.ref).font(.system(size: 9, design: .monospaced)).foregroundColor(.dim).lineLimit(1)
                    Spacer()
                    Text(String(format: "%.1f", v.cvss)).font(.system(size: 10, weight: .heavy))
                        .foregroundColor(v.sev.color)
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, minHeight: 92, alignment: .topLeading)
            .background(RoundedRectangle(cornerRadius: 16).fill(Color.surface))
            .overlay(RoundedRectangle(cornerRadius: 16)
                .strokeBorder(v.sev.color.opacity(0.25), lineWidth: 1))
        }
        .buttonStyle(ScaleButton())
    }
}

struct VectorDetailSheet: View {
    let v: AttackVector
    @Environment(\.dismiss) var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Text(v.sev.rawValue.uppercased())
                            .font(.system(size: 11, weight: .heavy, design: .rounded))
                            .padding(.horizontal, 10).padding(.vertical, 5)
                            .background(Capsule().fill(v.sev.color.opacity(0.15)))
                            .overlay(Capsule().strokeBorder(v.sev.color.opacity(0.6), lineWidth: 1))
                            .foregroundColor(v.sev.color)
                        Spacer()
                        capBadge
                    }
                    Text(v.name).font(.system(size: 22, weight: .heavy, design: .rounded))
                    HStack(spacing: 8) {
                        Pill(text: v.proto.rawValue, color: protoColor(v.proto))
                        Pill(text: "\(v.year)", color: .dim)
                        Pill(text: "ATT&CK \(v.attack)", color: .info)
                    }
                    KV(k: "Reference", val: v.ref)
                    KV(k: "CVSS", val: String(format: "%.1f — %@", v.cvss, v.cvssVec))
                    KV(k: "Prerequisiti", val: v.prereq)
                    Text(v.brief).font(.body).foregroundColor(.white.opacity(0.9))
                    Text("EXEC").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                    Text(v.hint).font(.system(size: 12, design: .monospaced))
                        .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.08), lineWidth: 1))
                        .foregroundColor(.ok)
                    Text("REMEDIATION").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                    Text(v.remediation).font(.footnote).foregroundColor(.white.opacity(0.75))
                }
                .padding(18)
            }
            .background(Color.bg.ignoresSafeArea())
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("chiudi") { dismiss() }
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private var capBadge: some View {
        let (text, color): (String, Color) = {
            switch v.cap {
            case .native: return ("NATIVE", .ok)
            case .shellTool(let t): return ("TOOL:\(t)", .info)
            case .plan: return ("PLAN", .warn)
            }
        }()
        return Pill(text: text, color: color)
    }
}

struct KV: View {
    let k: String
    let val: String
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(k.uppercased()).font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
            Text(val).font(.system(size: 12, design: .monospaced)).foregroundColor(.white.opacity(0.85))
        }
    }
}
