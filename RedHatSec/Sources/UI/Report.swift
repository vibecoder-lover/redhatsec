import SwiftUI
import WebKit

struct ReportView: View {
    @EnvironmentObject var o: Orchestrator
    @State private var preview = false

    var body: some View {
        NavigationStack {
            Group {
                if let rep = o.report {
                    content(rep)
                } else {
                    empty
                }
            }
            .background(Color.bg.ignoresSafeArea())
            .navigationTitle("Report")
            .fullScreenCover(isPresented: $preview) {
                if let url = o.reportURL { HTMLPreview(url: url) }
            }
        }
    }

    private var empty: some View {
        VStack(spacing: 14) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 42, weight: .light)).foregroundColor(.dim)
            Text("Nessun report").font(.headline)
            Text("Scan → Execute → il report si genera qui.").font(.caption).foregroundColor(.dim)
        }
    }

    private func content(_ rep: Report) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(rep.title).font(.system(size: 19, weight: .heavy, design: .rounded))
                    Text("\(rep.targets.count) targets · \(rep.findings.count) findings · \(DateFormatter.localizedString(from: rep.date, dateStyle: .medium, timeStyle: .short))")
                        .font(.caption).foregroundColor(.dim)
                }
                .padding(16).card()

                severityBars(rep)

                ForEach(rep.findings.sorted { $0.sev < $1.sev }) { f in
                    FindingCard(f: f)
                }

                exportRow
            }
            .padding(16)
        }
    }

    private func severityBars(_ rep: Report) -> some View {
        var counts: [Sev: Int] = [:]
        for f in rep.findings { counts[f.sev, default: 0] += 1 }
        let maxC = max(1, counts.values.max() ?? 1)
        return VStack(alignment: .leading, spacing: 8) {
            Text("SEVERITY DISTRIBUTION").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundColor(.dim)
            ForEach(Sev.allCases) { s in
                HStack(spacing: 10) {
                    Text(s.rawValue).font(.system(size: 11, design: .monospaced))
                        .frame(width: 64, alignment: .leading).foregroundColor(s.color)
                    GeometryReader { g in
                        ZStack(alignment: .leading) {
                            Capsule().fill(Color.surfaceHi)
                            Capsule().fill(s.color)
                                .frame(width: g.size.width * CGFloat(counts[s] ?? 0) / CGFloat(maxC))
                                .animation(.spring(response: 0.6, dampingFraction: 0.85), value: counts[s])
                        }
                    }.frame(height: 10)
                    Text("\(counts[s] ?? 0)").font(.system(size: 11, design: .monospaced)).foregroundColor(.dim)
                        .frame(width: 24)
                }
            }
        }
        .padding(16).card()
    }

    private var exportRow: some View {
        HStack(spacing: 10) {
            if let htmlURL = o.reportURL {
                ShareLink(item: htmlURL) {
                    Label("HTML", systemImage: "square.and.arrow.up")
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .frame(maxWidth: .infinity).padding(.vertical, 12)
                }
                .background(RoundedRectangle(cornerRadius: 12).fill(Color.redHat))
                .foregroundColor(.white)
            }
            Button {
                Haptics.tap()
                if let rep = o.report { _ = ReportBuilder.pdf(rep) }
            } label: {
                Label("PDF", systemImage: "doc.badge.plus")
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .frame(maxWidth: .infinity).padding(.vertical, 12)
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.surfaceHi))
            .foregroundColor(.white)
        }
        .buttonStyle(ScaleButton())
    }
}

struct FindingCard: View {
    let f: Finding
    @State private var open = false
    var body: some View {
        Button { withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) { open.toggle() } } label: {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    Circle().fill(f.sev.color).frame(width: 9, height: 9)
                        .glow(f.sev.color, radius: 5)
                    Text(f.title).font(.system(size: 14, weight: .bold, design: .rounded))
                        .foregroundColor(.white).multilineTextAlignment(.leading)
                    Spacer()
                    Image(systemName: open ? "chevron.up" : "chevron.down")
                        .font(.caption2).foregroundColor(.dim)
                }
                HStack(spacing: 6) {
                    Pill(text: f.sev.rawValue.uppercased(), color: f.sev.color)
                    Pill(text: "CVSS \(String(format: "%.1f", f.cvss))", color: .dim)
                    Pill(text: f.attack, color: .info)
                    Spacer()
                    Text(f.target).font(.system(size: 10, design: .monospaced)).foregroundColor(.dim)
                        .lineLimit(1)
                }
                if open {
                    Text("EVIDENCE").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                    Text(f.evidence).font(.system(size: 11, design: .monospaced))
                        .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                        .foregroundColor(.ok)
                        .lineLimit(14)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("REPRO").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                        ForEach(f.repro, id: \.self) { r in
                            HStack(alignment: .top, spacing: 6) {
                                Text("▸").font(.caption2).foregroundColor(f.sev.color)
                                Text(r).font(.system(size: 11, design: .monospaced)).foregroundColor(.white.opacity(0.85))
                            }
                        }
                        Text("IMPACT").font(.system(size: 10, weight: .bold)).foregroundColor(.dim).padding(.top, 4)
                        Text(f.impact).font(.footnote).foregroundColor(.white.opacity(0.8))
                        Text("REMEDIATION").font(.system(size: 10, weight: .bold)).foregroundColor(.dim).padding(.top, 4)
                        Text(f.remediation).font(.footnote).foregroundColor(.white.opacity(0.8))
                    }
                }
            }
            .padding(14).card()
        }
        .buttonStyle(.plain)
    }
}

struct HTMLPreview: UIViewRepresentable {
    let url: URL
    func makeUIView(context: Context) -> WKWebView {
        let w = WKWebView()
        w.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        return w
    }
    func updateUIView(_ uiView: WKWebView, context: Context) {}
}
