import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var o: Orchestrator
    @State private var showConsole = false
    @State private var confirmExec = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    statusRow
                    RadarView(targets: o.targets, scanning: o.phase == .scan || o.phase == .enumerate)
                        .frame(height: 300)
                        .overlay(radarButton)
                    PhaseStepper(phase: o.phase)
                    statsRow
                    actionArea
                    recentLogs
                }
                .padding(16)
            }
            .background(Color.bg.ignoresSafeArea())
            .navigationTitle("RedHat Sec")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { showConsole = true } label: {
                        Image(systemName: "terminal")
                    }
                }
            }
            .sheet(isPresented: $showConsole) { ConsoleView() }
            .confirmationDialog("Eseguire il piano?", isPresented: $confirmExec, titleVisibility: .visible) {
                Button("Esegui (\(o.plan.count) step)", role: .destructive) { o.execute() }
                Button("Annulla", role: .cancel) {}
            } message: {
                Text("Scrive veramente sui device (GATT write, comandi di rete). Solo su target autorizzati.")
            }
        }
    }

    private var statusRow: some View {
        HStack(spacing: 8) {
            Pill(text: ShellRunner.shared.isJailbroken ? "JB OK" : "NO JB",
                 color: ShellRunner.shared.isJailbroken ? .ok : .bad)
            Pill(text: "tools: \(ShellRunner.shared.availableTools.count)", color: .info)
            Spacer()
            if o.phase == .execute {
                Pill(text: o.currentStep, color: .warn).shimmering()
            }
        }
    }

    private var radarButton: some View {
        Button {
            Haptics.heavy()
            switch o.phase {
            case .idle, .report: o.startScan()
            case .armed: confirmExec = true
            default: break
            }
        } label: {
            ZStack {
                Circle()
                    .fill(LinearGradient(colors: [.redHat, Color(hex: 0x8A0000)],
                                         startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 88, height: 88)
                    .glow(.redHat, radius: 16, on: o.phase != .idle)
                    .shadow(color: .black.opacity(0.5), radius: 8, y: 4)
                VStack(spacing: 2) {
                    Image(systemName: o.phase == .scan ? "dot.radiowaves.left.and.right" : "play.fill")
                        .font(.system(size: 20, weight: .bold))
                    Text(label).font(.system(size: 11, weight: .bold, design: .rounded))
                }
                .foregroundColor(.white)
            }
        }
        .buttonStyle(ScaleButton())
        .disabled(o.phase == .execute || o.phase == .enumerate || o.phase == .match)
        .animation(.spring(response: 0.4, dampingFraction: 0.7), value: o.phase)
    }

    private var label: String {
        switch o.phase {
        case .idle: return "SCAN"
        case .scan: return "SCAN…"
        case .enumerate, .match: return "…"
        case .armed: return "ESEGUI"
        case .execute: return "RUN"
        case .report: return "REPORT"
        }
    }

    private var statsRow: some View {
        HStack(spacing: 10) {
            StatCard(value: "\(o.targets.count)", label: "targets", color: .ok, icon: "sensor.tag.radiowaves.forward")
            StatCard(value: "\(o.plan.count)", label: "vectors", color: .warn, icon: "crosshair")
            StatCard(value: "\(o.findings.count)", label: "findings", color: .redHat, icon: "flag.2.crossed")
        }
    }

    @ViewBuilder
    private var actionArea: some View {
        if o.phase == .execute || o.phase == .scan || o.phase == .enumerate {
            VStack(spacing: 8) {
                HStack { Text(o.currentStep.isEmpty ? "working…" : o.currentStep).font(.footnote) ; Spacer() }
                GeometryReader { g in
                    ZStack(alignment: .leading) {
                        Capsule().fill(Color.surfaceHi)
                        Capsule()
                            .fill(LinearGradient(colors: [.redHat, .warn], startPoint: .leading, endPoint: .trailing))
                            .frame(width: max(12, g.size.width * o.progress))
                            .animation(.spring(response: 0.5, dampingFraction: 0.9), value: o.progress)
                    }
                }.frame(height: 8)
            }
            .padding(14).card()
        }
    }

    private var recentLogs: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("LIVE JOURNAL").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundColor(.dim)
                Spacer()
                Button("apri console") { showConsole = true }.font(.caption).foregroundColor(.redHat)
            }
            ForEach(o.logs.suffix(5)) { l in
                LogLine(l: l)
            }
            if o.logs.isEmpty {
                Text("journal vuoto — premi SCAN")
                    .font(.system(size: 12, design: .monospaced)).foregroundColor(.dim)
            }
        }
        .padding(14).card()
    }
}

struct RadarView: View {
    let targets: [TargetDevice]
    let scanning: Bool

    var body: some View {
        TimelineView(.animation) { timeline in
            Canvas { ctx, size in
                let c = CGPoint(x: size.width / 2, y: size.height / 2)
                let r = min(size.width, size.height) / 2 - 6
                let now = timeline.date.timeIntervalSinceReferenceDate

                for i in 1...3 {
                    let rr = r * CGFloat(i) / 3
                    ctx.stroke(Path(ellipseIn: CGRect(x: c.x - rr, y: c.y - rr, width: rr * 2, height: rr * 2)),
                               with: .color(.white.opacity(0.07)), lineWidth: 1)
                }

                let period = 2.6
                let frac = now.truncatingRemainder(dividingBy: period) / period
                for k in 0..<14 {
                    let a0 = Angle(degrees: Double(frac) * 360 - Double(k) * 3.2)
                    let a1 = Angle(degrees: Double(frac) * 360 - Double(k - 1) * 3.2)
                    let alpha = 0.30 * (1 - Double(k) / 14)
                    var wedge = Path()
                    wedge.move(to: c)
                    wedge.addArc(center: c, radius: r,
                                 startAngle: a0 - 90, endAngle: a1 - 90, clockwise: false)
                    ctx.fill(wedge, with: .color(.redHat.opacity(alpha)))
                }
                let edge = Path()
                edge.move(to: c)
                edge.addArc(center: c, radius: r,
                            startAngle: .degrees(Double(frac) * 360 - 90),
                            endAngle: .degrees(Double(frac) * 360 - 86), clockwise: false)
                ctx.stroke(edge, with: .color(.redHat.opacity(0.9)), lineWidth: 2)

                for (i, t) in targets.enumerated() {
                    let seed = abs(t.id.hashValue)
                    let angle = Angle(degrees: Double(seed % 360))
                    let dist = CGFloat(min(90, max(30, -t.rssi))) / 90
                    let rr = r * (0.25 + 0.65 * dist)
                    let pos = CGPoint(x: c.x + rr * cos(angle - 90),
                                      y: c.y + rr * sin(angle - 90))
                    let pulse = 0.5 + 0.5 * sin(now * 3 + Double(i) * 1.3)
                    let dot = Path(ellipseIn: CGRect(x: pos.x - 4 - pulse * 2, y: pos.y - 4 - pulse * 2,
                                                     width: 8 + pulse * 4, height: 8 + pulse * 4))
                    ctx.fill(dot, with: .color(protoColor(t.proto).opacity(0.85)))
                    let halo = Path(ellipseIn: CGRect(x: pos.x - 9 - pulse * 6, y: pos.y - 9 - pulse * 6,
                                                      width: 18 + pulse * 12, height: 18 + pulse * 12))
                    ctx.stroke(halo, with: .color(protoColor(t.proto).opacity(0.3 * (1 - pulse))), lineWidth: 1)
                }
            }
        }
        .background(
            RadialGradient(colors: [.surfaceHi, .bg], center: .center, startRadius: 10, endRadius: 170)
        )
        .overlay(
            Circle().strokeBorder(Color.white.opacity(0.05), lineWidth: 1).padding(2)
        )
        .clipShape(Circle())
        .card()
    }
}

func protoColor(_ p: Proto) -> Color {
    switch p {
    case .wifi: return .info
    case .ble, .classic: return .ok
    case .nfc, .rfid: return .warn
    case .zigbee, .zwave, .lora, .thread: return Color(hex: 0xB44DFF)
    case .net: return Color(hex: 0x4DFFE0)
    case .rf, .ir: return Color(hex: 0xFF7AB2)
    }
}

struct PhaseStepper: View {
    let phase: Phase
    var body: some View {
        HStack(spacing: 0) {
            ForEach(Phase.allCases) { p in
                VStack(spacing: 6) {
                    ZStack {
                        Circle()
                            .fill(p == phase ? Color.redHat : (phaseIdx(p) < phaseIdx(phase) ? Color.ok.opacity(0.8) : Color.surfaceHi))
                            .frame(width: 14, height: 14)
                            .glow(.redHat, radius: 8, on: p == phase)
                        if p == phase {
                            Circle().strokeBorder(Color.redHat.opacity(0.4), lineWidth: 1).frame(width: 22, height: 22)
                                .scaleEffect(1.0).animation(.easeOut(duration: 0.8).repeatForever(autoreverses: false), value: phase)
                        }
                    }
                    Text(p.label).font(.system(size: 8.5, weight: .semibold, design: .rounded))
                        .foregroundColor(p == phase ? .redHat : .dim)
                }
                .frame(maxWidth: .infinity)
                if p != Phase.allCases.last {
                    Rectangle().fill(Color.white.opacity(0.08)).frame(height: 1).padding(.bottom, 18)
                }
            }
        }
        .animation(.spring(response: 0.4, dampingFraction: 0.8), value: phase)
    }
    private func phaseIdx(_ p: Phase) -> Int { Phase.allCases.firstIndex(of: p)! }
}

struct StatCard: View {
    let value: String
    let label: String
    let color: Color
    let icon: String
    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: icon).font(.system(size: 13, weight: .bold)).foregroundColor(color)
            Text(value).font(.system(size: 24, weight: .heavy, design: .rounded))
            Text(label).font(.system(size: 10, weight: .semibold)).foregroundColor(.dim)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12).card()
    }
}

struct Pill: View {
    let text: String
    let color: Color
    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .bold, design: .rounded))
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(Capsule().fill(color.opacity(0.14)))
            .overlay(Capsule().strokeBorder(color.opacity(0.5), lineWidth: 1))
            .foregroundColor(color)
            .lineLimit(1)
    }
}

struct LogLine: View {
    let l: LogEntry
    var color: Color {
        switch l.level {
        case .info: return .dim
        case .warn: return .warn
        case .good: return .ok
        case .bad: return .bad
        case .exec: return .info
        }
    }
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Circle().fill(color).frame(width: 6, height: 6).padding(.top, 5)
            Text(l.text).font(.system(size: 11, design: .monospaced)).foregroundColor(.white.opacity(0.85))
            Spacer()
        }
    }
}

struct ConsoleView: View {
    @EnvironmentObject var o: Orchestrator

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 6) {
                        ForEach(o.logs) { l in LogLine(l: l).id(l.id) }
                    }.padding(12)
                }
                .background(Color(hex: 0x070709).ignoresSafeArea())
                .onChange(of: o.logs.count) { _ in
                    withAnimation { proxy.scrollTo(o.logs.last?.id, anchor: .bottom) }
                }
            }
            .navigationTitle("audit_journal")
            .navigationBarTitleDisplayMode(.inline)
        }
        .preferredColorScheme(.dark)
    }
}

struct ScaleButton: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.92 : 1)
            .animation(.spring(response: 0.3, dampingFraction: 0.6), value: configuration.isPressed)
    }
}
