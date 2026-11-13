import SwiftUI

struct TargetsView: View {
    @EnvironmentObject var o: Orchestrator
    @State private var selected: TargetDevice?

    var body: some View {
        NavigationStack {
            Group {
                if o.targets.isEmpty {
                    emptyState
                } else {
                    ScrollView {
                        VStack(spacing: 10) {
                            ForEach(o.targets) { t in
                                TargetRow(t) { withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) { selected = t } }
                            }
                        }
                        .padding(16)
                    }
                }
            }
            .background(Color.bg.ignoresSafeArea())
            .navigationTitle("Targets — \(o.targets.count)")
            .sheet(item: $selected) { t in TargetDetailView(target: t) }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "antenna.radiowaves.left.and.right.slash")
                .font(.system(size: 42, weight: .light)).foregroundColor(.dim)
            Text("Nessun target").font(.headline)
            Text("Esegui uno scan dal tab Orchestrator.").font(.caption).foregroundColor(.dim)
        }
    }
}

struct TargetRow: View {
    let t: TargetDevice
    let tap: () -> Void
    var body: some View {
        Button(action: { Haptics.tap(); tap() }) {
            HStack(spacing: 12) {
                ZStack {
                    Circle().fill(protoColor(t.proto).opacity(0.15)).frame(width: 40, height: 40)
                    Image(systemName: t.proto.icon).font(.system(size: 16, weight: .semibold))
                        .foregroundColor(protoColor(t.proto))
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text(t.name).font(.system(size: 14, weight: .bold, design: .rounded))
                        .foregroundColor(.white).lineLimit(1)
                    HStack(spacing: 6) {
                        Text(t.via).font(.system(size: 10)).foregroundColor(.dim)
                        if let ports = t.extra["open"], !ports.isEmpty {
                            Text(ports).font(.system(size: 10, design: .monospaced)).foregroundColor(.ok)
                        }
                        if let sec = t.extra["sec"] {
                            Text(sec).font(.system(size: 10)).foregroundColor(.warn)
                        }
                    }
                }
                Spacer()
                RSSIMeter(rssi: t.rssi, color: protoColor(t.proto))
                Image(systemName: "chevron.right").font(.caption).foregroundColor(.dim)
            }
            .padding(14).card()
        }
        .buttonStyle(ScaleButton())
    }
}

struct RSSIMeter: View {
    let rssi: Int
    let color: Color
    var bars: Int {
        let v = max(-95, min(-30, rssi))
        return Int(Double(v + 95) / 65.0 * 4 + 0.5) // 1...4
    }
    var body: some View {
        HStack(alignment: .bottom, spacing: 2) {
            ForEach(1...4, id: \.self) { i in
                RoundedRectangle(cornerRadius: 1)
                    .fill(i <= bars ? color : Color.white.opacity(0.12))
                    .frame(width: 4, height: CGFloat(4 + i * 3))
            }
        }
        .animation(.spring(response: 0.4, dampingFraction: 0.8), value: bars)
    }
}

struct TargetDetailView: View {
    let target: TargetDevice
    @EnvironmentObject var o: Orchestrator
    @Environment(\.dismiss) var dismiss
    @State private var payloadHex = ""
    @State private var svcUUID = ""
    @State private var chrUUID = ""

    private var relatedPlan: [PlanEntry] {
        o.plan.filter { $0.target?.id == target.id }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    header
                    if target.proto == .ble { bleConfig }
                    if target.proto == .net { netInfo }
                    planSection
                }
                .padding(18)
            }
            .background(Color.bg.ignoresSafeArea())
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .navigationBarTrailing) { Button("chiudi") { dismiss() } } }
        }
        .preferredColorScheme(.dark)
        .onAppear {
            payloadHex = target.extra["payload"] ?? ""
            svcUUID = target.extra["svcUUID"] ?? ""
            chrUUID = target.extra["chrUUID"] ?? ""
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(target.name).font(.system(size: 21, weight: .heavy, design: .rounded))
                Spacer()
                RSSIMeter(rssi: target.rssi, color: protoColor(target.proto))
            }
            HStack(spacing: 8) {
                Pill(text: target.proto.rawValue, color: protoColor(target.proto))
                Pill(text: "via \(target.via)", color: .dim)
                if let v = target.vendor { Pill(text: v, color: .info) }
            }
            ForEach(Array(target.extra.keys.sorted()), id: \.self) { k in
                if !["payload", "svcUUID", "chrUUID"].contains(k) {
                    KV(k, target.extra[k] ?? "")
                }
            }
        }
        .padding(16).card()
    }

    private var bleConfig: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("BLE WRITE ARMING").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundColor(.warn)
            Text("Payload in hex scritto sulla characteristic (es. 0100 unlock). Campo vuoto = solo enumerazione.")
                .font(.caption).foregroundColor(.dim)
            TextField("payload hex", text: $payloadHex)
                .textFieldStyle(.rounded).font(.system(size: 13, design: .monospaced))
            TextField("service UUID (opz.)", text: $svcUUID)
                .textFieldStyle(.rounded).font(.system(size: 13, design: .monospaced))
            TextField("characteristic UUID (opz.)", text: $chrUUID)
                .textFieldStyle(.rounded).font(.system(size: 13, design: .monospaced))
            Button {
                Haptics.tap()
                if let idx = o.targets.firstIndex(where: { $0.id == target.id }) {
                    o.targets[idx].extra["payload"] = payloadHex
                    o.targets[idx].extra["svcUUID"] = svcUUID
                    o.targets[idx].extra["chrUUID"] = chrUUID
                }
            } label: {
                Text("salva arming").font(.system(size: 13, weight: .bold, design: .rounded))
                    .frame(maxWidth: .infinity).padding(.vertical, 10)
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.redHat))
            .foregroundColor(.white)
        }
        .padding(16).card()
    }

    private var netInfo: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("PORTS / BANNERS").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundColor(.info)
            KV("open", target.extra["open"]?.isEmpty == false ? target.extra["open"]! : "nessuna")
            if let b = target.extra["banners"], !b.isEmpty {
                KV("banners", b)
            }
        }
        .padding(16).card()
    }

    private var planSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("PLAN — \(relatedPlan.count) vector").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundColor(.dim)
            ForEach(relatedPlan) { e in
                HStack(spacing: 10) {
                    Circle().fill(e.vector.sev.color).frame(width: 8, height: 8)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(e.vector.name).font(.system(size: 13, weight: .semibold)).foregroundColor(.white)
                        Text(capLabel(e.vector)).font(.system(size: 10, design: .monospaced)).foregroundColor(.dim)
                    }
                    Spacer()
                    Button {
                        Haptics.heavy()
                        o.executeOnly(e)
                    } label: {
                        Image(systemName: "play.fill")
                            .font(.system(size: 12, weight: .bold))
                            .padding(9)
                            .background(Circle().fill(e.vector.sev.color.opacity(0.2)))
                            .overlay(Circle().strokeBorder(e.vector.sev.color.opacity(0.6), lineWidth: 1))
                            .foregroundColor(e.vector.sev.color)
                    }
                    .buttonStyle(ScaleButton())
                }
                .padding(12)
                .background(RoundedRectangle(cornerRadius: 12).fill(Color.surfaceHi))
            }
            if relatedPlan.isEmpty {
                Text("nessun vector matchato per questo target").font(.caption).foregroundColor(.dim)
            }
        }
        .padding(16).card()
    }

    private func capLabel(_ v: AttackVector) -> String {
        switch v.cap {
        case .native: return "native"
        case .shellTool(let t): return "tool: \(t)"
        case .plan: return "plan (hardware esterno)"
        }
    }
}
