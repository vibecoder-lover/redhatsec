import SwiftUI

func outcomeColor(_ outcome: String) -> Color {
    if outcome.contains("executed") || outcome.contains("tool:") { return .ok }
    if outcome == "plan" { return .warn }
    return .bad
}

func outcomeMark(_ outcome: String) -> String {
    if outcome.contains("executed") || outcome.contains("tool:") { return "✓" }
    if outcome == "plan" { return "◌" }
    return "✕"
}

struct TargetsView: View {
    @EnvironmentObject var o: Orchestrator
    @State private var filter: Proto?
    @State private var selected: TargetDevice?
    @State private var dumpDetail: NFCDump?

    var filtered: [TargetDevice] {
        filter == nil ? o.targets : o.targets.filter { $0.proto == filter }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 12) {
                    filterChips
                    if o.targets.isEmpty { emptyState }
                    ForEach(filtered) { t in
                        TargetRow(t: t) {
                            withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) { selected = t }
                        }
                    }
                    nfcDumpsSection
                    attackLogSection
                }
                .padding(16)
            }
            .background(Color.bg.ignoresSafeArea())
            .navigationTitle("Targets — \(o.targets.count)")
            .sheet(item: $selected) { t in TargetDetailView(target: t) }
            .sheet(item: $dumpDetail) { d in NFCDumpDetail(dump: d) }
        }
    }

    private var filterChips: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                Chip(text: "TUTTI", active: filter == nil) { filter = nil }
                ForEach(Proto.allCases) { p in
                    let n = o.targets.filter { $0.proto == p }.count
                    if n > 0 {
                        Chip(text: "\(p.rawValue) (\(n))", active: filter == p) { filter = p }
                    }
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "antenna.radiowaves.left.and.right.slash")
                .font(.system(size: 42, weight: .light)).foregroundColor(.dim)
            Text("Nessun target").font(.headline)
            Text("Esegui uno scan dal tab Orchestrator.").font(.caption).foregroundColor(.dim)
        }
        .padding(.vertical, 30)
    }

    @ViewBuilder
    private var nfcDumpsSection: some View {
        if !o.nfcDumps.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                Text("NFC DUMPS — \(o.nfcDumps.count)").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundColor(.warn)
                ForEach(o.nfcDumps) { d in
                    Button {
                        Haptics.tap()
                        dumpDetail = d
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: "wave.3.right.circle.fill")
                                .font(.system(size: 22)).foregroundColor(.warn)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(d.title).font(.system(size: 13, weight: .bold, design: .rounded)).foregroundColor(.white)
                                Text("\(d.pages.count) pages · \(d.ndefHex.count) NDEF · \(DateFormatter.localizedString(from: d.date, dateStyle: .short, timeStyle: .short))")
                                    .font(.system(size: 10, design: .monospaced)).foregroundColor(.dim)
                            }
                            Spacer()
                            Image(systemName: "chevron.right").font(.caption).foregroundColor(.dim)
                        }
                        .padding(12).card()
                    }
                    .buttonStyle(ScaleButton())
                }
            }
        }
    }

    @ViewBuilder
    private var attackLogSection: some View {
        if !o.attackLog.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                Text("ATTACK LOG — \(o.attackLog.count)").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundColor(.redHat)
                ForEach(o.attackLog.reversed().prefix(20)) { a in
                    HStack(alignment: .top, spacing: 10) {
                        Circle()
                            .fill(outcomeColor(a.outcome))
                            .frame(width: 8, height: 8)
                            .padding(.top, 5)
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(a.vector).font(.system(size: 12, weight: .semibold)).foregroundColor(.white)
                                Spacer()
                                Text(DateFormatter.localizedString(from: a.date, dateStyle: .none, timeStyle: .short))
                                    .font(.system(size: 9, design: .monospaced)).foregroundColor(.dim)
                            }
                            Text("\(a.target) · \(a.outcome)").font(.system(size: 10, design: .monospaced)).foregroundColor(.dim)
                            if !a.evidence.isEmpty {
                                Text(a.evidence.prefix(110)).font(.system(size: 10, design: .monospaced)).foregroundColor(.ok.opacity(0.8)).lineLimit(2)
                            }
                        }
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 12).fill(Color.surfaceHi))
                }
            }
        }
    }
}

struct NFCDumpDetail: View {
    let dump: NFCDump
    @EnvironmentObject var o: Orchestrator
    @Environment(\.dismiss) var dismiss
    @State private var replaying = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Pill(text: dump.family, color: .warn)
                        Pill(text: "UID \(dump.uid)", color: .info)
                        Spacer()
                        Pill(text: DateFormatter.localizedString(from: dump.date, dateStyle: .short, timeStyle: .short), color: .dim)
                    }

                    if !dump.ndefText.isEmpty {
                        Text("NDEF RECORDS").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                        ForEach(Array(dump.ndefText.enumerated()), id: \.offset) { i, t in
                            VStack(alignment: .leading, spacing: 4) {
                                Text("rec \(i) — payload").font(.system(size: 9, design: .monospaced)).foregroundColor(.dim)
                                Text(t).font(.system(size: 12, design: .monospaced)).foregroundColor(.ok)
                                    .textSelection(.enabled)
                                Text("hex: \(dump.ndefHex.indices.contains(i) ? dump.ndefHex[i] : "?")")
                                    .font(.system(size: 10, design: .monospaced)).foregroundColor(.dim)
                                    .textSelection(.enabled)
                            }
                            .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                            .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                        }
                    }

                    Text("PAGES (\(dump.pages.count))").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                    ForEach(Array(dump.pages.enumerated()), id: \.offset) { i, p in
                        HStack(spacing: 8) {
                            Text(String(format: "%02d", i)).font(.system(size: 10, design: .monospaced)).foregroundColor(.warn)
                            Text(p).font(.system(size: 10, design: .monospaced)).foregroundColor(.white.opacity(0.85))
                                .textSelection(.enabled)
                            Spacer()
                        }
                    }

                    HStack(spacing: 10) {
                        Button {
                            Haptics.heavy()
                            replaying = true
                            o.replayDump(dump)
                            DispatchQueue.main.asyncAfter(deadline: .now() + 25) { replaying = false }
                        } label: {
                            Label(replaying ? "AVVICINA TAG…" : "REPLAY SU TAG", systemImage: replaying ? "wave.3.right" : "arrow.uturn.forward")
                                .font(.system(size: 13, weight: .bold, design: .rounded))
                                .frame(maxWidth: .infinity).padding(.vertical, 12)
                        }
                        .background(RoundedRectangle(cornerRadius: 12).fill(Color.redHat))
                        .foregroundColor(.white)
                        .buttonStyle(ScaleButton())
                        .disabled(replaying)

                        Button {
                            o.deleteDump(dump)
                            dismiss()
                        } label: {
                            Image(systemName: "trash")
                                .font(.system(size: 13)).padding(14)
                        }
                        .background(RoundedRectangle(cornerRadius: 12).fill(Color.surfaceHi))
                        .foregroundColor(.bad)
                        .buttonStyle(ScaleButton())
                    }
                }
                .padding(16)
            }
            .background(Color.bg.ignoresSafeArea())
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .navigationBarTrailing) { Button("chiudi") { dismiss() } } }
        }
        .preferredColorScheme(.dark)
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
                        if t.extra["autoArm"] == "1" {
                            Pill(text: "AUTO-ARM", color: .ok)
                        }
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
        return Int(Double(v + 95) / 65.0 * 4 + 0.5)
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

    private var relatedAttacks: [AttackRecord] {
        o.attackLog.filter { $0.target == target.name }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    header
                    reconSection
                    autoSection
                    if target.proto == .ble { bleConfig }
                    if target.proto == .net { netInfo }
                    planSection
                    if !relatedAttacks.isEmpty { attacksSection }
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
                if !["payload", "svcUUID", "chrUUID", "autoArm", "gatt", "banners", "mqtt",
                     "rtsp", "snmp", "telnet", "sec", "ch", "armNote", "uid", "family",
                     "dump", "open", "host"].contains(k) {
                    KV(k: k, val: target.extra[k] ?? "")
                }
            }
        }
        .padding(16).card()
    }

    private var autoSection: some View {
        Button {
            Haptics.heavy()
            Task { await o.autoPrepareTarget(target) }
        } label: {
            HStack(spacing: 8) {
                if o.prepBusy {
                    ProgressView().tint(.white)
                    Text("PREPARAZIONE…").font(.system(size: 13, weight: .bold, design: .rounded))
                } else {
                    Image(systemName: "wand.and.stars").font(.system(size: 13, weight: .bold))
                    Text("AUTO-PREPARE — CONFIG DA SOLO").font(.system(size: 13, weight: .bold, design: .rounded))
                }
            }
            .frame(maxWidth: .infinity).padding(.vertical, 12)
        }
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.redHat))
        .foregroundColor(.white)
        .buttonStyle(ScaleButton())
        .disabled(o.prepBusy)
    }

    private var bleConfig: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("BLE WRITE ARMING").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundColor(.warn)
                Spacer()
                if target.extra["autoArm"] == "1" { Pill(text: "AUTO-DETECTED", color: .ok) }
            }
            Text("Payload in hex scritto sulla characteristic. Auto-arm riempie svc/chr dal GATT dump; payload default 0100.")
                .font(.caption).foregroundColor(.dim)
            TextField("payload hex", text: $payloadHex)
                .textFieldStyle(.plain)
                .font(.system(size: 13, design: .monospaced))
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            TextField("service UUID", text: $svcUUID)
                .textFieldStyle(.plain)
                .font(.system(size: 13, design: .monospaced))
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            TextField("characteristic UUID", text: $chrUUID)
                .textFieldStyle(.plain)
                .font(.system(size: 13, design: .monospaced))
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
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
            KV(k: "open", val: target.extra["open"]?.isEmpty == false ? target.extra["open"]! : "nessuna")
            if let b = target.extra["banners"], !b.isEmpty {
                KV(k: "banners", val: b)
            }
        }
        .padding(16).card()
    }

    private var reconSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("RECON — Cosa posso fare davvero").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundColor(.info)
            switch target.proto {
            case .ble:
                if target.extra["autoArm"] == "1" {
                    KV(k: "write chr", val: target.extra["chrUUID"]?.prefix(12).description ?? "?")
                    KV(k: "service", val: target.extra["svcUUID"]?.prefix(12).description ?? "?")
                    KV(k: "payload", val: target.extra["payload"] ?? "0100")
                } else {
                    KV(k: "gatt", val: target.extra["gatt"]?.isEmpty == false ? target.extra["gatt"]! : "non enumerato — AUTO-PREPARE")
                }
                KV(k: "posso", val: "enum GATT · write · flood · malformed ATT (on-device)")
            case .net:
                let open = target.extra["open"]?.isEmpty == false ? target.extra["open"]! : "nessuna porta nota"
                KV(k: "porte aperte", val: open)
                if let b = target.extra["banners"], !b.isEmpty { KV(k: "banners", val: b) }
                KV(k: "posso", val: "probe MQTT/CoAP/SNMP/Modbus/RTSP/telnet-creds/UPnP (on-device)")
            case .wifi:
                KV(k: "bssid", val: target.mac ?? "?")
                KV(k: "security", val: target.extra["sec"] ?? "?")
                KV(k: "posso", val: "scan live · join open · args pronti per radio esterna")
            case .nfc:
                KV(k: "uid", val: target.extra["uid"] ?? "?")
                KV(k: "family", val: target.extra["family"] ?? "?")
                KV(k: "posso", val: "fingerprint · keys/PWD probe · NDEF inject · clone")
            default:
                KV(k: "proto", val: target.proto.rawValue)
            }
        }
        .padding(16).card()
    }

    private var planSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("ATTACCHI — \(relatedPlan.count) vettore(i)").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundColor(.dim)
                Spacer()
                Menu {
                    ForEach(addableVectors) { v in
                        Button(v.name) { o.addVectorToPlan(v.id, target: target) }
                    }
                } label: {
                    Label("aggiungi", systemImage: "plus.circle.fill")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.redHat)
                }
            }
            ForEach(relatedPlan) { e in
                planRow(e)
            }
            if relatedPlan.isEmpty {
                Text("nessun vettore — tocca \"aggiungi\" o AUTO-PREPARE").font(.caption).foregroundColor(.dim)
            }
        }
        .padding(16).card()
    }

    private var addableVectors: [AttackVector] {
        VectorDB.all().filter { $0.proto == target.proto }
            .filter { v in !relatedPlan.contains { $0.vector.id == v.id } }
    }

    private func planRow(_ e: PlanEntry) -> some View {
        HStack(spacing: 10) {
            Circle().fill(e.vector.sev.color).frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 3) {
                Text(e.vector.name).font(.system(size: 13, weight: .semibold)).foregroundColor(.white)
                Text(capLabel(e.vector)).font(.system(size: 10, design: .monospaced)).foregroundColor(.dim)
            }
            Spacer()
            Pill(text: statusLabel(e), color: statusColor(e))
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
            Button {
                Haptics.tap()
                o.removePlanEntry(e)
            } label: {
                Image(systemName: "minus.circle.fill")
                    .font(.system(size: 12))
                    .foregroundColor(.dim)
            }
            .buttonStyle(ScaleButton())
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.surfaceHi))
    }

    private func statusLabel(_ e: PlanEntry) -> String {
        switch e.vector.cap {
        case .plan: return "PLAN"
        case .shellTool(let t): return ShellRunner.shared.resolve(t) != nil ? "TOOL ✓" : "TOOL ✗"
        case .native:
            if e.vector.id == "ble_write" {
                return target.extra["chrUUID"]?.isEmpty == false ? "AUTO-ARMED" : "SERVE CONFIG"
            }
            return "READY"
        }
    }

    private func statusColor(_ e: PlanEntry) -> Color {
        switch e.vector.cap {
        case .plan: return .warn
        case .shellTool(let t): return ShellRunner.shared.resolve(t) != nil ? .ok : .bad
        case .native:
            if e.vector.id == "ble_write" && target.extra["chrUUID"]?.isEmpty != false { return .warn }
            return .ok
        }
    }

    private var attacksSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("ATTACCHI SU QUESTO TARGET").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundColor(.redHat)
            ForEach(relatedAttacks) { a in
                HStack(spacing: 8) {
                    Text(outcomeMark(a.outcome))
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(outcomeColor(a.outcome))
                    Text(a.vector).font(.system(size: 12)).foregroundColor(.white)
                    Spacer()
                    Text(DateFormatter.localizedString(from: a.date, dateStyle: .none, timeStyle: .short))
                        .font(.system(size: 9, design: .monospaced)).foregroundColor(.dim)
                }
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
