import SwiftUI

struct NFCAttackView: View {
    @EnvironmentObject var o: Orchestrator
    @State private var tag: NFCTagFingerprint?
    @State private var armed: NFCTactic?
    @State private var phishURL = "https://example.com/catch?u="
    @State private var log: [LogEntry] = []
    @State private var busy = false

    struct NFCTactic: Identifiable {
        let id: String
        let name: String
        let brief: String
        let sev: Sev
        let needsConfig: Bool
        let executable: Bool
    }

    private var tactics: [NFCTactic] {
        guard let t = tag else { return [] }
        let inject = NFCTactic(id: "ndef_inject", name: "NDEF Injection",
                               brief: "Riscrive NDEF con URL tracker/phish — auto-open su Android.",
                               sev: .high, needsConfig: true, executable: t.ndefWritable)
        let clone = NFCTactic(id: "clone", name: "Clone su Magic Card",
                              brief: "Dump completo + replay su tag bersaglio (da Targets › NFC DUMPS).",
                              sev: .high, needsConfig: false, executable: true)
        switch t.family {
        case "Mifare Classic":
            // CoreNFC non espone l'auth Mifare Classic (0x60) in modo affidabile: keys/dump/clone = PoC fisico richiesto
            return [
                NFCTactic(id: "mifare_keys", name: "Default Keys Probe (PoC)",
                          brief: "CoreNFC non garantisce l'auth 0x60 su Classic — eseguibile solo come PoC su tag fisico.",
                          sev: .medium, needsConfig: false, executable: true),
                NFCTactic(id: "clone_plan", name: "Clone (PLAN — hardware)",
                          brief: "Dump+clone Classic richiedono Proxmark/PN532 via bridge BLE.",
                          sev: .info, needsConfig: false, executable: false),
                inject,
            ]
        case "NTAG/Ultralight":
            return [
                NFCTactic(id: "ntag_pwd", name: "PWD Dictionary Probe (PoC)",
                          brief: "PWD di fabbrica NTAG21x — comando 0x1B ISO14443-A da verificare su tag fisico.",
                          sev: .high, needsConfig: false, executable: true),
                inject, clone,
            ]
        case "DESFire":
            return [
                NFCTactic(id: "desfire_probe", name: "DESFire CoPP (PLAN)",
                          brief: "Crack CoPP richiede Proxmark/hardware dedicato — piano nel report.",
                          sev: .info, needsConfig: false, executable: false),
                NFCTactic(id: "ndef_inject", name: "NDEF Injection",
                          brief: "DESFire con NDEF app configurato — tentativo write.",
                          sev: .medium, needsConfig: true, executable: t.ndefWritable),
            ]
        default:
            return [inject, clone]
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                scanSection
                if let t = tag { tagCard(t) }
                if tag != nil {
                    Text("VETTORI CALIBRATI").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundColor(.dim)
                    ForEach(tactics) { tac in
                        tacticCard(tac)
                    }
                }
                if armed != nil { armBar }
                logSection
            }
            .padding(16)
        }
        .background(Color.bg.ignoresSafeArea())
    }

    private var scanSection: some View {
        Button {
            Haptics.heavy()
            Task { await runDetect() }
        } label: {
            Label(tag == nil ? "AVVICINA TAG — FINGERPRINT" : "NUOVO TAG",
                  systemImage: "wave.3.right.circle")
                .font(.system(size: 14, weight: .bold, design: .rounded))
                .frame(maxWidth: .infinity).padding(.vertical, 14)
        }
        .background(RoundedRectangle(cornerRadius: 14).fill(LinearGradient(colors: [.redHat, Color(hex: 0x8A0000)],
                                                                           startPoint: .topLeading, endPoint: .bottomTrailing)))
        .foregroundColor(.white)
        .buttonStyle(ScaleButton())
        .disabled(busy)
    }

    private func tagCard(_ t: NFCTagFingerprint) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(t.family).font(.system(size: 18, weight: .heavy, design: .rounded)).foregroundColor(.white)
                Spacer()
                Pill(text: t.ndefWritable ? "NDEF RW" : "NDEF RO", color: t.ndefWritable ? .ok : .warn)
            }
            KV(k: "UID", val: t.uid)
        }
        .padding(14).card()
        .transition(.asymmetric(insertion: .scale(scale: 0.9).combined(with: .opacity), removal: .opacity))
    }

    private func tacticCard(_ tac: NFCTactic) -> some View {
        Button {
            Haptics.tap()
            if tac.executable { armed = (armed?.id == tac.id) ? nil : tac }
        } label: {
            HStack(spacing: 10) {
                Circle().fill(tac.sev.color).frame(width: 9, height: 9)
                    .glow(tac.sev.color, radius: 4)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(tac.name).font(.system(size: 13, weight: .bold, design: .rounded)).foregroundColor(.white)
                        if !tac.executable { Pill(text: "PLAN", color: .warn) }
                        if tac.id == armed?.id { Pill(text: "ARMED", color: .redHat) }
                    }
                    Text(tac.brief).font(.system(size: 11)).foregroundColor(.dim)
                }
                Spacer()
                Image(systemName: tac.id == armed?.id ? "checkmark.circle.fill" : "crosshair")
                    .font(.system(size: 13))
                    .foregroundColor(tac.id == armed?.id ? .redHat : .dim)
            }
            .padding(12)
            .background(RoundedRectangle(cornerRadius: 14).fill(tac.id == armed?.id ? Color.surfaceHi : Color.surface))
            .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(tac.id == armed?.id ? Color.redHat.opacity(0.6) : Color.white.opacity(0.07), lineWidth: 1))
        }
        .buttonStyle(ScaleButton())
    }

    @ViewBuilder
    private var armBar: some View {
        VStack(alignment: .leading, spacing: 8) {
            if armed?.needsConfig == true {
                Text("PAYLOAD URL").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                TextField("https://...", text: $phishURL)
                    .textFieldStyle(.plain).font(.system(size: 13, design: .monospaced))
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                    .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            }
            Button {
                Haptics.heavy()
                if let a = armed { Task { await execute(a) } }
            } label: {
                Label(busy ? "IN ATTESA TAG…" : "RIAVVICINA TAG PER ATTACCARE",
                      systemImage: busy ? "wave.3.right" : "bolt.fill")
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .frame(maxWidth: .infinity).padding(.vertical, 13)
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(armed?.id == "clone" ? Color.surfaceHi : Color.redHat))
            .foregroundColor(.white)
            .buttonStyle(ScaleButton())
            .disabled(busy)
        }
        .padding(14).card()
    }

    private func logColor(_ lvl: LogEntry.Level) -> Color {
        switch lvl {
        case .good: return .ok
        case .bad: return .bad
        case .exec: return .redHat
        default: return .dim
        }
    }

    private var logSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            if !log.isEmpty {
                Text("SESSION LOG").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                ForEach(Array(log.suffix(12))) { l in
                    HStack(alignment: .top, spacing: 8) {
                        Circle().fill(logColor(l.level))
                            .frame(width: 6, height: 6).padding(.top, 5)
                        Text(l.text).font(.system(size: 11, design: .monospaced)).foregroundColor(.white.opacity(0.85))
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func runDetect() async {
        busy = true
        let info = await o.nfc.detect()
        await MainActor.run {
            busy = false
            withAnimation(.spring(response: 0.4, dampingFraction: 0.8)) {
                tag = info
                armed = nil
            }
            if let i = info {
                o.recordAttack(vectorID: "nfc_detect", vector: "NFC Fingerprint", target: "NFC \(i.uid.prefix(10))",
                               outcome: "executed", evidence: "family=\(i.family) ndefRW=\(i.ndefWritable)")
            } else {
                log.append(LogEntry(level: .warn, text: "nessun tag letto"))
            }
        }
    }

    private func execute(_ tac: NFCTactic) async {
        guard let t = tag else { return }
        busy = true
        log.append(LogEntry(level: .exec, text: "ARM \(tac.name) — riavvicina il tag"))
        if tac.id == "clone" {
            if let d = o.nfcDumps.first(where: { t.uid.hasPrefix($0.uid) }) {
                o.replayDump(d)
                log.append(LogEntry(level: .good, text: "replay lanciato — avvicina il tag target (vedi Targets › NFC DUMPS)"))
            } else {
                log.append(LogEntry(level: .warn, text: "dump mancante per \(t.uid.prefix(10)) — fai prima un DUMP"))
            }
            busy = false
            return
        }
        let lines = await o.nfc.attack(tac.id, config: ["url": phishURL])
        await MainActor.run {
            for l in lines {
                self.log.append(LogEntry(level: l.contains("✓") || l.contains("FOUND") ? .good : (l.contains("FAIL") ? .bad : .info), text: l))
            }
            let hit = lines.contains { $0.contains("✓") || $0.contains("FOUND") }
            o.recordAttack(vectorID: tac.id, vector: tac.name, target: "NFC \(t.uid.prefix(10))",
                           outcome: hit ? "executed" : "failed", evidence: lines.joined(separator: " | "))
            busy = false
            Haptics.win()
        }
    }
}
