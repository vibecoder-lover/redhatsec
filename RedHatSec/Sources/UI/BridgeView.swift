import SwiftUI

struct BridgeView: View {
    @ObservedObject var ble: BridgeManager
    @ObservedObject var tcp: TCPBridge
    @State private var spamText = "FreeWiFi,Hotel_Guest"
    @State private var scanning = false
    @State private var manualIP = ""
    @State private var rawHex = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            tcpSection
            joinSection
            actionsSection
            netsSection
            rawSection
            logSection
        }
        .onAppear { tcp.startAutoConnect() }
    }

    @State private var targetSSID = ""
    @State private var targetPass = ""
    @State private var joining = false

    private var joinSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("RETE TARGET — la radio dell'ESP attacca qui").font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
            TextField("SSID rete target", text: $targetSSID)
                .textFieldStyle(.plain).font(.system(size: 12, design: .monospaced))
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            TextField("password (opzionale per OPEN)", text: $targetPass)
                .textFieldStyle(.plain).font(.system(size: 12, design: .monospaced))
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            Button {
                guard !joining else { return }
                Haptics.heavy(); joining = true
                Task {
                    // timeout 20s ma il re-entry resta bloccato finché il join reale non finisce
                    let j = Task { await tcp.joinTarget(targetSSID, targetPass) }
                    let ok = await withTaskGroup(of: Bool.self) { group -> Bool in
                        group.addTask { await j.value }
                        group.addTask {
                            try? await Task.sleep(nanoseconds: 20_000_000_000)
                            return false
                        }
                        let first = await group.next() ?? false
                        group.cancelAll()
                        return first
                    }
                    let real = await j.value
                    joining = false
                    if !(ok || real) { tcp.log("join \(targetSSID): timeout o negato") }
                }
            } label: {
                Label(joining ? "JOIN…" : "JOIN RETE TARGET", systemImage: "arrow.turn.right.down")
                    .frame(maxWidth: .infinity).padding(.vertical, 11)
                    .font(.system(size: 13, weight: .bold, design: .rounded))
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.info.opacity(0.3)))
            .foregroundColor(.info)
            .buttonStyle(ScaleButton())
            .disabled(joining || !tcp.connected || targetSSID.isEmpty)
            Text("AP+STA: il bridge resta connesso all'app e la STA entra nella rete target — scan/port/MQTT/SNMP/telnet girano dalla radio dell'ESP.")
                .font(.caption2).foregroundColor(.dim)
        }
        .padding(14).card()
    }

    private var tcpSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("ESP8266 BRIDGE").font(.system(size: 16, weight: .heavy, design: .rounded)).foregroundColor(.white)
                Spacer()
                Pill(text: tcp.connected ? "ONLINE" : (tcp.state.hasPrefix("auto") ? "RICERCA…" : "OFFLINE"),
                     color: tcp.connected ? .ok : (tcp.state.hasPrefix("auto") ? .warn : .bad))
            }
            KV(k: "stato", val: tcp.state)
            KV(k: "rete", val: "STA: l'ESP entra nel tuo hotspot (Hexxeted) → sweep 172.20.10.2-14 o IP manuale")
            if tcp.connected {
                KV(k: "stato radio", val: "i vettori PLAN (deauth/PMKID/beacon) sono eseguibili")
            }
            if !tcp.connected {
                Text("Modifica STA_SSID/STA_PASS nel firmware col nome della TUA hotspot, flasha: l'ESP entra nella rete e l'app lo trova con lo sweep, da sola.")
                    .font(.caption2).foregroundColor(.dim)
            }
            HStack(spacing: 8) {
                TextField("IP manuale (default 192.168.4.1)", text: $manualIP)
                    .textFieldStyle(.plain).font(.system(size: 12, design: .monospaced))
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                    .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
                Button {
                    Haptics.heavy()
                    let ip = manualIP.trimmingCharacters(in: .whitespaces)
                    tcp.connect(host: ip.isEmpty ? "192.168.4.1" : ip)
                } label: {
                    Image(systemName: "arrow.right.circle.fill").foregroundColor(.redHat)
                }
                .buttonStyle(ScaleButton())
            }
        }
        .padding(14).card()
    }

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeader(title: "Azioni radio", icon: "dot.radiowaves.left.and.right", color: .redHat)
            Button {
                Haptics.heavy(); scanning = true
                CrashTracer.mark("bridge scan tap tcp=\(tcp.connected) ble=\(ble.connected)")
                Task {
                    if ble.connected { _ = await ble.wifiScan() } else { _ = await tcp.wifiScan() }
                    scanning = false
                    CrashTracer.mark("bridge scan flow done")
                }
            } label: {
                Label(scanning ? "SCAN IN CORSO…" : "WIFI SCAN (via bridge)", systemImage: "dot.radiowaves.left.and.right")
                    .frame(maxWidth: .infinity).padding(.vertical, 12)
                    .font(.system(size: 13, weight: .bold, design: .rounded))
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.surfaceHi))
            .foregroundColor(.white)
            .buttonStyle(ScaleButton())
            .disabled(scanning || (!ble.connected && !tcp.connected))

            TextField("SSID spam (virgole)", text: $spamText)
                .textFieldStyle(.plain).font(.system(size: 12, design: .monospaced))
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            Button {
                Haptics.heavy()
                let ssids = spamText.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) }
                Task {
                    if ble.connected { _ = await ble.beaconSpam(ssids: ssids) } else { _ = await tcp.beaconSpam(ssids: ssids) }
                }
            } label: {
                Label("BEACON SPAM", systemImage: "tower.broadcast")
                    .frame(maxWidth: .infinity).padding(.vertical, 12)
                    .font(.system(size: 13, weight: .bold, design: .rounded))
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.warn.opacity(0.25)))
            .foregroundColor(.warn)
            .buttonStyle(ScaleButton())
            .disabled(!ble.connected && !tcp.connected)

            Button {
                Haptics.tap()
                ble.stopAll()
                tcp.stopAll()
            } label: {
                Label("STOP TUTTO", systemImage: "stop.circle")
                    .frame(maxWidth: .infinity).padding(.vertical, 10)
                    .font(.system(size: 12, weight: .bold))
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.bad.opacity(0.2)))
            .foregroundColor(.bad)
            .buttonStyle(ScaleButton())
        }
        .padding(14).card()
    }

    private var nets: [BridgeManager.BridgeNet] {
        !tcp.scanNets.isEmpty ? tcp.scanNets : ble.scanNets
    }

    private var netsSection: some View {
        Group {
            if !nets.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    SectionHeader(title: "Reti visibili dalla radio", icon: "wifi", color: .ok,
                                  trailing: "\(nets.count)")
                    ForEach(nets, id: \.bssid) { n in
                        HStack(spacing: 10) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(n.ssid).font(.system(size: 13, weight: .semibold)).foregroundColor(.white)
                                Text("\(n.bssid) · ch\(n.ch) · \(n.rssi)dBm · \(n.sec)").font(.system(size: 9, design: .monospaced)).foregroundColor(.dim)
                            }
                            Spacer()
                            Button {
                                Haptics.heavy()
                                if ble.connected {
                                    Task { _ = await ble.deauth(mac: n.bssid, ch: n.ch) }
                                } else {
                                    Task { _ = await tcp.deauth(mac: n.bssid, ch: n.ch) }
                                }
                            } label: {
                                Image(systemName: "bolt.slash.fill")
                                    .font(.system(size: 12, weight: .bold))
                                    .padding(9)
                                    .background(Circle().fill(Color.bad.opacity(0.2)))
                                    .overlay(Circle().strokeBorder(Color.bad.opacity(0.6), lineWidth: 1))
                                    .foregroundColor(.bad)
                            }
                            .buttonStyle(ScaleButton())
                        }
                        .padding(12)
                        .background(RoundedRectangle(cornerRadius: 12).fill(Color.surfaceHi))
                    }
                }
                .padding(14).card()
            }
        }
    }

    private var rawSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Raw UART", icon: "cable.connector", color: .warn, trailing: "Proxmark / PN532")
            TextField("byte hex (es. AA 00 01)", text: $rawHex)
                .textFieldStyle(.plain).font(.system(size: 12, design: .monospaced))
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            Button {
                Haptics.tap()
                let clean = rawHex.replacingOccurrences(of: " ", with: "")
                if let bytes = clean.hexBytes {
                    tcp.rawSend(bytes)
                    rawHex = ""
                }
            } label: {
                Label("INVIA RAW", systemImage: "paperplane.fill")
                    .font(.system(size: 12, weight: .bold))
                    .frame(maxWidth: .infinity).padding(.vertical, 10)
            }
            .background(RoundedRectangle(cornerRadius: 10).fill(Color.info.opacity(0.25)))
            .foregroundColor(.info)
            .buttonStyle(ScaleButton())
            .disabled(!tcp.connected || rawHex.isEmpty)
            Text("Byte grezzi sulla UART0 dell'ESP8266 (TX GPIO1 → RX target, RX GPIO3 → TX target, GND comune).")
                .font(.caption2).foregroundColor(.dim)
        }
        .padding(14).card()
    }

    private var logSection: some View {
        let lines = tcp.bridgeLog
        return Group {
            if !lines.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    SectionHeader(title: "Bridge log", icon: "text.alignleft", color: .dim)
                    ForEach(Array(lines.enumerated().suffix(14)), id: \.offset) { _, l in
                        Text(l).font(.system(size: 10, design: .monospaced)).foregroundColor(.white.opacity(0.85))
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject var o: Orchestrator
    @Environment(\.dismiss) var dismiss
    @State private var trace: [String] = []

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    BridgeView(ble: o.bridge, tcp: o.tcpBridge)
                    traceSection
                }
                .padding(16)
            }
            .background(RHBackground())
            .navigationTitle("Impostazioni")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("chiudi") { dismiss() }
                }
            }
            .onAppear { trace = Self.readTrace() }
        }
        .preferredColorScheme(.dark)
    }

    private var traceSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                SectionHeader(title: "Crash trace", icon: "exclamationmark.triangle.fill", color: .bad)
                Button("cancella") {
                    CrashTracer.clear()
                    trace = []
                }
                .font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
            }
            if trace.isEmpty {
                Text("vuoto — nessuna traccia").font(.caption).foregroundColor(.dim)
            } else {
                ForEach(Array(trace.suffix(30).enumerated()), id: \.offset) { _, l in
                    Text(l).font(.system(size: 10, design: .monospaced)).foregroundColor(.white.opacity(0.85))
                }
            }
            Text("Se l'app crasha: reinstalla/apri e incolli le ultime righe — l'ultima senza \"ok\" è il punto del crash.")
                .font(.caption2).foregroundColor(.dim)
        }
        .padding(14).card()
    }

    static func readTrace() -> [String] {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        guard let s = try? String(contentsOf: docs.appendingPathComponent("crash_trace.txt"), encoding: .utf8) else { return [] }
        return s.split(separator: "\n").map(String.init)
    }
}
