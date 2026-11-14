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
            actionsSection
            netsSection
            rawSection
            logSection
        }
        .onAppear { tcp.startAutoConnect() }
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
            KV(k: "rete", val: "AP 'RHS-Bridge' (pass redhatsec) → 192.168.4.1:3333")
            if tcp.connected {
                KV(k: "stato radio", val: "i vettori PLAN (deauth/PMKID/beacon) sono eseguibili")
            }
            if !tcp.connected {
                Text("Una sola volta: Impostazioni iOS › Wi-Fi › unisciti a 'RHS-Bridge'. Poi l'app si riconnette da sola.")
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
                    tcp.connect(host: manualIP.trimmingCharacters(in: .whitespaces).isEmpty ? "192.168.4.1" : manualIP)
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
            Text("AZIONI RADIO").font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
            Button {
                Haptics.heavy(); scanning = true
                Task {
                    if ble.connected { _ = await ble.wifiScan() } else { _ = await tcp.wifiScan() }
                    scanning = false
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
                    Text("RETI VISIBILI DALLA RADIO — \(nets.count)").font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
                    ForEach(Array(nets.enumerated()), id: \.offset) { i, n in
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
            Text("RAW UART (Proxmark / PN532 passthrough)").font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
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
                    Text("BRIDGE LOG").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
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

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    BridgeView(ble: o.bridge, tcp: o.tcpBridge)
                }
                .padding(16)
            }
            .background(Color.bg.ignoresSafeArea())
            .navigationTitle("Impostazioni")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("chiudi") { dismiss() }
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}
