import SwiftUI

struct BridgeView: View {
    @EnvironmentObject var o: Orchestrator
    @State private var transport = 0 // 0 BLE, 1 TCP
    @State private var spamText = "FreeWiFi,Hotel_Guest"
    @State private var scanning = false
    @State private var manualIP = ""
    @State private var rawHex = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Picker("transport", selection: $transport) {
                    Text("BLE ESP32").tag(0)
                    Text("TCP ESP8266").tag(1)
                }
                .pickerStyle(.segmented)
                if transport == 0 { bleSection }
                else { tcpSection }
                actionsSection
                netsSection
                rawSection
                logSection
            }
            .padding(16)
        }
        .background(Color.bg.ignoresSafeArea())
    }

    private var bleSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("ESP32 BLE BRIDGE").font(.system(size: 16, weight: .heavy, design: .rounded)).foregroundColor(.white)
                Spacer()
                Pill(text: o.bridge.connected ? "ONLINE" : "OFFLINE", color: o.bridge.connected ? .ok : .bad)
            }
            KV(k: "stato", val: o.bridge.state)
            KV(k: "device", val: o.bridge.deviceName ?? "—")
            Button {
                Haptics.heavy()
                o.bridge.start()
            } label: {
                Label("CONNETTI BRIDGE", systemImage: "antenna.radiowaves.left.and.right")
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .frame(maxWidth: .infinity).padding(.vertical, 12)
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.redHat))
            .foregroundColor(.white)
            .buttonStyle(ScaleButton())
        }
        .padding(14).card()
    }

    private var tcpSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("ESP8266 TCP BRIDGE").font(.system(size: 16, weight: .heavy, design: .rounded)).foregroundColor(.white)
                Spacer()
                Pill(text: o.tcpBridge.connected ? "ONLINE" : "OFFLINE", color: o.tcpBridge.connected ? .ok : .bad)
            }
            KV(k: "stato", val: o.tcpBridge.state)
            KV(k: "dispositivo", val: o.tcpBridge.deviceName)
            HStack(spacing: 8) {
                Button {
                    Haptics.tap()
                    o.tcpBridge.browse()
                } label: {
                    Label(o.tcpBridge.browsing ? "cerco…" : "CERCA (mDNS)", systemImage: "magnifyingglass")
                        .font(.system(size: 12, weight: .bold))
                        .frame(maxWidth: .infinity).padding(.vertical, 10)
                }
                .background(RoundedRectangle(cornerRadius: 10).fill(Color.surfaceHi))
                .foregroundColor(.white)
                .buttonStyle(ScaleButton())
                .disabled(o.tcpBridge.browsing)

                Button {
                    Haptics.tap()
                    o.tcpBridge.joinAP(ssid: "RHS-Bridge", pass: "redhatsec")
                } label: {
                    Label("JOIN AP ESP", systemImage: "wifi.router")
                        .font(.system(size: 12, weight: .bold))
                        .frame(maxWidth: .infinity).padding(.vertical, 10)
                }
                .background(RoundedRectangle(cornerRadius: 10).fill(Color.surfaceHi))
                .foregroundColor(.white)
                .buttonStyle(ScaleButton())
            }
            ForEach(o.tcpBridge.foundHosts, id: \.self) { h in
                Button {
                    Haptics.heavy()
                    o.tcpBridge.connect(host: h)
                } label: {
                    HStack {
                        Image(systemName: "link.circle.fill").foregroundColor(.ok)
                        Text(h).font(.system(size: 12, design: .monospaced)).foregroundColor(.white)
                        Spacer()
                        Text("connect").font(.system(size: 11, weight: .bold)).foregroundColor(.ok)
                    }.padding(10)
                }
                .background(RoundedRectangle(cornerRadius: 10).fill(Color.surface))
                .buttonStyle(ScaleButton())
            }
            HStack(spacing: 8) {
                TextField("IP manuale (es. 172.20.10.14)", text: $manualIP)
                    .textFieldStyle(.plain).font(.system(size: 12, design: .monospaced))
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                    .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
                Button {
                    Haptics.heavy()
                    o.tcpBridge.connect(host: manualIP.trimmingCharacters(in: .whitespaces))
                } label: {
                    Image(systemName: "arrow.right.circle.fill").foregroundColor(.redHat)
                }
                .buttonStyle(ScaleButton())
                .disabled(manualIP.isEmpty)
            }
            Text("STA: ESP su hotspot iPhone → mDNS lo trova da solo. AP: JOIN AP ESP poi connect 192.168.4.1.")
                .font(.caption2).foregroundColor(.dim)
        }
        .padding(14).card()
    }

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("AZIONI RADIO").font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
            Button {
                Haptics.heavy(); scanning = true
                Task {
                    if transport == 0 { _ = await o.bridge.wifiScan() }
                    else { _ = await o.tcpBridge.wifiScan() }
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
            .disabled(scanning || (transport == 0 ? !o.bridge.connected : !o.tcpBridge.connected))

            TextField("SSID spam (virgole)", text: $spamText)
                .textFieldStyle(.plain).font(.system(size: 12, design: .monospaced))
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            Button {
                Haptics.heavy()
                let ssids = spamText.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) }
                Task {
                    if transport == 0 { _ = await o.bridge.beaconSpam(ssids: ssids) }
                    else { _ = await o.tcpBridge.beaconSpam(ssids: ssids) }
                }
            } label: {
                Label("BEACON SPAM", systemImage: "tower.broadcast")
                    .frame(maxWidth: .infinity).padding(.vertical, 12)
                    .font(.system(size: 13, weight: .bold, design: .rounded))
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.warn.opacity(0.25)))
            .foregroundColor(.warn)
            .buttonStyle(ScaleButton())
            .disabled(transport == 0 ? !o.bridge.connected : !o.tcpBridge.connected)

            Button {
                Haptics.tap()
                if transport == 0 { o.bridge.stopAll() } else { o.tcpBridge.stopAll() }
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

    private var netsSection: some View {
        let nets = transport == 0 ? o.bridge.scanNets : o.tcpBridge.scanNets
        return Group {
            if !nets.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    Text("RETI VISIBILI DALLA RADIO — \(nets.count)").font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
                    ForEach(nets) { n in
                        HStack(spacing: 10) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(n.ssid).font(.system(size: 13, weight: .semibold)).foregroundColor(.white)
                                Text("\(n.bssid) · ch\(n.ch) · \(n.rssi)dBm · \(n.sec)").font(.system(size: 9, design: .monospaced)).foregroundColor(.dim)
                            }
                            Spacer()
                            Button {
                                Haptics.heavy()
                                if transport == 0 {
                                    Task { _ = await o.bridge.deauth(mac: n.bssid, ch: n.ch) }
                                } else {
                                    Task { _ = await o.tcpBridge.deauth(mac: n.bssid, ch: n.ch) }
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
                    o.tcpBridge.rawSend(bytes)
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
            .disabled(!o.tcpBridge.connected || rawHex.isEmpty)
            Text("Byte grezzi sulla UART0 dell'ESP8266 — bridge trasparente verso l'hardware attaccato.")
                .font(.caption2).foregroundColor(.dim)
        }
        .padding(14).card()
    }

    private var logSection: some View {
        let lines = transport == 0 ? o.bridge.bridgeLog : o.tcpBridge.bridgeLog
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
