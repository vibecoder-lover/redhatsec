import SwiftUI

struct BridgeView: View {
    @EnvironmentObject var o: Orchestrator
    @State private var spamText = "FreeWiFi,Hotel_Guest"
    @State private var scanning = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                statusCard
                if o.bridge.connected { actions }
                if !o.bridge.scanNets.isEmpty { netsSection }
                logSection
            }
            .padding(16)
        }
        .background(Color.bg.ignoresSafeArea())
    }

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("ESP32 BRIDGE").font(.system(size: 18, weight: .heavy, design: .rounded)).foregroundColor(.white)
                Spacer()
                Pill(text: o.bridge.connected ? "ONLINE" : "OFFLINE", color: o.bridge.connected ? .ok : .bad)
            }
            KV(k: "stato", val: o.bridge.state)
            KV(k: "device", val: o.bridge.deviceName ?? "—")
            Button {
                Haptics.heavy()
                o.bridge.start()
            } label: {
                Label(o.bridge.connected ? "RICONNETTI" : "CONNETTI BRIDGE", systemImage: "antenna.radiowaves.left.and.right")
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .frame(maxWidth: .infinity).padding(.vertical, 12)
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.redHat))
            .foregroundColor(.white)
            .buttonStyle(ScaleButton())
            Text("Vettori Wi-Fi PLAN (deauth/PMKID/beacon) diventano eseguibili quando il bridge è online.")
                .font(.caption2).foregroundColor(.dim)
        }
        .padding(14).card()
    }

    private var actions: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("AZIONI RADIO").font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
            Button {
                Haptics.heavy(); scanning = true
                Task {
                    _ = await o.bridge.wifiScan()
                    scanning = false
                }
            } label: {
                Label(scanning ? "SCAN IN CORSO…" : "WIFI SCAN (via radio)", systemImage: "dot.radiowaves.left.and.right")
                    .frame(maxWidth: .infinity).padding(.vertical, 12)
                    .font(.system(size: 13, weight: .bold, design: .rounded))
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.surfaceHi))
            .foregroundColor(.white)
            .buttonStyle(ScaleButton())
            .disabled(scanning || !o.bridge.connected)

            TextField("SSID spam (virgole)", text: $spamText)
                .textFieldStyle(.plain).font(.system(size: 12, design: .monospaced))
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(hex: 0x070709)))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            Button {
                Haptics.heavy()
                let ssids = spamText.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) }
                Task { _ = await o.bridge.beaconSpam(ssids: ssids) }
            } label: {
                Label("BEACON SPAM", systemImage: "tower.broadcast")
                    .frame(maxWidth: .infinity).padding(.vertical, 12)
                    .font(.system(size: 13, weight: .bold, design: .rounded))
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.warn.opacity(0.25)))
            .foregroundColor(.warn)
            .buttonStyle(ScaleButton())
            .disabled(!o.bridge.connected)

            Button {
                Haptics.tap()
                o.bridge.stopAll()
            } label: {
                Label("STOP TUTTO", systemImage: "stop.circle")
                    .frame(maxWidth: .infinity).padding(.vertical, 10)
                    .font(.system(size: 12, weight: .bold))
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.bad.opacity(0.2)))
            .foregroundColor(.bad)
            .buttonStyle(ScaleButton())
            .disabled(!o.bridge.connected)
        }
        .padding(14).card()
    }

    private var netsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("RETI VISIBILI DALLA RADIO — \(o.bridge.scanNets.count)").font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
            ForEach(o.bridge.scanNets) { n in
                HStack(spacing: 10) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(n.ssid).font(.system(size: 13, weight: .semibold)).foregroundColor(.white)
                        Text("\(n.bssid) · ch\(n.ch) · \(n.rssi)dBm · \(n.sec)").font(.system(size: 9, design: .monospaced)).foregroundColor(.dim)
                    }
                    Spacer()
                    Button {
                        Haptics.heavy()
                        Task { _ = await o.bridge.deauth(mac: n.bssid, ch: n.ch) }
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

    private var logSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            if !o.bridge.bridgeLog.isEmpty {
                Text("BRIDGE LOG").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                ForEach(Array(o.bridge.bridgeLog.enumerated().suffix(14)), id: \.offset) { _, l in
                    Text(l).font(.system(size: 10, design: .monospaced)).foregroundColor(.white.opacity(0.85))
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
