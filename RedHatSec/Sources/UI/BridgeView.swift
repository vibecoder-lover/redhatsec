import SwiftUI

struct BridgeView: View {
    @ObservedObject var ble: BridgeManager
    @ObservedObject var tcp: TCPBridge
    var onBT: ([BridgeManager.BTDevice]) -> Void = { _ in }
    @State private var spamText = "FreeWiFi,Hotel_Guest"
    @State private var scanning = false
    @State private var manualIP = ""
    @State private var rawHex = ""
    @State private var btBusy = false
    @State private var sdpBusyFor: String?
    @State private var sdpMsg = ""
    @State private var bleFloodOn = false
    @State private var connMac = ""
    @State private var faseBMsg = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            bleSection
            btSection
            faseBSection
            tcpSection
            joinSection
            actionsSection
            netsSection
            rawSection
            logSection
        }
        .onAppear { ble.start() }
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
                    let j = Task {
                        if ble.connected { return await ble.joinTarget(targetSSID, targetPass) }
                        return await tcp.joinTarget(targetSSID, targetPass)
                    }
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
                    if !(ok || real) {
                        if ble.connected { ble.log("join \(targetSSID): timeout o negato") }
                        else { tcp.log("join \(targetSSID): timeout o negato") }
                    }
                }
            } label: {
                Label(joining ? "JOIN…" : "JOIN RETE TARGET", systemImage: "arrow.turn.right.down")
                    .frame(maxWidth: .infinity).padding(.vertical, 11)
                    .font(.system(size: 13, weight: .bold, design: .rounded))
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.info.opacity(0.3)))
            .foregroundColor(.info)
            .buttonStyle(ScaleButton())
            .disabled(joining || !(ble.connected || tcp.connected) || targetSSID.isEmpty)
            Text("AP+STA: il bridge resta connesso all'app e la STA entra nella rete target — scan/port/MQTT/SNMP/telnet girano dalla radio dell'ESP.")
                .font(.caption2).foregroundColor(.dim)
        }
        .padding(14).card()
    }

    // ESP32: modulo Wi-Fi + Bluetooth via BLE. È la radio primaria.
    private var bleSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("ESP32 — MODULO BLE").font(.system(size: 16, weight: .heavy, design: .rounded)).foregroundColor(.white)
                Spacer()
                Pill(text: ble.connected ? "ONLINE" : (ble.state == "off" ? "OFF" : "RICERCA…"),
                     color: ble.connected ? .ok : (ble.state == "off" ? .bad : .warn))
            }
            KV(k: "stato", val: ble.state)
            KV(k: "device", val: ble.deviceName ?? "RedHatBridge32")
            if ble.connected {
                Text("Radio pronta: Wi-Fi scan, deauth/beacon/PMKID, rogue AP + NAPT, BT Classic inquiry/SDP, BLE sniffer.")
                    .font(.caption2).foregroundColor(.dim)
            } else {
                Text("Alimenta l'ESP32 (firmware RedHatBridge32) e resta vicino: il telefono si aggancia da solo al GATT FFE0/FFE1.")
                    .font(.caption2).foregroundColor(.dim)
            }
            HStack(spacing: 8) {
                Button {
                    Haptics.tap()
                    ble.start()
                } label: {
                    Label("CERCA/RICONNETTI", systemImage: "antenna.radiowaves.left.and.right")
                        .font(.system(size: 12, weight: .bold))
                        .frame(maxWidth: .infinity).padding(.vertical, 10)
                }
                .background(RoundedRectangle(cornerRadius: 10).fill(Color.ok.opacity(0.2)))
                .foregroundColor(.ok)
                .buttonStyle(ScaleButton())
            }
        }
        .padding(14).card()
    }

    // Bluetooth dell'ESP32: Classic (BR/EDR) non esiste sull'iPhone → lo fa la radio esterna.
    private var btSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Bluetooth ESP32", icon: "dot.radiowaves.left.and.right", color: .info)
            HStack(spacing: 8) {
                Button {
                    guard !btBusy else { return }
                    Haptics.heavy(); btBusy = true
                    Task {
                        let d = await ble.btInquiry(seconds: 10)
                        onBT(d)
                        btBusy = false
                    }
                } label: {
                    Label(btBusy ? "INQUIRY…" : "BT CLASSIC SCAN", systemImage: "magnifyingglass")
                        .font(.system(size: 12, weight: .bold))
                        .frame(maxWidth: .infinity).padding(.vertical, 10)
                }
                .background(RoundedRectangle(cornerRadius: 10).fill(Color.info.opacity(0.2)))
                .foregroundColor(.info)
                .buttonStyle(ScaleButton())
                .disabled(!ble.connected || btBusy)

                Button {
                    guard !btBusy else { return }
                    Haptics.tap(); btBusy = true
                    Task {
                        _ = await ble.bleAdvScan(seconds: 6)
                        btBusy = false
                    }
                } label: {
                    Label("BLE SNIFF", systemImage: "waveform.badge.magnifyingglass")
                        .font(.system(size: 12, weight: .bold))
                        .frame(maxWidth: .infinity).padding(.vertical, 10)
                }
                .background(RoundedRectangle(cornerRadius: 10).fill(Color.warn.opacity(0.2)))
                .foregroundColor(.warn)
                .buttonStyle(ScaleButton())
                .disabled(!ble.connected || btBusy)
            }
            if !ble.btDevices.isEmpty {
                Text("BR/EDR \(ble.btDevices.count)").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                ForEach(ble.btDevices) { d in
                    HStack(spacing: 8) {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(d.name).font(.system(size: 12, weight: .semibold)).foregroundColor(.white)
                            Text("\(d.mac) · \(d.rssi)dBm").font(.system(size: 9, design: .monospaced)).foregroundColor(.dim)
                        }
                        Spacer()
                        Button {
                            Haptics.tap()
                            sdpBusyFor = d.mac
                            sdpMsg = ""
                            Task {
                                let svcs = await ble.btSdp(mac: d.mac)
                                sdpMsg = svcs.isEmpty ? "\(d.mac): nessun servizio (spento / out of range)" : ""
                                sdpBusyFor = nil
                            }
                        } label: {
                            Text(sdpBusyFor == d.mac ? "…" : "SDP")
                                .font(.system(size: 10, weight: .bold))
                                .padding(.horizontal, 10).padding(.vertical, 7)
                                .background(RoundedRectangle(cornerRadius: 8).fill(Color.redHat.opacity(0.2)))
                                .foregroundColor(.redHat)
                        }
                        .buttonStyle(ScaleButton())
                        .disabled(sdpBusyFor != nil)
                    }
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color(hex: 0x070709)))
                }
            }
            if !sdpMsg.isEmpty {
                Text(sdpMsg).font(.system(size: 10, design: .monospaced)).foregroundColor(.warn)
            }
            if !ble.btServices.isEmpty {
                ForEach(Array(ble.btServices.enumerated()), id: \.offset) { _, s in
                    Text(s).font(.system(size: 10, design: .monospaced)).foregroundColor(.ok)
                }
            }
            if !ble.bleAdvDevices.isEmpty {
                Text("BLE ADV \(ble.bleAdvDevices.count)").font(.system(size: 10, weight: .bold)).foregroundColor(.dim)
                ForEach(ble.bleAdvDevices.prefix(10)) { a in
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(a.name) · \(a.mac) · \(a.rssi)dBm")
                            .font(.system(size: 11, weight: .semibold)).foregroundColor(.white)
                        Text(a.adv).font(.system(size: 9, design: .monospaced))
                            .foregroundColor(.dim).lineLimit(2)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color(hex: 0x070709)))
                }
            }
        }
        .padding(14).card()
    }

    // Fase B: offensive BLE host-level sull'ESP32 (adv flood, conn flood, ATT probe).
    private var faseBSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "BLE offensive (Fase B)", icon: "bolt.horizontal.circle", color: .warn)
            Text("adv flood raw con MAC random, conn flood GATTC, probe ATT su handle casuali. Radio unica: non usare insieme alla capture Wi-Fi.")
                .font(.system(size: 10)).foregroundColor(.dim)
            Button {
                Task { await toggleFlood() }
            } label: {
                Text(bleFloodOn ? "STOP FLOOD" : "ADV FLOOD")
                    .font(.system(size: 12, weight: .bold))
                    .frame(maxWidth: .infinity).padding(.vertical, 10)
            }
            .background(RoundedRectangle(cornerRadius: 10).fill((bleFloodOn ? Color.bad : Color.warn).opacity(0.2)))
            .foregroundColor(bleFloodOn ? .bad : .warn)
            .buttonStyle(ScaleButton())
            .disabled(!ble.connected)

            HStack(spacing: 8) {
                TextField("MAC target AA:BB:…", text: $connMac)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .font(.system(size: 12, design: .monospaced))
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color(hex: 0x070709)))
                Button("CONN") { Task { await connFlood() } }
                    .font(.system(size: 11, weight: .bold)).foregroundColor(.warn)
                Button("PROBE") { Task { await probeAtt() } }
                    .font(.system(size: 11, weight: .bold)).foregroundColor(.info)
            }
            .disabled(!ble.connected)

            if !faseBMsg.isEmpty {
                Text(faseBMsg)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.white.opacity(0.8))
            }
            Button("STOP STORM") {
                Task { _ = await ble.bleStormStop(); bleFloodOn = false; faseBMsg = "storm stop" }
            }
            .font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
            .disabled(!ble.connected)
        }
        .padding(14).card()
    }

    private func toggleFlood() async {
        let want = !bleFloodOn
        if await ble.bleFlood(want) {
            bleFloodOn = want
            faseBMsg = want ? "flood ON — MAC random, 31B" : "flood OFF — adv FFE0 ripristinato"
            Haptics.tap()
        } else {
            faseBMsg = "flood: comando rifiutato"
        }
    }

    private func connFlood() async {
        guard !connMac.isEmpty else { faseBMsg = "MAC mancante"; return }
        if let r = await ble.bleConnFlood(mac: connMac, addrType: 1, count: 2) {
            faseBMsg = "conn: accepted=\(r.accepted) attive=\(r.conns) rc=\(r.rc)"
        } else {
            faseBMsg = "conn: comando rifiutato"
        }
    }

    private func probeAtt() async {
        if let n = await ble.bleAttProbe(count: 8) {
            faseBMsg = "probe: \(n) richieste inviate"
        } else {
            faseBMsg = "probe: nessun link GATTC"
        }
    }

    private var tcpSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("ESP8266 BRIDGE (fallback TCP)").font(.system(size: 16, weight: .heavy, design: .rounded)).foregroundColor(.white)
                Spacer()
                Pill(text: tcp.connected ? "ONLINE" : (tcp.state.hasPrefix("auto") ? "RICERCA…" : "OFFLINE"),
                     color: tcp.connected ? .ok : (tcp.state.hasPrefix("auto") ? .warn : .bad))
            }
            KV(k: "stato", val: tcp.state)
            KV(k: "rete", val: "STA: l'ESP entra nel tuo hotspot (Hexxeted) → sweep 172.20.10.2-14 o IP manuale")
            Button {
                Haptics.tap()
                tcp.startAutoConnect()
            } label: {
                Label("CERCA ESP8266 (sweep TCP)", systemImage: "magnifyingglass")
                    .font(.system(size: 12, weight: .bold))
                    .frame(maxWidth: .infinity).padding(.vertical, 10)
            }
            .background(RoundedRectangle(cornerRadius: 10).fill(Color.surfaceHi))
            .foregroundColor(.white)
            .buttonStyle(ScaleButton())
            .disabled(tcp.connected)
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
        let lines = ble.connected ? ble.bridgeLog : tcp.bridgeLog
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
    @ObservedObject private var dbg = DebugServer.shared
    @State private var portText = ""

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    debugSection
                    BridgeView(ble: o.bridge, tcp: o.tcpBridge, onBT: { devs in o.ingestBridgeBT(devs) })
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
            .onAppear {
                trace = Self.readTrace()
                portText = String(dbg.port)
                dbg.startIfEnabled()
            }
        }
        .preferredColorScheme(.dark)
    }

    // Debug server: log dell'app leggibili dal PC sulla stessa rete (niente screen)
    private var debugSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Debug server", icon: "antenna.radiowaves.left.and.right", color: .ok)
            Toggle(isOn: Binding(get: { dbg.enabled }, set: { dbg.enabled = $0 })) {
                Text("attivo — log via HTTP sulla rete locale")
                    .font(.system(size: 12)).foregroundColor(.white.opacity(0.85))
            }
            .tint(.ok)
            HStack(spacing: 8) {
                Text("porta").font(.system(size: 11)).foregroundColor(.dim)
                TextField("8787", text: $portText)
                    .keyboardType(.numberPad)
                    .textFieldStyle(.plain)
                    .font(.system(size: 13, design: .monospaced))
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color(hex: 0x070709)))
                Button("applica") {
                    if let p = Int(portText), (1024...65535).contains(p) { dbg.port = p }
                }
                .font(.system(size: 11, weight: .bold)).foregroundColor(.ok)
            }
            Text(dbg.urlHint)
                .font(.system(size: 12, design: .monospaced)).foregroundColor(.info)
                .textSelection(.enabled)
            HStack(spacing: 12) {
                Button("copia URL") { UIPasteboard.general.string = dbg.urlHint }
                Button("pulisci log") { DebugLog.shared.clear() }
                Button("apri /status") {
                    if let u = URL(string: dbg.urlHint + "status") { UIApplication.shared.open(u) }
                }
            }
            .font(.system(size: 11, weight: .bold)).foregroundColor(.dim)
            Text(dbg.running ? "in ascolto su :\(dbg.port)" : (dbg.enabled ? "non attivo — \(dbg.lastError)" : "spento"))
                .font(.system(size: 10)).foregroundColor(dbg.running ? .ok : .dim)
            Text("Dal PC: curl \(dbg.urlHint)  ·  /all tutto  ·  /status JSON  ·  /clear svuota")
                .font(.system(size: 10, design: .monospaced)).foregroundColor(.dim)
        }
        .padding(14).card()
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
