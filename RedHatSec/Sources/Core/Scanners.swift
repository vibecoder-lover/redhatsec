import Foundation
import CoreBluetooth
import CoreNFC
import Network

// MARK: - BLE

final class BLEScanner: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    private var central: CBCentralManager!
    private var peripherals: [String: CBPeripheral] = [:]
    private var onDiscover: ((TargetDevice) -> Void)?
    private var enumContinuation: CheckedContinuation<[String], Never>?
    private var enumBuffer: [String] = []
    private var floodCount = 0

    var isReady: Bool { central?.state == .poweredOn }

    override init() {
        super.init()
        central = CBCentralManager(delegate: self, queue: nil)
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        // state handled at scan start
    }

    func startScan(timeout: TimeInterval, onDiscover: @escaping (TargetDevice) -> Void) {
        guard central.state == .poweredOn else {
            onDiscover(TargetDevice(name: "BT off/unavailable", proto: .ble, rssi: 0, via: "ble"))
            return
        }
        self.onDiscover = onDiscover
        central.scanForPeripherals(withServices: nil,
                                   options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
            self?.central.stopScan()
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let name = (advertisementData[CBAdvertisementDataLocalNameKey] as? String)
            ?? (advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data).map { BLEScanner.guessVendor($0) }
            ?? peripheral.identifier.uuidString.prefix(8).description
        var services: [String] = []
        if let s = advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] {
            services = s.map { BLEScanner.friendlyService($0) }
        }
        var extra: [String: String] = [:]
        if let adv = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data {
            extra["companyID"] = String(format: "0x%04X", (UInt16(adv[0]) << 8) | UInt16(adv[1]))
        }
        if let tx = advertisementData[CBAdvertisementDataTxPowerLevelKey] as? NSNumber {
            extra["txPower"] = "\(tx)"
        }
        peripherals[peripheral.identifier.uuidString] = peripheral
        onDiscover?(TargetDevice(name: name, proto: .ble, rssi: RSSI.intValue,
                                 mac: peripheral.identifier.uuidString,
                                 vendor: BLEScanner.guessVendor(advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data ?? Data()),
                                 services: services, via: "BLE adv", extra: extra))
    }

    static func guessVendor(_ adv: Data) -> String? {
        guard adv.count >= 2 else { return nil }
        let id = (UInt16(adv[0]) << 8) | UInt16(adv[1])
        switch id {
        case 0x004C: return "Apple"
        case 0x0006: return "Microsoft"
        case 0x0075: return "Samsung"
        case 0x0087: return "Garmin"
        case 0x0157: return "Anhui Huami (Amazfit)"
        case 0x0111: return "Anki"
        case 0x0131: return "iHealth"
        case 0x0059: return "Nordic Semiconductor"
        case 0x0206: return "FitBit"
        case 0x02E0: return "Tile"
        case 0x0171: return "Amazon"
        case 0x00E0: return "Google"
        case 0x038F: return "Xiaomi"
        case 0x06D5: return "Bosch"
        case 0x016B: return "Skeleton (smart wearables)"
        default: return nil
        }
    }

    static func friendlyService(_ u: CBUUID) -> String {
        switch u.uuidString {
        case "180F": return "Battery (0x180F)"
        case "180D": return "Heart Rate (0x180D)"
        case "1809": return "Health Thermometer (0x1809)"
        case "180A": return "Device Information (0x180A)"
        case "180C": return "User Data (0x180C)"
        case "1811": return "Alert Notification (0x1811)"
        case "FFF0", "FFE0", "FFF1": return "Vendor SVC \(u.uuidString)"
        case "FD6F": return "Matter/Thread (0xFD6F)"
        case "FE9F": return "Google Fast Pair (0xFE9F)"
        case "FE2C": return "Google (0xFE2C)"
        default: return "SVC \(u.uuidString)"
        }
    }

    // Enumerate GATT: connect → discover services/characteristics → dump
    func enumerate(_ target: TargetDevice, timeout: TimeInterval = 8) async -> [String] {
        guard central.state == .poweredOn,
              let per = peripherals[target.mac ?? ""] else { return ["peripheral not in range/cache"] }
        enumBuffer = []
        return await withCheckedContinuation { cont in
            enumContinuation = cont
            per.delegate = self
            central.connect(per, options: nil)
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self, weak per] in
                guard let self, let per else { return }
                if self.enumContinuation != nil {
                    self.central.cancelPeripheralConnection(per)
                }
            }
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.discoverServices(nil)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        for s in peripheral.services ?? [] {
            enumBuffer.append("SVC \(BLEScanner.friendlyService(s.uuid))")
            peripheral.discoverCharacteristics(nil, for: s)
        }
        if peripheral.services?.isEmpty ?? true { finishEnum() }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        for c in service.characteristics ?? [] {
            var line = "  CHR \(c.uuid.uuidString) [\(propsText(c.properties))]"
            if c.value != nil { line += " val=\((c.value ?? Data()).hexPreview)" }
            enumBuffer.append(line)
            if c.properties.contains(.read) { peripheral.readValue(for: c) }
        }
        if service == peripheral.services?.last { finishEnum() }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        if let v = characteristic.value, !v.isEmpty {
            enumBuffer.append("    val \(characteristic.uuid.uuidString): \(v.hexPreview)")
        }
    }

    func write(_ target: TargetDevice, service: String, characteristic: String,
               payload: Data, timeout: TimeInterval = 8) async -> String {
        guard central.state == .poweredOn,
              let per = peripherals[target.mac ?? ""] else { return "peripheral not in range/cache" }
        return await withCheckedContinuation { cont in
            writeCont = { cont.resume(returning: $0) }
            per.delegate = self
            writeTarget = (service, characteristic, payload)
            central.connect(per, options: nil)
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self, weak per] in
                guard let self, let per else { return }
                if self.writeCont != nil { self.central.cancelPeripheralConnection(per) }
            }
        }
    }

    private var writeCont: ((String) -> Void)?
    private var writeTarget: (service: String, chr: String, payload: Data)?

    func flood(_ target: TargetDevice, attempts: Int) async -> Int {
        guard central.state == .poweredOn,
              let per = peripherals[target.mac ?? ""] else { return 0 }
        var done = 0
        for _ in 0..<attempts {
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                floodCont = { c.resume() }
                per.delegate = self
                central.connect(per, options: nil)
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self, weak per] in
                    guard let self, let per else { return }
                    self.central.cancelPeripheralConnection(per)
                }
            }
            done += 1
        }
        return done
    }

    private var floodCont: (() -> Void)?

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        finishEnum()
        writeCont?("disconnected — write outcome unknown")
        writeCont = nil
        floodCont?()
        floodCont = nil
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        finishEnum()
        writeCont?("connect failed: \(error?.localizedDescription ?? "?")")
        writeCont = nil
    }

    private func propsText(_ p: CBCharacteristicProperties) -> String {
        var s: [String] = []
        if p.contains(.read) { s.append("R") }
        if p.contains(.write) { s.append("W") }
        if p.contains(.writeWithoutResponse) { s.append("Wnr") }
        if p.contains(.notify) { s.append("N") }
        if p.contains(.indicate) { s.append("I") }
        return s.joined(separator: ",")
    }

    private func finishEnum() {
        let c = enumContinuation
        enumContinuation = nil
        c?.resume(returning: enumBuffer)
    }
}

extension Data {
    var hexPreview: String {
        let hex = map { String(format: "%02x", $0) }.joined()
        return hex.count > 48 ? String(hex.prefix(48)) + "…" : hex
    }

    init?(hexString: String) {
        let s = hexString.replacingOccurrences(of: " ", with: "")
        guard s.count % 2 == 0, s.range(of: "^[0-9a-fA-F]+$", options: .regularExpression) != nil else { return nil }
        var d = Data()
        var i = s.startIndex
        while i < s.endIndex {
            let next = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<next], radix: 16) ?? 0)
            i = next
        }
        self = d
    }
}

// MARK: - WiFi

final class WiFiScanner {
    struct WiFiNet: Identifiable {
        var id: String { ssid + bssid }
        var ssid: String
        var bssid: String
        var rssi: Int
        var sec: String
    }

    func availableNetworks() -> [WiFiNet] {
        if let nets = probeMobileWiFi() { return nets }
        return probeHotspotCurrent()
    }

    private func probeMobileWiFi() -> [WiFiNet]? {
        guard dlopen("/System/Library/PrivateFrameworks/MobileWiFi.framework/MobileWiFi", RTLD_NOW) != nil,
              let cls = NSClassFromString("WiFiManager") as? NSObject.Type else { return nil }
        let sharedSel = NSSelectorFromString("sharedInstance")
        guard let shared = cls.perform(sharedSel)?.takeUnretainedValue() as? NSObject else { return nil }
        var raw: NSArray?
        for sel in ["copyNetworkList", "networks", "allNetworks"] {
            if let r = shared.perform(NSSelectorFromString(sel))?.takeUnretainedValue() as? NSArray,
               r.count > 0 { raw = r; break }
        }
        guard let arr = raw as? [NSObject] else { return nil }
        var out: [WiFiNet] = []
        for n in arr {
            let ssid = n.perform(NSSelectorFromString("ssidName"))?.takeUnretainedValue() as? String ?? "?"
            let bssid = n.perform(NSSelectorFromString("bssid"))?.takeUnretainedValue() as? String ?? "?"
            let rssi = n.perform(NSSelectorFromString("rssi"))?.takeUnretainedValue() as? Int ?? -100
            let sec = n.perform(NSSelectorFromString("security"))?.takeUnretainedValue() as? String ?? "?"
            out.append(WiFiNet(ssid: ssid, bssid: bssid, rssi: rssi, sec: sec))
        }
        return out.isEmpty ? nil : out
    }

    private func probeHotspotCurrent() -> [WiFiNet] {
        var result: [WiFiNet] = []
        let sem = DispatchSemaphore(value: 0)
        NEHotspotNetwork.fetchCurrent { net in
            if let n = net {
                result = [WiFiNet(ssid: n.ssid, bssid: "?", rssi: -60, sec: n.isSecure ? "WPA2/WPA3" : "OPEN")]
            }
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + 4)
        return result
    }
}

import NetworkExtension

// MARK: - NFC

final class NFCScanner: NSObject, NFCNDEFReaderSessionDelegate, NFCTagReaderSessionDelegate {
    private var session: NFCTagReaderSession?
    private var ndefSession: NFCNDEFReaderSession?
    private var cont: CheckedContinuation<[String], Never>?
    private var buffer: [String] = []

    func scan(timeout: TimeInterval = 20) async -> [String] {
        guard NFCNDEFReaderSession.readingAvailable else { return ["NFC reader unavailable"] }
        buffer = []
        return await withCheckedContinuation { c in
            cont = c
            ndefSession = NFCNDEFReaderSession(delegate: self, queue: nil, invalidateAfterFirstRead: false)
            ndefSession?.begin()
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self, self.cont != nil else { return }
                self.ndefSession?.invalidate()
            }
        }
    }

    func readerSession(_ session: NFCNDEFReaderSession, didInvalidateWithError error: Error) {
        let c = cont
        cont = nil
        if buffer.isEmpty { c?.resume(returning: ["NFC session invalidated: \(error.localizedDescription)"]) }
        else { c?.resume(returning: buffer) }
    }

    func readerSession(_ session: NFCNDEFReaderSession, didDetectNDEFs messages: [NFCNDEFMessage]) {
        for m in messages {
            for r in m.records {
                let payload = String(data: r.payload, encoding: .utf8) ?? r.payload.hexPreview
                buffer.append("NDEF \(r.typeNameFormat) type=\(String(data: r.type, encoding: .utf8) ?? "?") → \(payload.prefix(160))")
            }
        }
        session.invalidate()
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {}
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        for t in tags {
            switch t {
            case .miFare(let m):
                buffer.append("MIFARE \(m.mifareFamily) UID=\(m.identifier.hexPreview)")
                _ = try? m.queryNDEFStatus { st, cap, _ in
                    self.buffer.append("NDEF status=\(st) cap=\(cap)")
                    session.invalidate()
                }
            default:
                buffer.append("tag \(t)")
                session.invalidate()
            }
        }
    }
}

// MARK: - Network (mDNS / SSDP / TCP-UDP probes)

final class NetScanner {
    private var browsers: [NWBrowser] = []
    private var udp: NWConnection?
    private let portTable: [UInt16] = [23, 80, 161, 502, 554, 1883, 5683, 8080, 9100]

    func bonjour(onResult: @escaping (TargetDevice) -> Void) {
        for svc in ["_hap._tcp", "_googlecast._tcp", "_esphomelib._tcp", "_ipp._tcp", "_http._tcp"] {
            let params = NWParameters()
            params.includePeerToPeer = true
            let b = NWBrowser(for: .bonjour(type: svc, domain: "local."), using: params)
            b.browseResultsChangedHandler = { results, _ in
                for r in results {
                    guard case let .service(name, svcType, _, _) = r.endpoint else { continue }
                    _ = svcType
                    var t = TargetDevice(name: name, proto: .net, rssi: -50,
                                         mac: nil, vendor: nil, services: [svc], via: "mDNS")
                    t.extra["svc"] = svc
                    onResult(t)
                }
            }
            b.start(queue: .global())
            browsers.append(b)
        }
    }

    func stopBonjour() { browsers.forEach { $0.cancel() }; browsers.removeAll() }

    func ssdp(timeout: TimeInterval = 5, onResult: @escaping (TargetDevice) -> Void) {
        let c = NWConnection(host: "239.255.255.250", port: 1900, using: .udp)
        var found: Set<String> = []
        c.receiveMessage { [weak self] data, _, _, _ in
            if let d = data, let s = String(data: d, encoding: .utf8) {
                let loc = s.split(separator: "\n").first { $0.uppercased().contains("LOCATION:") }?
                    .split(separator: ":", maxSplits: 1).last.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
                if !loc.isEmpty, found.insert(loc).inserted {
                    var t = TargetDevice(name: "SSDP \(loc.prefix(60))", proto: .net, rssi: -50,
                                         services: ["upnp"], via: "SSDP")
                    t.extra["host"] = loc.hostPart()
                    t.extra["port"] = loc.portPart()
                    t.extra["desc"] = loc
                    onResult(t)
                }
            }
            self?.udp = c // keep alive
        }
        c.stateUpdateHandler = { st in
            if case .ready = st {
                let msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
                c.send(content: msg.data(using: .utf8)!, completion: .contentProcessed { _ in })
            }
        }
        c.start(queue: .global())
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { c.cancel() }
    }

    static func portProbe(host: String, ports: [UInt16], timeout: TimeInterval = 2,
                          onOpen: @escaping (UInt16, String) -> Void, onDone: @escaping () -> Void) {
        let group = DispatchGroup()
        let sem = DispatchSemaphore(value: 6)
        DispatchQueue.global().async {
            for p in ports {
                group.enter()
                sem.wait()
                var result: (Bool, String)?
                let inner = DispatchSemaphore(value: 0)
                pokeTCP(host: host, port: p, timeout: timeout) { open, banner in
                    result = (open, banner)
                    inner.signal()
                }
                _ = inner.wait(timeout: .now() + timeout + 0.5)
                if let r = result, r.0 { onOpen(p, r.1) }
                sem.signal()
                group.leave()
            }
            onDone()
        }
    }

    static func pokeTCP(host: String, port: UInt16, timeout: TimeInterval,
                        onResult: @escaping (Bool, String) -> Void) {
        guard let p = NWEndpoint.Port(rawValue: port) else { onResult(false, ""); return }
        let c = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
        var done = false
        let finish: (Bool, String) -> Void = { open, banner in
            guard !done else { return }
            done = true
            c.cancel()
            onResult(open, banner)
        }
        var received = Data()
        c.stateUpdateHandler = { st in
            switch st {
            case .ready:
                c.receive(minimumIncompleteLength: 1, maximumLength: 4096) { d, _, _, _ in
                    received += d ?? Data()
                    finish(true, String(data: received, encoding: .utf8) ?? received.hexPreview)
                }
                if received.isEmpty {
                    // give a moment for banner-less ports
                    DispatchQueue.global().asyncAfter(deadline: .now() + timeout * 0.5) {
                        finish(true, "")
                    }
                }
            case .failed, .cancelled, .waiting:
                finish(false, "")
            default: break
            }
        }
        c.start(queue: .global(qos: .utility))
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(false, "") }
    }

    static func udpPoke(host: String, port: UInt16, payload: Data, timeout: TimeInterval,
                        onReply: @escaping (String) -> Void) {
        let c = NWConnection(host: NWEndpoint.Host(host),
                             port: NWEndpoint.Port(rawValue: port)!, using: .udp)
        var done = false
        c.stateUpdateHandler = { st in
            if case .ready = st {
                c.send(content: payload, completion: .contentProcessed { _ in
                    c.receiveMessage { d, _, _, _ in
                        guard !done else { return }
                        done = true
                        let s = d.flatMap { String(data: $0, encoding: .utf8) } ?? d?.hexPreview ?? ""
                        c.cancel()
                        onReply(s)
                    }
                })
            }
        }
        c.start(queue: .global(qos: .utility))
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
            if !done { done = true; c.cancel(); onReply("") }
        }
    }
}

extension String {
    func hostPart() -> String {
        guard let m = self.range(of: "//([^:/]+)", options: .regularExpression) else { return "?" }
        return String(self[m]).replacingOccurrences(of: "//", with: "")
    }
    func portPart() -> String {
        guard let m = self.range(of: ":[0-9]+", options: .regularExpression) else { return "80" }
        return String(self[m]).dropFirst().description
    }
}
